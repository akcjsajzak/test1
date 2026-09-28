/**
 * Request normalization.
 *
 * Turns concrete request URLs into stable signatures where volatile path and
 * query segments become typed placeholders, so that two requests targeting the
 * "same" logical endpoint (differing only by an id/uuid/timestamp) collapse to
 * one signature. The concrete values are preserved separately so the analyzer
 * can still reason about a specific resource id (needed for horizontal authz).
 */
import type { HttpMethod, NormalizedRequest, ParamPair } from '../core/types';
import { isSensitiveParam } from '../config/redaction';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OBJECTID_RE = /^[0-9a-f]{24}$/i;
const LONGHEX_RE = /^[0-9a-f]{16,}$/i;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const ISO_TS_RE = /^\d{4}-\d{2}-\d{2}[tT]\d{2}:\d{2}/;
const NUMERIC_RE = /^\d+$/;
const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const LONG_TOKEN_RE = /^[A-Za-z0-9_-]{20,}$/;
const SLUG_RE = /^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+$/;

/** Query keys whose values are dynamic regardless of content. */
const DYNAMIC_QUERY_KEYS = new Set([
  'ts',
  't',
  '_',
  'time',
  'timestamp',
  'nonce',
  'cachebust',
  'cb',
  'v',
  'rid',
  'requestid',
  'request_id',
  'traceid',
  'trace_id',
]);

/** Classify a single path segment into a placeholder or keep it literal. */
export function classifySegment(seg: string): string | null {
  if (seg.length === 0) return null;
  if (UUID_RE.test(seg)) return '{uuid}';
  if (OBJECTID_RE.test(seg)) return '{objectid}';
  if (ISO_TS_RE.test(seg)) return '{ts}';
  if (DATE_RE.test(seg)) return '{date}';
  if (NUMERIC_RE.test(seg)) return '{id}';
  if (JWT_RE.test(seg)) return '{jwt}';
  if (LONGHEX_RE.test(seg)) return '{hex}';
  // Mixed alphanumeric segments that also contain a digit and are long are
  // very likely opaque identifiers (slugs with numbers, base62 ids).
  if (seg.length >= 20 && LONG_TOKEN_RE.test(seg) && /\d/.test(seg)) return '{token}';
  // Hyphenated slugs that carry a digit (e.g. "q3-financials-8842") are almost
  // always resource identifiers rather than fixed route names ("feature-flags",
  // which carries no digit, stays literal).
  if (seg.length >= 12 && SLUG_RE.test(seg) && /\d/.test(seg)) return '{slug}';
  return null;
}

export interface NormalizeResult extends NormalizedRequest {
  params: ParamPair[];
}

/** Normalize a single request URL + method into a signature and variables. */
export function normalizeRequest(method: HttpMethod, rawUrl: string): NormalizeResult {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    // Non-URL (data:, blob:, relative) — degrade gracefully.
    return {
      signature: `${method.toUpperCase()} ${rawUrl}`,
      method: method.toUpperCase(),
      host: '',
      pathTemplate: rawUrl,
      queryTemplate: '',
      variables: {},
      params: [],
    };
  }

  const variables: Record<string, string> = {};
  const counters: Record<string, number> = {};
  const params: ParamPair[] = [];

  const segments = u.pathname.split('/');
  const templatedSegments = segments.map((seg) => {
    const decoded = safeDecode(seg);
    const placeholder = classifySegment(decoded);
    if (placeholder) {
      const key = nextVarName(placeholder, counters);
      variables[key] = decoded;
      params.push({ name: key, value: decoded, location: 'path' });
      return placeholder;
    }
    return seg;
  });
  const pathTemplate = templatedSegments.join('/') || '/';

  // Query: sort keys, template dynamic values, keep key names.
  const queryEntries: Array<[string, string]> = [];
  for (const [k, v] of u.searchParams.entries()) {
    const redacted = isSensitiveParam(k);
    params.push({
      name: k,
      value: redacted ? '[REDACTED]' : v,
      location: 'query',
      redacted: redacted || undefined,
    });
    const dynamic = redacted || DYNAMIC_QUERY_KEYS.has(k.toLowerCase()) || isVolatileValue(v);
    queryEntries.push([k, dynamic ? '{val}' : v]);
  }
  queryEntries.sort((a, b) => a[0].localeCompare(b[0]));
  const queryTemplate = queryEntries.map(([k, v]) => `${k}=${v}`).join('&');

  const host = u.hostname;
  const signature = `${method.toUpperCase()} ${host}${pathTemplate}${queryTemplate ? `?${queryTemplate}` : ''}`;

  return {
    signature,
    method: method.toUpperCase(),
    host,
    pathTemplate,
    queryTemplate,
    variables,
    params,
  };
}

/** Heuristic: does a path segment look like an opaque identifier (vs a word)? */
function looksIdentifierLike(seg: string): boolean {
  const s = safeDecode(seg);
  if (s.length === 0) return false;
  if (/\d/.test(s)) return true; // any digit strongly suggests an id
  if (s.length >= 12) return true; // long opaque token
  if (/[_-]/.test(s) && s.length >= 8) return true; // slug-like id
  return false;
}

function isVolatileValue(v: string): boolean {
  return (
    UUID_RE.test(v) ||
    OBJECTID_RE.test(v) ||
    ISO_TS_RE.test(v) ||
    NUMERIC_RE.test(v) ||
    JWT_RE.test(v) ||
    LONGHEX_RE.test(v) ||
    (LONG_TOKEN_RE.test(v) && /\d/.test(v))
  );
}

function nextVarName(placeholder: string, counters: Record<string, number>): string {
  const base = placeholder.replace(/[{}]/g, '');
  const n = (counters[base] ?? 0) + 1;
  counters[base] = n;
  return n === 1 ? base : `${base}${n}`;
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * Stateful normalizer that additionally learns which path positions are
 * variable by observing many distinct concrete values at the same position.
 * This catches opaque string ids (e.g. usernames) that rule-based templating
 * would keep literal.
 */
export class NormalizerState {
  /** map of "METHOD host/parent/parent/*" -> set of distinct values seen. */
  private readonly positionValues = new Map<string, Set<string>>();
  private readonly threshold: number;

  constructor(threshold = 3) {
    this.threshold = threshold;
  }

  /** First pass: record observed segment values per structural position. */
  observe(method: HttpMethod, rawUrl: string): void {
    let u: URL;
    try {
      u = new URL(rawUrl);
    } catch {
      return;
    }
    const segs = u.pathname.split('/');
    for (let i = 0; i < segs.length; i++) {
      const prefix = segs.slice(0, i).join('/');
      const key = `${method.toUpperCase()} ${u.hostname}${prefix}/[${i}]`;
      let set = this.positionValues.get(key);
      if (!set) {
        set = new Set();
        this.positionValues.set(key, set);
      }
      set.add(segs[i]);
    }
  }

  /**
   * Whether a position has enough distinct values to be treated as variable.
   * To avoid collapsing legitimate REST collection names (e.g. /api/orders,
   * /api/admin, /api/internal), a position is only considered variable when a
   * strong majority of its observed values are identifier-like (contain a digit
   * or are long/opaque) rather than short dictionary words.
   */
  private positionIsVariable(method: HttpMethod, hostname: string, segs: string[], i: number): boolean {
    const prefix = segs.slice(0, i).join('/');
    const key = `${method.toUpperCase()} ${hostname}${prefix}/[${i}]`;
    const set = this.positionValues.get(key);
    if (!set || set.size < this.threshold) return false;
    let idish = 0;
    for (const v of set) if (looksIdentifierLike(v)) idish += 1;
    return idish / set.size >= 0.6;
  }

  /** Second pass: normalize using both rules and learned variability. */
  normalize(method: HttpMethod, rawUrl: string): NormalizeResult {
    const base = normalizeRequest(method, rawUrl);
    let u: URL;
    try {
      u = new URL(rawUrl);
    } catch {
      return base;
    }
    const segs = u.pathname.split('/');
    const templateSegs = base.pathTemplate.split('/');
    let changed = false;
    for (let i = 0; i < segs.length; i++) {
      // Only override segments the rule-based pass left literal.
      if (templateSegs[i] && !templateSegs[i].startsWith('{') && segs[i].length > 0) {
        if (this.positionIsVariable(method, u.hostname, segs, i)) {
          base.variables[`seg${i}`] = safeDecode(segs[i]);
          templateSegs[i] = '{seg}';
          changed = true;
        }
      }
    }
    if (!changed) return base;
    const pathTemplate = templateSegs.join('/') || '/';
    return {
      ...base,
      pathTemplate,
      signature: `${base.method} ${base.host}${pathTemplate}${base.queryTemplate ? `?${base.queryTemplate}` : ''}`,
    };
  }
}
