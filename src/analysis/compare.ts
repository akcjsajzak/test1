/**
 * Response comparison.
 *
 * Compares two responses (typically the same normalized request seen from two
 * user contexts) and produces a structured, explainable {@link ResponseDiff}.
 * The comparison is content-type aware (JSON structural diff, text similarity),
 * ignores configured dynamic fields to suppress false positives, and detects
 * explicit access-denied signals rather than relying on status codes alone.
 */
import type { ResponseDiff } from '../core/types';

export interface ResponseLike {
  status?: number;
  contentType?: string;
  body?: string;
  size?: number;
  headers?: Array<{ name: string; value: string }>;
  /** redirect target, if any. */
  location?: string;
}

export interface CompareOptions {
  ignoreFields?: string[];
  ignoreHeaders?: string[];
  /** similarity at/above which two successful responses are "access-granted". */
  grantedThreshold?: number;
  /** similarity at/above which two responses are "identical". */
  identicalThreshold?: number;
}

const DEFAULT_GRANTED = 0.85;
const DEFAULT_IDENTICAL = 0.98;

const DENIAL_STATUSES = new Set([401, 403, 407, 511]);
const DENIAL_TEXT_RE =
  /\b(forbidden|unauthorized|not\s+authoriz(ed|ation)|access\s+denied|permission\s+denied|insufficient\s+(privileges|permissions)|must\s+log\s?in|please\s+(log|sign)\s?in|login\s+required|authentication\s+required)\b/i;
const AUTH_REDIRECT_RE = /(login|signin|sign-in|auth|sso|account\/login)/i;

export function isDenialStatus(status?: number): boolean {
  return status !== undefined && DENIAL_STATUSES.has(status);
}

/** Whether a (short-ish) body reads like an access-denied page/message. */
export function bodyLooksLikeDenial(body?: string): boolean {
  if (!body) return false;
  // Only treat as denial when the denial language dominates a small body, to
  // avoid flagging a large page that merely mentions "login" in a footer.
  if (body.length <= 2000 && DENIAL_TEXT_RE.test(body)) return true;
  if (body.length <= 400 && /"error"\s*:\s*"[^"]*(forbidden|denied|unauthorized)/i.test(body)) return true;
  return false;
}

export function isAuthRedirect(resp: ResponseLike): boolean {
  if (resp.status && resp.status >= 300 && resp.status < 400 && resp.location) {
    return AUTH_REDIRECT_RE.test(resp.location);
  }
  return false;
}

/** Detect any access-denied signal in a response. */
export function detectDenial(resp: ResponseLike): boolean {
  return isDenialStatus(resp.status) || isAuthRedirect(resp) || bodyLooksLikeDenial(resp.body);
}

/** Remove ignored keys recursively from a parsed JSON value. */
export function stripJsonFields(value: unknown, ignore: Set<string>): unknown {
  if (Array.isArray(value)) return value.map((v) => stripJsonFields(v, ignore));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (ignore.has(k.toLowerCase())) continue;
      out[k] = stripJsonFields(v, ignore);
    }
    return out;
  }
  return value;
}

/** Collect key paths that differ structurally between two JSON values. */
export function jsonStructuralDiff(a: unknown, b: unknown, prefix = ''): string[] {
  const diffs: string[] = [];
  const ta = typeOf(a);
  const tb = typeOf(b);
  if (ta !== tb) {
    diffs.push(`${prefix || '(root)'}: type ${ta} vs ${tb}`);
    return diffs;
  }
  if (ta === 'object') {
    const ao = a as Record<string, unknown>;
    const bo = b as Record<string, unknown>;
    const keys = new Set([...Object.keys(ao), ...Object.keys(bo)]);
    for (const k of keys) {
      const p = prefix ? `${prefix}.${k}` : k;
      if (!(k in ao)) diffs.push(`${p}: only in test`);
      else if (!(k in bo)) diffs.push(`${p}: only in source`);
      else diffs.push(...jsonStructuralDiff(ao[k], bo[k], p));
    }
  } else if (ta === 'array') {
    const aa = a as unknown[];
    const ba = b as unknown[];
    if (aa.length !== ba.length) diffs.push(`${prefix || '(root)'}: array length ${aa.length} vs ${ba.length}`);
    const n = Math.min(aa.length, ba.length);
    for (let i = 0; i < n; i++) diffs.push(...jsonStructuralDiff(aa[i], ba[i], `${prefix}[${i}]`));
  } else {
    if (a !== b) diffs.push(`${prefix || '(root)'}: value differs`);
  }
  return diffs;
}

function typeOf(v: unknown): string {
  if (Array.isArray(v)) return 'array';
  if (v === null) return 'null';
  return typeof v;
}

/** Jaccard similarity over word tokens, after stripping volatile substrings. */
export function textSimilarity(a: string, b: string): number {
  const sa = tokenize(scrubVolatile(a));
  const sb = tokenize(scrubVolatile(b));
  if (sa.size === 0 && sb.size === 0) return 1;
  if (sa.size === 0 || sb.size === 0) return 0;
  let inter = 0;
  for (const t of sa) if (sb.has(t)) inter += 1;
  const union = sa.size + sb.size - inter;
  return union === 0 ? 1 : inter / union;
}

function scrubVolatile(s: string): string {
  return s
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, 'UUID')
    .replace(/\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}[:\d.zZ+-]*/gi, 'TS')
    .replace(/\b[0-9a-f]{16,}\b/gi, 'HEX')
    .replace(/\b\d{4,}\b/g, 'NUM')
    .replace(/name="csrf[^"]*"\s+value="[^"]*"/gi, 'CSRF')
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

function tokenize(s: string): Set<string> {
  return new Set(s.split(/[^a-z0-9_]+/i).filter((t) => t.length > 1));
}

function tryParseJson(body?: string, contentType?: string): unknown | undefined {
  if (!body) return undefined;
  const looksJson =
    (contentType ?? '').toLowerCase().includes('json') || /^\s*[[{]/.test(body);
  if (!looksJson) return undefined;
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

/**
 * Compare a source (authorized) response with a test response and classify the
 * outcome. The verdict plus similarity and notes give the analyzer everything
 * it needs to decide confidence.
 */
export function compareResponses(
  source: ResponseLike,
  test: ResponseLike,
  opts: CompareOptions = {},
): ResponseDiff {
  const ignore = new Set((opts.ignoreFields ?? []).map((f) => f.toLowerCase()));
  const grantedThreshold = opts.grantedThreshold ?? DEFAULT_GRANTED;
  const identicalThreshold = opts.identicalThreshold ?? DEFAULT_IDENTICAL;
  const notes: string[] = [];

  const diff: ResponseDiff = {
    statusChanged: source.status !== test.status,
    sourceStatus: source.status,
    testStatus: test.status,
    sizeDeltaBytes:
      source.size !== undefined && test.size !== undefined ? test.size - source.size : undefined,
    verdict: 'inconclusive',
    notes,
    similarity: 0,
  };

  // 1. Explicit denial on the test side => access denied (expected, not a finding).
  if (detectDenial(test)) {
    diff.verdict = 'access-denied';
    if (isDenialStatus(test.status)) notes.push(`test response returned denial status ${test.status}`);
    if (isAuthRedirect(test)) notes.push(`test response redirected to an auth endpoint (${test.location})`);
    if (bodyLooksLikeDenial(test.body)) notes.push('test response body reads as an access-denied message');
    diff.similarity = 0;
    return diff;
  }

  // 2. If the source itself was denied/unavailable, there is nothing to compare.
  if (source.status !== undefined && source.status >= 400) {
    diff.verdict = 'inconclusive';
    notes.push(`source response was not a success (status ${source.status}); comparison inconclusive`);
    return diff;
  }

  // 3. Structural JSON comparison when both look like JSON.
  const sj = tryParseJson(source.body, source.contentType);
  const tj = tryParseJson(test.body, test.contentType);
  if (sj !== undefined && tj !== undefined) {
    const strippedS = stripJsonFields(sj, ignore);
    const strippedT = stripJsonFields(tj, ignore);
    const keyDiffs = jsonStructuralDiff(strippedS, strippedT);
    diff.jsonKeyDiffs = keyDiffs.slice(0, 50);
    const totalKeys = Math.max(1, countLeaves(strippedS) + countLeaves(strippedT));
    diff.similarity = Math.max(0, 1 - keyDiffs.length / totalKeys);
    notes.push(
      keyDiffs.length === 0
        ? 'JSON bodies are structurally identical after ignoring dynamic fields'
        : `JSON bodies differ in ${keyDiffs.length} field(s) after ignoring dynamic fields`,
    );
  } else {
    // 4. Fall back to text similarity.
    diff.similarity = textSimilarity(source.body ?? '', test.body ?? '');
    notes.push(`text similarity ${(diff.similarity * 100).toFixed(1)}% after scrubbing volatile substrings`);
  }

  // 5. Classify.
  if (test.status !== undefined && test.status >= 200 && test.status < 300) {
    if (diff.similarity >= identicalThreshold && source.status === test.status) {
      diff.verdict = 'identical';
    } else if (diff.similarity >= grantedThreshold) {
      diff.verdict = 'access-granted';
    } else if (diff.similarity >= 0.5) {
      diff.verdict = 'similar';
    } else {
      diff.verdict = 'different';
    }
  } else if (test.status !== undefined && test.status >= 400) {
    // Non-denial error (e.g. 404/500) — not access-granted, not a clean denial.
    diff.verdict = 'different';
    notes.push(`test response returned status ${test.status}`);
  } else {
    diff.verdict = diff.similarity >= grantedThreshold ? 'access-granted' : 'similar';
  }

  return diff;
}

function countLeaves(v: unknown): number {
  if (Array.isArray(v)) return v.reduce<number>((acc, x) => acc + countLeaves(x), 0) || 1;
  if (v && typeof v === 'object') {
    const entries = Object.values(v as Record<string, unknown>);
    return entries.reduce<number>((acc, x) => acc + countLeaves(x), 0) || 1;
  }
  return 1;
}
