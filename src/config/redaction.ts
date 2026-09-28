/**
 * Secret redaction utilities.
 *
 * The auditor deliberately never persists or logs secret values in clear text.
 * Sensitive header values, parameters and body fields are replaced with a
 * stable placeholder. Where the analysis needs to know whether two contexts
 * carried "the same" or "a different" secret, a short non-reversible fingerprint
 * can be requested; it is a truncated SHA-256 and cannot recover the value.
 */
import { createHash } from 'node:crypto';

export const PLACEHOLDER = '[REDACTED]';

/** Header names (lower-cased) whose values must never be stored in clear. */
export const SENSITIVE_HEADERS = new Set([
  'cookie',
  'set-cookie',
  'authorization',
  'proxy-authorization',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'x-csrf-token',
  'x-xsrf-token',
  'x-session-token',
  'authentication',
]);

/** Parameter / body field names (matched case-insensitively) treated as secret. */
export const SENSITIVE_PARAM_PATTERNS: RegExp[] = [
  /pass(word|wd)?/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /session/i,
  /auth/i,
  /csrf/i,
  /xsrf/i,
  /signature/i,
  /^sig$/i,
  /credential/i,
  /bearer/i,
];

export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADERS.has(name.toLowerCase());
}

export function isSensitiveParam(name: string): boolean {
  return SENSITIVE_PARAM_PATTERNS.some((re) => re.test(name));
}

/**
 * A short, non-reversible fingerprint of a secret. Useful only to answer
 * "is this the same value as before?" without revealing the value itself.
 */
export function fingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 8);
}

export interface RedactOptions {
  /** include a short fingerprint so equality can be checked. Default false. */
  withFingerprint?: boolean;
}

/** Redact a single value, returning the placeholder (optionally fingerprinted). */
export function maskSecret(value: string, opts: RedactOptions = {}): string {
  if (opts.withFingerprint && value.length > 0) {
    return `${PLACEHOLDER}:${fingerprint(value)}`;
  }
  return PLACEHOLDER;
}

/** Redact a header value based on its name. */
export function redactHeader(
  name: string,
  value: string,
  opts: RedactOptions = {},
): { value: string; redacted: boolean } {
  if (isSensitiveHeader(name)) {
    return { value: maskSecret(value, opts), redacted: true };
  }
  return { value, redacted: false };
}

/** Redact a parameter value based on its name. */
export function redactParam(
  name: string,
  value: string,
  opts: RedactOptions = {},
): { value: string; redacted: boolean } {
  if (isSensitiveParam(name)) {
    return { value: maskSecret(value, opts), redacted: true };
  }
  return { value, redacted: false };
}

/**
 * Best-effort redaction of a request/response body. JSON bodies have sensitive
 * keys masked recursively; url-encoded bodies have sensitive params masked;
 * other content types are returned unchanged (they are size-limited elsewhere).
 */
export function redactBody(contentType: string | undefined, body: string): string {
  if (!body) return body;
  const ct = (contentType ?? '').toLowerCase();
  if (ct.includes('application/json') || looksLikeJson(body)) {
    try {
      const parsed = JSON.parse(body);
      return JSON.stringify(redactJsonValue(parsed));
    } catch {
      return body;
    }
  }
  if (ct.includes('application/x-www-form-urlencoded') || looksLikeForm(body)) {
    return body
      .split('&')
      .map((pair) => {
        const idx = pair.indexOf('=');
        if (idx < 0) return pair;
        const key = pair.slice(0, idx);
        const decodedKey = safeDecode(key);
        return isSensitiveParam(decodedKey) ? `${key}=${PLACEHOLDER}` : pair;
      })
      .join('&');
  }
  return body;
}

function redactJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redactJsonValue);
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveParam(k) ? PLACEHOLDER : redactJsonValue(v);
    }
    return out;
  }
  return value;
}

function looksLikeJson(s: string): boolean {
  const t = s.trimStart();
  return t.startsWith('{') || t.startsWith('[');
}

function looksLikeForm(s: string): boolean {
  return /^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$/.test(s.trim());
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
