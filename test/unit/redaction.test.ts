import { describe, it, expect } from 'vitest';
import {
  isSensitiveHeader,
  isSensitiveParam,
  redactHeader,
  redactParam,
  redactBody,
  maskSecret,
  fingerprint,
} from '../../src/config/redaction';

describe('sensitivity classification', () => {
  it('flags sensitive headers', () => {
    expect(isSensitiveHeader('Cookie')).toBe(true);
    expect(isSensitiveHeader('authorization')).toBe(true);
    expect(isSensitiveHeader('Accept')).toBe(false);
  });
  it('flags sensitive params', () => {
    expect(isSensitiveParam('session')).toBe(true);
    expect(isSensitiveParam('csrf_token')).toBe(true);
    expect(isSensitiveParam('page')).toBe(false);
  });
});

describe('redaction', () => {
  it('redacts sensitive header values but keeps others', () => {
    expect(redactHeader('Cookie', 'session=abc')).toEqual({ value: '[REDACTED]', redacted: true });
    expect(redactHeader('Accept', 'text/html')).toEqual({ value: 'text/html', redacted: false });
  });
  it('redacts sensitive params', () => {
    expect(redactParam('token', 'xyz').redacted).toBe(true);
    expect(redactParam('q', 'hello').redacted).toBe(false);
  });
  it('recursively redacts sensitive JSON body fields', () => {
    const out = redactBody('application/json', '{"user":{"password":"p","name":"a"},"token":"t"}');
    expect(out).not.toContain('"p"');
    expect(out).not.toContain('"t"');
    expect(out).toContain('"name":"a"');
  });
  it('redacts sensitive form fields', () => {
    const out = redactBody('application/x-www-form-urlencoded', 'q=hi&password=secret');
    expect(out).toBe('q=hi&password=[REDACTED]');
  });
  it('fingerprints are stable and non-reversible-looking', () => {
    expect(maskSecret('abc', { withFingerprint: true })).toBe(`[REDACTED]:${fingerprint('abc')}`);
    expect(maskSecret('abc')).toBe('[REDACTED]');
  });
});
