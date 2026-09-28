import { describe, it, expect } from 'vitest';
import {
  compareResponses,
  detectDenial,
  jsonStructuralDiff,
  stripJsonFields,
  textSimilarity,
} from '../../src/analysis/compare';

describe('detectDenial', () => {
  it('detects denial status codes', () => {
    expect(detectDenial({ status: 403 })).toBe(true);
    expect(detectDenial({ status: 401 })).toBe(true);
    expect(detectDenial({ status: 200 })).toBe(false);
  });
  it('detects auth redirects', () => {
    expect(detectDenial({ status: 302, location: 'https://x.test/login?next=/a' })).toBe(true);
    expect(detectDenial({ status: 302, location: 'https://x.test/home' })).toBe(false);
  });
  it('detects denial message bodies', () => {
    expect(detectDenial({ status: 200, body: '{"error":"forbidden"}' })).toBe(true);
    expect(detectDenial({ status: 200, body: 'You must log in to continue' })).toBe(true);
  });
});

describe('jsonStructuralDiff / stripJsonFields', () => {
  it('finds added and changed keys', () => {
    const diffs = jsonStructuralDiff({ a: 1, b: 2 }, { a: 1, b: 3, c: 4 });
    expect(diffs.join('\n')).toMatch(/b: value differs/);
    expect(diffs.join('\n')).toMatch(/c: only in test/);
  });
  it('ignores configured dynamic fields', () => {
    const ignore = new Set(['csrftoken']);
    const a = stripJsonFields({ id: 1, csrfToken: 'x' }, ignore);
    const b = stripJsonFields({ id: 1, csrfToken: 'y' }, ignore);
    expect(jsonStructuralDiff(a, b)).toEqual([]);
  });
});

describe('textSimilarity', () => {
  it('is 1 for identical text after scrubbing volatile substrings', () => {
    expect(textSimilarity('order 12345 ready', 'order 67890 ready')).toBe(1);
  });
  it('is low for unrelated text', () => {
    expect(textSimilarity('the quick brown fox', 'completely different words here')).toBeLessThan(0.2);
  });
});

describe('compareResponses', () => {
  const opts = { ignoreFields: ['csrfToken', 'ts'] };

  it('classifies a shared protected object as access-granted/identical', () => {
    const src = { status: 200, contentType: 'application/json', body: '{"order":{"id":4815,"item":"Widget"},"csrfToken":"a","ts":1}' };
    const test = { status: 200, contentType: 'application/json', body: '{"order":{"id":4815,"item":"Widget"},"csrfToken":"b","ts":2}' };
    const diff = compareResponses(src, test, opts);
    expect(['identical', 'access-granted']).toContain(diff.verdict);
    expect(diff.similarity).toBeGreaterThan(0.9);
  });

  it('classifies a 403 test response as access-denied', () => {
    const src = { status: 200, contentType: 'application/json', body: '{"order":{"id":4815}}' };
    const test = { status: 403, contentType: 'application/json', body: '{"error":"forbidden"}' };
    const diff = compareResponses(src, test, opts);
    expect(diff.verdict).toBe('access-denied');
  });

  it('classifies per-user content as different (not a finding)', () => {
    const src = { status: 200, contentType: 'application/json', body: '{"name":"Alice","orders":[1,2,3]}' };
    const test = { status: 200, contentType: 'application/json', body: '{"name":"Bob","orders":[9]}' };
    const diff = compareResponses(src, test, opts);
    expect(['different', 'similar']).toContain(diff.verdict);
  });

  it('is inconclusive when the source itself failed', () => {
    const diff = compareResponses({ status: 500 }, { status: 200, body: 'ok' }, opts);
    expect(diff.verdict).toBe('inconclusive');
  });
});
