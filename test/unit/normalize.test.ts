import { describe, it, expect } from 'vitest';
import { classifySegment, normalizeRequest, NormalizerState } from '../../src/analysis/normalize';

describe('classifySegment', () => {
  it('templates numeric ids', () => {
    expect(classifySegment('123')).toBe('{id}');
  });
  it('templates uuids and objectids', () => {
    expect(classifySegment('550e8400-e29b-41d4-a716-446655440000')).toBe('{uuid}');
    expect(classifySegment('507f1f77bcf86cd799439011')).toBe('{objectid}');
  });
  it('templates dates and timestamps', () => {
    expect(classifySegment('2024-01-02')).toBe('{date}');
    expect(classifySegment('2024-01-02T10:00:00')).toBe('{ts}');
  });
  it('keeps ordinary collection names literal', () => {
    expect(classifySegment('orders')).toBeNull();
    expect(classifySegment('admin')).toBeNull();
    expect(classifySegment('me')).toBeNull();
  });
  it('templates hyphenated slugs that carry a digit', () => {
    expect(classifySegment('q3-financials-8842')).toBe('{slug}');
    expect(classifySegment('globex-roadmap-3310')).toBe('{slug}');
  });
  it('keeps hyphenated route names without a digit literal', () => {
    expect(classifySegment('feature-flags')).toBeNull();
    expect(classifySegment('sign-in')).toBeNull();
  });
});

describe('normalizeRequest', () => {
  it('collapses different ids to the same signature', () => {
    const a = normalizeRequest('GET', 'https://x.test/api/users/123');
    const b = normalizeRequest('GET', 'https://x.test/api/users/456');
    expect(a.signature).toBe(b.signature);
    expect(a.pathTemplate).toBe('/api/users/{id}');
    expect(a.variables).toEqual({ id: '123' });
  });

  it('sorts and templates dynamic query values', () => {
    const n = normalizeRequest('GET', 'https://x.test/search?ts=999&q=hello');
    expect(n.queryTemplate).toBe('q=hello&ts={val}');
  });

  it('redacts sensitive query params in the returned params list', () => {
    const n = normalizeRequest('GET', 'https://x.test/api?token=abc123secretvalue');
    const p = n.params.find((p) => p.name === 'token');
    expect(p?.redacted).toBe(true);
    expect(p?.value).toBe('[REDACTED]');
  });

  it('degrades gracefully on non-URLs', () => {
    const n = normalizeRequest('GET', 'data:text/plain,hello');
    expect(n.host).toBe('');
    expect(n.signature).toContain('GET');
  });
});

describe('NormalizerState', () => {
  it('collapses high-cardinality identifier-like segments', () => {
    const s = new NormalizerState(3);
    const urls = [
      'https://x.test/api/files/ab12cd34ef',
      'https://x.test/api/files/9f8e7d6c5b',
      'https://x.test/api/files/1a2b3c4d5e',
    ];
    urls.forEach((u) => s.observe('GET', u));
    const n = s.normalize('GET', urls[0]);
    expect(n.pathTemplate).toBe('/api/files/{seg}');
  });

  it('does NOT collapse dictionary-word collection names', () => {
    const s = new NormalizerState(3);
    const urls = [
      'https://x.test/api/orders',
      'https://x.test/api/products',
      'https://x.test/api/admin',
      'https://x.test/api/internal',
    ];
    urls.forEach((u) => s.observe('GET', u));
    const n = s.normalize('GET', 'https://x.test/api/internal');
    expect(n.pathTemplate).toBe('/api/internal');
  });
});
