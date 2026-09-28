import { describe, it, expect } from 'vitest';
import { detectGraphql, graphqlSignature, extractRootFields } from '../../src/analysis/graphql';
import type { ObservedRequest } from '../../src/core/types';

function req(url: string, method: string, body?: string): ObservedRequest {
  return {
    id: 'r', user: 'u', method, url, host: new URL(url).hostname,
    requestHeaders: [], params: [], responseHeaders: [], timing: { startedAt: 0 },
    requestBody: body,
  };
}

describe('extractRootFields', () => {
  it('extracts the root field from a named query with args', () => {
    expect(extractRootFields('query GetTicket($id: ID!){ ticket(id:$id){ id subject } }')).toEqual(['ticket']);
  });
  it('handles shorthand queries', () => {
    expect(extractRootFields('{ me { id name } }')).toEqual(['me']);
  });
  it('handles aliases (returns the underlying field)', () => {
    expect(extractRootFields('{ t: ticket(id: 1){ id } }')).toEqual(['ticket']);
  });
  it('does not mistake argument names for fields', () => {
    const fields = extractRootFields('query($id: ID!){ order(id: $id, tenant: $t){ id } }');
    expect(fields).toEqual(['order']);
  });
  it('captures multiple root fields', () => {
    expect(extractRootFields('{ a { x } b { y } }')).toEqual(['a', 'b']);
  });
});

describe('detectGraphql', () => {
  it('detects a POST GraphQL query and its variables', () => {
    const r = req('https://x.test/graphql', 'POST', JSON.stringify({ query: 'query Q($id: ID!){ ticket(id:$id){ id } }', variables: { id: '5001' } }));
    const p = detectGraphql(r);
    expect(p).not.toBeNull();
    expect(p?.info.operationType).toBe('query');
    expect(p?.info.rootFields).toEqual(['ticket']);
    expect(p?.info.variableCount).toBe(1);
    expect(p?.variables).toEqual({ id: '5001' });
  });
  it('detects mutations', () => {
    const r = req('https://x.test/graphql', 'POST', JSON.stringify({ query: 'mutation M{ deleteTicket(id: 1) }' }));
    expect(detectGraphql(r)?.info.operationType).toBe('mutation');
  });
  it('returns null for non-GraphQL POSTs', () => {
    expect(detectGraphql(req('https://x.test/api/login', 'POST', JSON.stringify({ email: 'a', password: 'b' })))).toBeNull();
  });
  it('returns null for GET requests', () => {
    expect(detectGraphql(req('https://x.test/graphql', 'GET'))).toBeNull();
  });
});

describe('graphqlSignature', () => {
  it('keys on operation type and root field', () => {
    const r = req('https://x.test/graphql', 'POST', JSON.stringify({ query: '{ ticket(id: 1){ id } }' }));
    const p = detectGraphql(r)!;
    expect(graphqlSignature('x.test', '/graphql', p.info)).toBe('GRAPHQL query ticket @ x.test/graphql');
  });
});
