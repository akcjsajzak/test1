import { describe, it, expect } from 'vitest';
import {
  privilegeOf,
  isPrivilegedPath,
  resourceMarkers,
  markersPresent,
  isDataBearingResource,
} from '../../src/analysis/authz-common';
import type { ObservedRequest } from '../../src/core/types';

function req(partial: Partial<ObservedRequest>): ObservedRequest {
  return {
    id: 'r1',
    user: 'u',
    method: 'GET',
    url: 'https://x.test/api/orders/4815',
    host: 'x.test',
    requestHeaders: [],
    params: [],
    responseHeaders: [],
    timing: { startedAt: 0 },
    ...partial,
  };
}

describe('privilegeOf', () => {
  it('prefers an explicit privilege level', () => {
    expect(privilegeOf({ name: 'a', privilegeLevel: 42 })).toBe(42);
  });
  it('infers from role', () => {
    expect(privilegeOf({ name: 'a', role: 'admin' })).toBe(100);
    expect(privilegeOf({ name: 'a', role: 'user' })).toBe(10);
  });
  it('treats anonymous-named contexts as level 0', () => {
    expect(privilegeOf({ name: 'anonymous' })).toBe(0);
  });
});

describe('isPrivilegedPath', () => {
  it('matches admin/internal paths', () => {
    expect(isPrivilegedPath('https://x.test/api/admin/stats')).toBe(true);
    expect(isPrivilegedPath('/api/internal/debug')).toBe(true);
    expect(isPrivilegedPath('/api/orders/1')).toBe(false);
  });
});

describe('resourceMarkers / markersPresent', () => {
  it('extracts id-like markers and finds them in a body', () => {
    const r = req({ normalized: { signature: 's', method: 'GET', host: 'x.test', pathTemplate: '/api/orders/{id}', queryTemplate: '', variables: { id: '4815' } } });
    const markers = resourceMarkers(r);
    expect(markers).toContain('4815');
    expect(markersPresent('{"order":{"id":4815}}', markers)).toEqual(['4815']);
  });
});

describe('isDataBearingResource', () => {
  it('keeps JSON responses', () => {
    expect(isDataBearingResource(req({ contentType: 'application/json', responseBody: '{"a":1}' }), [])).toBe(true);
  });
  it('drops an HTML SPA shell without markers', () => {
    const shell = req({ resourceType: 'document', contentType: 'text/html', responseBody: '<html><script src=/app.js></script></html>' });
    expect(isDataBearingResource(shell, ['4815'])).toBe(false);
  });
  it('keeps a server-rendered HTML page that embeds the resource id', () => {
    const page = req({ resourceType: 'document', contentType: 'text/html', responseBody: '<html><h1>Order 4815</h1></html>' });
    expect(isDataBearingResource(page, ['4815'])).toBe(true);
  });
});
