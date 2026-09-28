import { describe, it, expect } from 'vitest';
import { validateConfig } from '../../src/config/loader';
import { ScopeGuard } from '../../src/core/scope';
import { silentLogger } from '../../src/core/logger';
import { NormalizerState } from '../../src/analysis/normalize';
import { EndpointInventory } from '../../src/analysis/inventory';
import type { AnalysisContext, Replayer, UserInfo } from '../../src/analysis/engine';
import { HorizontalAnalyzer } from '../../src/analysis/horizontal';
import { IdorEnumerationAnalyzer } from '../../src/analysis/idor';
import type { ObservedRequest } from '../../src/core/types';

const TARGET = 'https://app.test/';

function mkReq(user: string, url: string, body: string, status = 200): ObservedRequest {
  return {
    id: `${user}:${url}`,
    user,
    method: 'GET',
    url,
    host: new URL(url).hostname,
    resourceType: 'fetch',
    contentType: 'application/json',
    requestHeaders: [{ name: 'Accept', value: 'application/json' }],
    params: [],
    status,
    responseHeaders: [],
    responseBody: body,
    responseSize: body.length,
    timing: { startedAt: Date.now() },
  };
}

function buildCtx(opts: {
  requests: ObservedRequest[];
  users: UserInfo[];
  replayer: Replayer;
  idor?: Record<string, unknown>;
}): AnalysisContext {
  const config = validateConfig({
    authorizedTesting: true,
    target: { url: TARGET },
    users: opts.users.map((u) => ({
      name: u.name,
      role: u.role,
      privilegeLevel: u.privilegeLevel,
      tenant: u.tenant,
      cookies: [{ name: 's', value: u.name }],
    })),
    idor: opts.idor ?? {},
  });
  const scope = new ScopeGuard(TARGET, config.scope);
  const normalizer = new NormalizerState();
  opts.requests.forEach((r) => normalizer.observe(r.method, r.url));
  opts.requests.forEach((r) => (r.normalized = normalizer.normalize(r.method, r.url)));
  const requestsById = new Map(opts.requests.map((r) => [r.id, r]));
  const inventory = new EndpointInventory();
  opts.users.forEach((u) => inventory.ensureUser(u.name, u.role, u.privilegeLevel));
  opts.requests.forEach((r) => inventory.add(r, 'fetch'));
  return {
    config,
    inventory,
    requestsById,
    graphs: new Map(),
    users: opts.users,
    replayer: opts.replayer,
    scope,
    logger: silentLogger(),
    compareOptions: { ignoreFields: config.compare.ignoreFields, ignoreHeaders: config.compare.ignoreHeaders },
  };
}

const okReplayerEcho = (requestsById: Map<string, ObservedRequest>): Replayer => ({
  async replay(request, asUser) {
    const src = requestsById.get(request.id);
    return {
      originalRequestId: request.id, originalUser: request.user, replayUser: asUser,
      method: request.method, url: request.url, requested: true, status: 200,
      contentType: 'application/json', responseBody: src?.responseBody, responseSize: src?.responseSize,
      timestamp: Date.now(),
    };
  },
});

describe('tenant-aware horizontal analysis', () => {
  const users: UserInfo[] = [
    { name: 'alice', role: 'member', privilegeLevel: 10, tenant: '1' },
    { name: 'bob', role: 'member', privilegeLevel: 10, tenant: '1' },
    { name: 'mallory', role: 'member', privilegeLevel: 10, tenant: '2' },
  ];

  it('elevates cross-tenant, downgrades same-tenant tenant-scoped, keeps per-user', async () => {
    const requests = [
      mkReq('alice', `${TARGET}api/orgs/1/projects/101`, '{"project":{"id":101,"name":"Apollo"}}'),
      mkReq('alice', `${TARGET}api/tickets/5001`, '{"ticket":{"id":5001,"body":"private"}}'),
    ];
    const ctx = buildCtx({ requests, users, replayer: okReplayerEcho(new Map(requests.map((r) => [r.id, r]))) });
    const findings = await new HorizontalAnalyzer().analyze(ctx);

    const proj = (u: string) => findings.find((f) => f.testUser === u && f.url?.includes('/projects/101'));
    const ticket = (u: string) => findings.find((f) => f.testUser === u && f.url?.includes('/tickets/5001'));

    // cross-tenant (mallory, tenant 2) reaching alice's org-1 resource -> elevated + tagged
    expect(proj('mallory')?.tags).toContain('cross-tenant');
    expect(proj('mallory')?.severity).toBe('high');

    // same-tenant peer on a tenant-scoped resource -> downgraded (likely sharing)
    expect(proj('bob')?.tags).toContain('same-tenant-shared');
    expect(proj('bob')?.severity).toBe('info');

    // same-tenant peer on a per-user resource (ticket) -> stays a real finding
    expect(ticket('bob')?.tags).toContain('same-tenant');
    expect(ticket('bob')?.severity).toBe('high');
    // and cross-tenant on the per-user resource is elevated too
    expect(ticket('mallory')?.tags).toContain('cross-tenant');
  });

  it('is unchanged (no tenant tags) when tenants are not configured', async () => {
    const noTenant = users.map((u) => ({ ...u, tenant: undefined }));
    const requests = [mkReq('alice', `${TARGET}api/tickets/5001`, '{"ticket":{"id":5001}}')];
    const ctx = buildCtx({ requests, users: noTenant, replayer: okReplayerEcho(new Map(requests.map((r) => [r.id, r]))) });
    const findings = await new HorizontalAnalyzer().analyze(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => !f.tags || f.tags.length === 0)).toBe(true);
  });
});

describe('active IDOR / enumeration analyzer', () => {
  const users: UserInfo[] = [{ name: 'alice', role: 'member', privilegeLevel: 10 }];

  // A replayer that models three endpoints by URL:
  //  - /api/records/N : open, returns a distinct record for 1..20, else 404 (no denial)
  //  - /api/secure/N  : returns 200 only for id 10, 403 otherwise (enforces authz)
  //  - /api/feed/N    : returns 200 {items:[]} for everything except id 10 (empty collection)
  const replayer: Replayer = {
    async replay(request, asUser) {
      const base = {
        originalRequestId: request.id, originalUser: request.user, replayUser: asUser,
        method: request.method, url: request.url, requested: true,
        contentType: 'application/json', timestamp: Date.now(),
      };
      const m = new URL(request.url).pathname.match(/\/api\/(records|secure|feed)\/(\d+)/);
      if (!m) return { ...base, status: 404, responseBody: '{"error":"not_found"}' };
      const kind = m[1];
      const n = Number(m[2]);
      if (kind === 'records') {
        if (n >= 1 && n <= 20) return { ...base, status: 200, responseBody: `{"record":{"id":${n},"data":"r${n}"}}` };
        return { ...base, status: 404, responseBody: '{"error":"not_found"}' };
      }
      if (kind === 'secure') {
        if (n === 10) return { ...base, status: 200, responseBody: '{"record":{"id":10}}' };
        return { ...base, status: 403, responseBody: '{"error":"forbidden"}' };
      }
      // feed: id 10 has an item; everything else (incl. sentinel) is an empty list
      if (n === 10) return { ...base, status: 200, responseBody: '{"items":[{"id":"a"}]}' };
      return { ...base, status: 200, responseBody: '{"items":[]}' };
    },
  };

  it('flags an open enumerable endpoint, but not a secured or empty-collection one', async () => {
    const requests = [
      mkReq('alice', `${TARGET}api/records/10`, '{"record":{"id":10,"data":"r10"}}'),
      mkReq('alice', `${TARGET}api/secure/10`, '{"record":{"id":10}}'),
      mkReq('alice', `${TARGET}api/feed/10`, '{"items":[{"id":"a"}]}'),
    ];
    const ctx = buildCtx({ requests, users, replayer, idor: { enabled: true, numericNeighbors: 3 } });
    const findings = await new IdorEnumerationAnalyzer().analyze(ctx);

    const byRoute = (re: RegExp) => findings.find((f) => re.test(f.normalizedRoute ?? ''));
    expect(byRoute(/\/api\/records\/\{id\}/)).toBeDefined(); // open -> flagged
    expect(byRoute(/\/api\/records\/\{id\}/)?.tags).toContain('enumeration');
    expect(byRoute(/\/api\/secure\//)).toBeUndefined(); // denials seen -> not flagged
    expect(byRoute(/\/api\/feed\//)).toBeUndefined(); // empty collections -> not flagged
  });

  it('does nothing when idor.enabled is false', async () => {
    const requests = [mkReq('alice', `${TARGET}api/records/10`, '{"record":{"id":10}}')];
    const ctx = buildCtx({ requests, users, replayer, idor: { enabled: false } });
    const findings = await new IdorEnumerationAnalyzer().analyze(ctx);
    expect(findings).toEqual([]);
  });
});
