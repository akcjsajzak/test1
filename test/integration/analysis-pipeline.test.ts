import { describe, it, expect } from 'vitest';
import { validateConfig } from '../../src/config/loader';
import { ScopeGuard } from '../../src/core/scope';
import { silentLogger } from '../../src/core/logger';
import { NormalizerState } from '../../src/analysis/normalize';
import { EndpointInventory } from '../../src/analysis/inventory';
import { AnalyzerRegistry, type AnalysisContext, type Replayer } from '../../src/analysis/engine';
import { HorizontalAnalyzer } from '../../src/analysis/horizontal';
import { VerticalAnalyzer } from '../../src/analysis/vertical';
import type { ObservedRequest, ReplayResult } from '../../src/core/types';

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

/** A stub replayer: returns 200 echoing the source body, unless the URL is in
 * `deniedFor` for that user, in which case it returns 403. */
function stubReplayer(
  requestsById: Map<string, ObservedRequest>,
  deniedFor: Record<string, string[]> = {},
): Replayer {
  return {
    async replay(request: ObservedRequest, asUser: string): Promise<ReplayResult> {
      const denied = (deniedFor[asUser] ?? []).some((u) => request.url.includes(u));
      const base = {
        originalRequestId: request.id,
        originalUser: request.user,
        replayUser: asUser,
        method: request.method,
        url: request.url,
        requested: true,
        timestamp: Date.now(),
      };
      if (denied) {
        return { ...base, status: 403, contentType: 'application/json', responseBody: '{"error":"forbidden"}', responseSize: 21 };
      }
      const src = requestsById.get(request.id);
      return { ...base, status: 200, contentType: 'application/json', responseBody: src?.responseBody, responseSize: src?.responseSize };
    },
  };
}

function buildContext(requests: ObservedRequest[], replayerFactory: (m: Map<string, ObservedRequest>) => Replayer): AnalysisContext {
  const config = validateConfig({
    authorizedTesting: true,
    target: { url: TARGET },
    users: [
      { name: 'user_a', role: 'user', privilegeLevel: 10, cookies: [{ name: 's', value: 'a' }] },
      { name: 'user_b', role: 'user', privilegeLevel: 10, cookies: [{ name: 's', value: 'b' }] },
      { name: 'admin', role: 'admin', privilegeLevel: 100, cookies: [{ name: 's', value: 'c' }] },
    ],
  });
  const scope = new ScopeGuard(TARGET, config.scope);
  const normalizer = new NormalizerState();
  requests.forEach((r) => normalizer.observe(r.method, r.url));
  requests.forEach((r) => (r.normalized = normalizer.normalize(r.method, r.url)));
  const requestsById = new Map(requests.map((r) => [r.id, r]));
  const inventory = new EndpointInventory();
  config.users.forEach((u) => inventory.ensureUser(u.name, u.role, u.privilegeLevel));
  requests.forEach((r) => inventory.add(r, 'fetch'));

  return {
    config,
    inventory,
    requestsById,
    graphs: new Map(),
    users: config.users.map((u) => ({ name: u.name, role: u.role, privilegeLevel: u.privilegeLevel })),
    replayer: replayerFactory(requestsById),
    scope,
    logger: silentLogger(),
    compareOptions: { ignoreFields: config.compare.ignoreFields, ignoreHeaders: config.compare.ignoreHeaders },
  };
}

describe('analysis pipeline (integration)', () => {
  it('detects a horizontal IDOR between peers and confirms the shared id', async () => {
    const requests = [
      mkReq('user_a', `${TARGET}api/orders/4815`, '{"order":{"id":4815,"item":"Widget"}}'),
      mkReq('user_b', `${TARGET}api/orders/1623`, '{"order":{"id":1623,"item":"Gadget"}}'),
    ];
    const ctx = buildContext(requests, (m) => stubReplayer(m));
    const findings = await new HorizontalAnalyzer().analyze(ctx);
    const idor = findings.find((f) => f.testUser === 'user_b' && f.url.includes('4815'));
    expect(idor).toBeDefined();
    expect(idor?.confidence).toBe('high');
    expect(idor?.evidence.some((e) => e.detail.includes('4815'))).toBe(true);
  });

  it('does NOT flag a securely-checked endpoint that denies the peer', async () => {
    const requests = [
      mkReq('user_a', `${TARGET}api/secure/orders/4815`, '{"order":{"id":4815}}'),
    ];
    const ctx = buildContext(requests, (m) => stubReplayer(m, { user_b: ['secure/orders'] }));
    const findings = await new HorizontalAnalyzer().analyze(ctx);
    expect(findings.find((f) => f.url.includes('secure/orders'))).toBeUndefined();
  });

  it('detects vertical escalation to an admin-only capability', async () => {
    const requests = [
      mkReq('admin', `${TARGET}api/admin/stats`, '{"stats":{"users":3}}'),
    ];
    const ctx = buildContext(requests, (m) => stubReplayer(m));
    const findings = await new VerticalAnalyzer().analyze(ctx);
    const esc = findings.filter((f) => f.url.includes('admin/stats'));
    expect(esc.length).toBeGreaterThan(0);
    expect(esc.every((f) => f.severity === 'high')).toBe(true);
    // one finding per lower-privilege user, not duplicated per source context
    expect(new Set(esc.map((f) => f.testUser)).size).toBe(esc.length);
  });

  it('does NOT flag vertical when the lower user is denied', async () => {
    const requests = [
      mkReq('admin', `${TARGET}api/admin/users`, '{"users":[1,2,3]}'),
    ];
    const ctx = buildContext(requests, (m) => stubReplayer(m, { user_a: ['admin/users'], user_b: ['admin/users'] }));
    const findings = await new VerticalAnalyzer().analyze(ctx);
    expect(findings.find((f) => f.url.includes('admin/users'))).toBeUndefined();
  });

  it('runs both analyzers through the registry', async () => {
    const requests = [
      mkReq('user_a', `${TARGET}api/orders/4815`, '{"order":{"id":4815}}'),
      mkReq('admin', `${TARGET}api/admin/stats`, '{"stats":{"x":1}}'),
    ];
    const ctx = buildContext(requests, (m) => stubReplayer(m));
    const registry = new AnalyzerRegistry().register(new HorizontalAnalyzer()).register(new VerticalAnalyzer());
    const findings = await registry.run(ctx);
    expect(findings.some((f) => f.type === 'AUTHZ-HORIZONTAL')).toBe(true);
    expect(findings.some((f) => f.type === 'AUTHZ-VERTICAL')).toBe(true);
  });
});
