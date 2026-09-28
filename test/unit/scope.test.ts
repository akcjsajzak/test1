import { describe, it, expect } from 'vitest';
import { ScopeGuard } from '../../src/core/scope';
import { scopeSchema } from '../../src/config/schema';

function guard(overrides: Record<string, unknown> = {}, target = 'https://app.test/') {
  return new ScopeGuard(target, scopeSchema.parse(overrides));
}

describe('ScopeGuard host scoping', () => {
  it('always allows the target host', () => {
    expect(guard().hostInScope('app.test').allowed).toBe(true);
  });

  it('allows subdomains when configured, and denies others', () => {
    const g = guard({ allowedDomains: ['app.test'], allowSubdomains: true });
    expect(g.hostInScope('api.app.test').allowed).toBe(true);
    expect(g.hostInScope('evil.test').allowed).toBe(false);
  });

  it('denies third-party hosts by default (default-deny)', () => {
    expect(guard().hostInScope('cdn.thirdparty.com').allowed).toBe(false);
  });

  it('denies private IP ranges for non-explicit hosts', () => {
    const g = guard({}, 'https://app.test/');
    expect(g.hostInScope('10.0.0.5').allowed).toBe(false);
    expect(g.hostInScope('192.168.1.1').allowed).toBe(false);
  });

  it('allows a private-IP target because it was explicitly authorized', () => {
    const g = guard({}, 'http://127.0.0.1:4123/');
    expect(g.hostInScope('127.0.0.1').allowed).toBe(true);
  });

  it('deny list wins over allow list', () => {
    const g = guard({ allowedDomains: ['app.test'], deniedDomains: ['app.test'] });
    expect(g.hostInScope('app.test').allowed).toBe(false);
  });
});

describe('ScopeGuard analysis exclusion', () => {
  it('excludes tracking hosts and telemetry paths', () => {
    const g = guard({ excludeHosts: ['google-analytics.com'], excludeUrlPatterns: ['/telemetry'] });
    expect(g.isExcludedFromAnalysis('https://google-analytics.com/collect')).toBe(true);
    expect(g.isExcludedFromAnalysis('https://app.test/telemetry/log')).toBe(true);
    expect(g.isExcludedFromAnalysis('https://app.test/api/orders/1')).toBe(false);
  });
});

describe('ScopeGuard budgets', () => {
  it('enforces the request budget', () => {
    const g = guard({ maxRequests: 2 });
    expect(g.tryConsumeRequest()).toBe(true);
    expect(g.tryConsumeRequest()).toBe(true);
    expect(g.tryConsumeRequest()).toBe(false);
    expect(g.remainingRequests()).toBe(0);
  });
});
