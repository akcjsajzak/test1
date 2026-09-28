import { describe, it, expect } from 'vitest';
import { ReplayEngine } from '../../src/analysis/replay';
import { ScopeGuard } from '../../src/core/scope';
import { silentLogger } from '../../src/core/logger';
import { replaySchema, scopeSchema } from '../../src/config/schema';
import type { ObservedRequest } from '../../src/core/types';

const TARGET = 'https://app.test/';

function fakeContext(capture: { headers?: Record<string, string> }) {
  return {
    fetch: async (_url: string, opts: any) => {
      capture.headers = opts.headers;
      return {
        status: () => 200,
        headers: () => ({ 'content-type': 'application/json' }),
        text: async () => '{"ok":true}',
      };
    },
  } as any;
}

function mkReq(method: string, url: string, headers: Array<{ name: string; value: string; redacted?: boolean }> = []): ObservedRequest {
  return {
    id: 'r', user: 'user_a', method, url, host: new URL(url).hostname,
    requestHeaders: headers, params: [], responseHeaders: [], timing: { startedAt: 0 },
  };
}

function engine(specOverride: Record<string, unknown> = {}, ctxFactory: (u: string) => any = () => fakeContext({})) {
  return new ReplayEngine({
    spec: replaySchema.parse(specOverride),
    scope: new ScopeGuard(TARGET, scopeSchema.parse({})),
    logger: silentLogger(),
    requestContextFor: ctxFactory,
  });
}

describe('ReplayEngine policy', () => {
  it('replays a safe GET and reports success', async () => {
    const capture: { headers?: Record<string, string> } = {};
    const e = engine({}, () => fakeContext(capture));
    const res = await e.replay(mkReq('GET', `${TARGET}api/orders/1`), 'user_b');
    expect(res.requested).toBe(true);
    expect(res.status).toBe(200);
  });

  it('skips mutating methods unless allowDestructive is set', async () => {
    const res = await engine().replay(mkReq('POST', `${TARGET}api/orders`), 'user_b');
    expect(res.requested).toBe(false);
    expect(res.skippedReason).toMatch(/mutating|allow-list/i);
  });

  it('replays a POST when explicitly allowed', async () => {
    const e = engine({ allowedMethods: ['GET', 'POST'], allowDestructive: true });
    const res = await e.replay(mkReq('POST', `${TARGET}api/orders`), 'user_b');
    expect(res.requested).toBe(true);
  });

  it('skips out-of-scope URLs', async () => {
    const res = await engine().replay(mkReq('GET', 'https://evil.test/x'), 'user_b');
    expect(res.requested).toBe(false);
    expect(res.skippedReason).toMatch(/scope/i);
  });

  it('skips when replay is disabled', async () => {
    const res = await engine({ enabled: false }).replay(mkReq('GET', `${TARGET}a`), 'user_b');
    expect(res.requested).toBe(false);
  });

  it('never forwards the source user secret headers', async () => {
    const capture: { headers?: Record<string, string> } = {};
    const e = engine({}, () => fakeContext(capture));
    await e.replay(
      mkReq('GET', `${TARGET}api/orders/1`, [
        { name: 'Cookie', value: '[REDACTED]', redacted: true },
        { name: 'Authorization', value: '[REDACTED]', redacted: true },
        { name: 'Accept', value: 'application/json' },
        { name: 'X-Requested-With', value: 'fetch' },
      ]),
      'user_b',
    );
    const keys = Object.keys(capture.headers ?? {}).map((k) => k.toLowerCase());
    expect(keys).not.toContain('cookie');
    expect(keys).not.toContain('authorization');
    expect(keys).toContain('accept');
    expect(keys).toContain('x-requested-with');
  });

  it('honors the replay budget', async () => {
    const e = engine({ maxReplays: 1 });
    const first = await e.replay(mkReq('GET', `${TARGET}a`), 'user_b');
    const second = await e.replay(mkReq('GET', `${TARGET}b`), 'user_b');
    expect(first.requested).toBe(true);
    expect(second.requested).toBe(false);
    expect(second.skippedReason).toMatch(/budget/i);
  });
});
