import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// The test app is a CommonJS fixture.
import { start } from '../../test-app/server.js';
import { validateConfig } from '../../src/config/loader';
import { silentLogger } from '../../src/core/logger';
import { runScan } from '../../src/orchestrator/scan';
import type { Finding } from '../../src/core/types';

let server: { close: () => void };
let baseUrl: string;
let outDir: string;

beforeAll(async () => {
  const started = await start(0);
  server = started.server;
  baseUrl = `http://127.0.0.1:${started.port}/`;
  outDir = mkdtempSync(join(tmpdir(), 'aa-e2e-'));
});

afterAll(() => {
  server?.close();
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

function findingsFor(findings: Finding[], type: string) {
  return findings.filter((f) => f.type === type);
}

describe('end-to-end scan against the vulnerable test app', () => {
  it(
    'crawls, replays safely, detects horizontal + vertical authz, and writes reports',
    async () => {
      const config = validateConfig({
        authorizedTesting: true,
        target: { url: baseUrl },
        users: [
          { name: 'user_a', role: 'user', privilegeLevel: 10, cookies: [{ name: 'session', value: 'token_user_a' }] },
          { name: 'user_b', role: 'user', privilegeLevel: 10, cookies: [{ name: 'session', value: 'token_user_b' }] },
          { name: 'admin', role: 'admin', privilegeLevel: 100, cookies: [{ name: 'session', value: 'token_admin' }] },
          { name: 'anonymous', role: 'anonymous', privilegeLevel: 0 },
        ],
        crawl: { maxDepth: 3, maxPages: 30, settleMs: 300 },
        output: { dir: outDir, formats: ['json', 'html'] },
      });

      const outcome = await runScan({ config, logger: silentLogger() });
      const findings = outcome.scan.findings;

      // --- Horizontal (IDOR): a peer can read another user's order ---
      const horizontal = findingsFor(findings, 'AUTHZ-HORIZONTAL');
      expect(horizontal.length).toBeGreaterThanOrEqual(1);
      expect(
        horizontal.some((f) => f.testUser === 'user_b' && /\/api\/orders\/4815/.test(f.url ?? '')),
      ).toBe(true);
      // High confidence because the shared resource id is echoed back.
      expect(horizontal.some((f) => f.confidence === 'high')).toBe(true);

      // --- Vertical: lower-privilege users reach admin-observed capabilities ---
      const vertical = findingsFor(findings, 'AUTHZ-VERTICAL');
      expect(vertical.some((f) => /\/api\/admin\/stats/.test(f.url ?? ''))).toBe(true);
      expect(vertical.some((f) => /\/api\/internal\/debug/.test(f.url ?? ''))).toBe(true);

      // --- True negatives: the securely-checked endpoints must NOT be flagged ---
      const flaggedUrls = findings.map((f) => f.url ?? '');
      expect(flaggedUrls.some((u) => u.includes('/api/secure/orders'))).toBe(false);
      expect(flaggedUrls.some((u) => u.includes('/api/admin/users'))).toBe(false);

      // --- Coverage: the scanner discovered SPA-driven API endpoints ---
      expect(outcome.scan.stats.endpoints).toBeGreaterThan(3);
      expect(outcome.scan.stats.replays).toBeGreaterThan(0);
      // The network-only endpoint (in no HTML link) was discovered.
      const allSignatures = outcome.bundle.inventory.flatMap((i) => i.endpoints.map((e) => e.pathTemplate));
      expect(allSignatures.some((s) => s.includes('/api/internal/debug'))).toBe(true);
      expect(allSignatures.some((s) => s.includes('/api/secure/orders'))).toBe(true);

      // --- Reports written ---
      expect(existsSync(join(outDir, 'report.json'))).toBe(true);
      expect(existsSync(join(outDir, 'report.html'))).toBe(true);
      const report = JSON.parse(readFileSync(join(outDir, 'report.json'), 'utf8'));
      expect(report.findings.length).toBe(findings.length);
      // No secret values leaked into the report.
      const raw = readFileSync(join(outDir, 'report.json'), 'utf8');
      expect(raw).not.toContain('token_user_a');
      expect(raw).not.toContain('token_admin');
    },
    120000,
  );
});
