import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// Atlas ERP: the 5×5 (department × authority level) matrix fixture.
import { start } from '../../test-app-atlas/server.js';
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
  outDir = mkdtempSync(join(tmpdir(), 'aa-atlas-'));
});
afterAll(() => {
  server?.close();
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

const nr = (f: Finding[], re: RegExp) => f.some((x) => re.test(x.normalizedRoute ?? ''));

describe('end-to-end scan against the 5×5 role-matrix fixture (Atlas ERP)', () => {
  it(
    'maps the department × level matrix and flags the broken cells (and only those)',
    async () => {
      const u = (name: string, tenant: string | undefined, level: number, token: string) => ({
        name,
        role: name,
        privilegeLevel: level,
        ...(tenant ? { tenant } : {}),
        cookies: [{ name: 'session', value: token }],
      });
      const config = validateConfig({
        authorizedTesting: true,
        target: { url: baseUrl },
        users: [
          u('finance_viewer', 'finance', 10, 'tok_finance_viewer'),
          u('finance_director', 'finance', 50, 'tok_finance_director'),
          u('sales_viewer', 'sales', 10, 'tok_sales_viewer'),
          u('procurement_approver', 'procurement', 30, 'tok_procurement_approver'),
          u('hr_viewer', 'hr', 10, 'tok_hr_viewer'),
          u('hr_manager', 'hr', 40, 'tok_hr_manager'),
          u('it_viewer', 'it', 10, 'tok_it_viewer'),
          { name: 'admin', role: 'admin', privilegeLevel: 100, cookies: [{ name: 'session', value: 'tok_admin' }] },
          { name: 'anonymous', role: 'anonymous', privilegeLevel: 0 },
        ],
        crawl: { maxDepth: 4, maxPages: 22, interact: false, settleMs: 100 },
        scope: { requestsPerSecond: 40 },
        idor: { enabled: true, numericNeighbors: 3 },
        output: { dir: outDir, formats: ['json', 'html'] },
      });

      const outcome = await runScan({ config, logger: silentLogger() });
      const f = outcome.scan.findings;

      // ── Broken cells (must be flagged) ───────────────────────────────────────
      // cross-department leaks (VULN_NONE): department check missing entirely
      expect(nr(f, /\/api\/finance\/invoices/)).toBe(true);
      expect(nr(f, /\/api\/sales\/deals/)).toBe(true);
      // within-department vertical escalation (VULN_LEVEL): finance budgets = director-only
      expect(f.some((x) => x.type === 'AUTHZ-VERTICAL' && /\/api\/finance\/budgets/.test(x.normalizedRoute ?? ''))).toBe(true);
      // missing admin check
      expect(nr(f, /\/api\/admin\/audit-log/)).toBe(true);
      // cross-department report leak
      expect(nr(f, /\/api\/reports\/finance/)).toBe(true);
      // enumeration IDOR (list returns own, detail leaks any) — records never listed to the user
      expect(f.some((x) => x.type === 'AUTHZ-IDOR-ENUM' && /\/api\/finance\/expenses/.test(x.normalizedRoute ?? ''))).toBe(true);
      // GraphQL: cross-dept IDOR + director-only leak
      expect(f.some((x) => x.type === 'AUTHZ-HORIZONTAL' && /GRAPHQL query deal/.test(x.normalizedRoute ?? ''))).toBe(true);
      expect(f.some((x) => x.type === 'AUTHZ-VERTICAL' && /GRAPHQL query financials/.test(x.normalizedRoute ?? ''))).toBe(true);
      // mistaken exposure reachable with no session
      expect(f.some((x) => x.type === 'AUTHN-NO-AUTH' && /internal\/config/.test(x.normalizedRoute ?? ''))).toBe(true);
      // cross-department findings are tagged for triage
      expect(f.some((x) => (x.tags ?? []).includes('cross-tenant'))).toBe(true);

      // ── Correctly-enforced cells (must NOT be flagged) ───────────────────────
      for (const re of [
        /\/api\/finance\/payments/, // SECURE_DEPT
        /\/api\/hr\/employees/, // SECURE_DEPT
        /\/api\/hr\/payroll/, // SECURE_LEVEL (manager+)
        /\/api\/sales\/customers/,
        /\/api\/it\/incidents/,
        /\/api\/it\/assets/,
        /\/api\/procurement\/vendors/,
        /\/api\/admin\/users/, // admin only
        /\/api\/admin\/roles/,
        /\/api\/reports\/hr/, // dept-enforced report
        /GRAPHQL query secureEmployee/,
      ]) {
        expect(nr(f, re)).toBe(false);
      }
      // no mutating op replayed
      expect(f.some((x) => /GRAPHQL mutation/.test(x.normalizedRoute ?? ''))).toBe(false);

      // ── Scale + reports ──────────────────────────────────────────────────────
      expect(f.length).toBeGreaterThan(20);
      expect(outcome.scan.stats.endpoints).toBeGreaterThan(25);
      expect(existsSync(join(outDir, 'report.html'))).toBe(true);
      const raw = readFileSync(join(outDir, 'report.json'), 'utf8');
      for (const s of ['tok_finance_viewer', 'tok_admin', 'tok_hr_manager']) expect(raw).not.toContain(s);
    },
    240000,
  );
});
