import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// The complex, multi-tenant fixture (CommonJS).
import { start } from '../../test-app-enterprise/server.js';
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
  outDir = mkdtempSync(join(tmpdir(), 'aa-ent-'));
});

afterAll(() => {
  server?.close();
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

const anyFinding = (f: Finding[], pred: (x: Finding) => boolean) => f.some(pred);
const urlRe = (f: Finding[], re: RegExp) => f.some((x) => re.test(x.url ?? ''));

describe('end-to-end scan against the complex multi-tenant fixture (Acme Cloud)', () => {
  it(
    'discovers the full API surface across roles/tenants and reports the planted authz issues (and only those)',
    async () => {
      const config = validateConfig({
        authorizedTesting: true,
        target: { url: baseUrl },
        users: [
          { name: 'alice', role: 'member', privilegeLevel: 10, tenant: 1, cookies: [{ name: 'session', value: 'tok_alice' }] },
          { name: 'bob', role: 'member', privilegeLevel: 10, tenant: 1, cookies: [{ name: 'session', value: 'tok_bob' }] },
          { name: 'mallory', role: 'member', privilegeLevel: 10, tenant: 2, cookies: [{ name: 'session', value: 'tok_mallory' }] },
          { name: 'admin1', role: 'org_admin', privilegeLevel: 80, tenant: 1, cookies: [{ name: 'session', value: 'tok_admin' }] },
          { name: 'root', role: 'super_admin', privilegeLevel: 120, tenant: 1, cookies: [{ name: 'session', value: 'tok_root' }] },
          { name: 'anonymous', role: 'anonymous', privilegeLevel: 0 },
        ],
        // Navigation-only crawl keeps the e2e fast and deterministic; each route
        // auto-fetches its data, so the whole API surface is still observed.
        crawl: { maxDepth: 4, maxPages: 16, interact: false, settleMs: 100 },
        scope: { requestsPerSecond: 40 },
        idor: { enabled: true, numericNeighbors: 2 },
        output: { dir: outDir, formats: ['json', 'html'] },
      });

      const outcome = await runScan({ config, logger: silentLogger() });
      const findings = outcome.scan.findings;

      // ── Discovery coverage: SPA routes, nested resources, multiple id formats,
      //    and non-HTML transports (SSE + WebSocket) ────────────────────────────
      const sigs = [...new Set(outcome.bundle.inventory.flatMap((i) => i.endpoints.map((e) => e.pathTemplate)))];
      expect(sigs).toContain('/api/users/{id}');
      expect(sigs).toContain('/api/orgs/{id}/projects/{id}');
      expect(sigs).toContain('/api/projects/{id}/tasks/{uuid}'); // numeric + UUID in one path
      expect(sigs).toContain('/api/documents/{slug}'); // slug ids
      const sources = new Set(outcome.bundle.inventory.flatMap((i) => i.endpoints.flatMap((e) => e.sources)));
      expect(sources.has('eventsource')).toBe(true); // SSE stream discovered
      expect(sources.has('websocket')).toBe(true); // WebSocket discovered
      expect(sources.has('fetch')).toBe(true);

      // ── Horizontal (object-level) across id formats ──────────────────────────
      expect(anyFinding(findings, (x) => x.type === 'AUTHZ-HORIZONTAL' && /\/api\/users\/\d+$/.test(x.url ?? ''))).toBe(true); // PII IDOR
      expect(anyFinding(findings, (x) => x.type === 'AUTHZ-HORIZONTAL' && /\/api\/tickets\/\d+$/.test(x.url ?? ''))).toBe(true); // ticket IDOR
      expect(anyFinding(findings, (x) => x.type === 'AUTHZ-HORIZONTAL' && /\/tasks\/[0-9a-f-]{36}$/.test(x.url ?? ''))).toBe(true); // UUID task IDOR
      expect(anyFinding(findings, (x) => x.type === 'AUTHZ-HORIZONTAL' && /\/api\/documents\//.test(x.url ?? ''))).toBe(true); // slug IDOR

      // ── Cross-tenant isolation: an org-2 member reaching an org-1 resource ────
      expect(anyFinding(findings, (x) => x.testUser === 'mallory' && /\/api\/orgs\/1\//.test(x.url ?? ''))).toBe(true);

      // ── Vertical (privilege escalation / function-level) ─────────────────────
      expect(urlRe(findings, /\/api\/admin\/metrics/)).toBe(true); // missing super_admin check
      expect(urlRe(findings, /\/api\/orgs\/\d+\/invoices/)).toBe(true); // billing without org_admin
      expect(urlRe(findings, /\/api\/orgs\/\d+\/export/)).toBe(true); // function-level export
      // Mistaken exposure reachable anonymously, discovered via a background fetch.
      expect(anyFinding(findings, (x) => x.testUser === 'anonymous' && /\/api\/admin\/feature-flags/.test(x.url ?? ''))).toBe(true);

      // ── Active enumeration analyzer: an open numeric-id endpoint is sweepable ─
      expect(anyFinding(findings, (x) => x.type === 'AUTHZ-IDOR-ENUM' && /(users|tickets)/.test(x.normalizedRoute ?? ''))).toBe(true);

      // ── GraphQL: per-operation authz over a single /graphql URL ──────────────
      expect(anyFinding(findings, (x) => x.type === 'AUTHZ-HORIZONTAL' && /GRAPHQL query ticket/.test(x.normalizedRoute ?? ''))).toBe(true);
      expect(anyFinding(findings, (x) => x.type === 'AUTHZ-VERTICAL' && /GRAPHQL query adminMetrics/.test(x.normalizedRoute ?? ''))).toBe(true);
      // the securely-checked GraphQL operation must NOT be flagged
      expect(anyFinding(findings, (x) => /GRAPHQL query secureTicket/.test(x.normalizedRoute ?? ''))).toBe(false);

      // ── Authentication-state analyzer: an endpoint reachable with no session ─
      expect(anyFinding(findings, (x) => x.type === 'AUTHN-NO-AUTH' && (x.tags ?? []).includes('no-auth') && /feature-flags/.test(x.url ?? ''))).toBe(true);

      // ── Tenant-awareness: cross-tenant elevated+tagged; same-tenant access to a
      //    tenant-scoped resource downgraded to info (likely legitimate sharing) ─
      expect(anyFinding(findings, (x) => (x.tags ?? []).includes('cross-tenant') && x.severity === 'high')).toBe(true);
      expect(anyFinding(findings, (x) => (x.tags ?? []).includes('same-tenant-shared') && x.severity === 'info')).toBe(true);
      // A same-tenant per-user resource (ticket/PII) is NOT downgraded.
      expect(anyFinding(findings, (x) => (x.tags ?? []).includes('same-tenant') && x.severity === 'high')).toBe(true);

      // ── True negatives: correctly-secured endpoints must NOT be flagged ──────
      expect(urlRe(findings, /\/api\/users\/\d+\/secure/)).toBe(false);
      expect(urlRe(findings, /\/api\/orgs\/\d+\/billing\/summary/)).toBe(false);
      expect(urlRe(findings, /\/api\/admin\/orgs(\b|$)/)).toBe(false);
      expect(urlRe(findings, /\/api\/tickets\/\d+\/secure/)).toBe(false);
      // Mutating operations must never be replayed by default (GraphQL *queries*
      // are POST but read-only and legitimately appear).
      expect(urlRe(findings, /\/suspend/)).toBe(false);
      expect(anyFinding(findings, (x) => /GRAPHQL mutation|GRAPHQL subscription/.test(x.normalizedRoute ?? ''))).toBe(false);

      // ── Scale sanity + reports ───────────────────────────────────────────────
      expect(findings.length).toBeGreaterThan(15);
      expect(outcome.scan.stats.replays).toBeGreaterThan(10);
      expect(outcome.scan.stats.endpoints).toBeGreaterThan(20);
      expect(existsSync(join(outDir, 'report.json'))).toBe(true);
      expect(existsSync(join(outDir, 'report.html'))).toBe(true);
      const raw = readFileSync(join(outDir, 'report.json'), 'utf8');
      for (const secret of ['tok_alice', 'tok_admin', 'tok_root', 'tok_mallory']) {
        expect(raw).not.toContain(secret);
      }
    },
    240000,
  );
});
