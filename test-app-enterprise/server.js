'use strict';
/**
 * "Acme Cloud" — a deliberately-vulnerable, multi-tenant SaaS fixture.
 *
 * A realistic end-to-end target for the auditor: multiple orgs (tenants), four
 * privilege tiers, nested resources, several id formats (numeric / UUID / slug),
 * pagination + search, Server-Sent Events and a WebSocket. It contains a
 * carefully designed matrix of broken and correct access controls so the
 * scanner's precision and recall can both be measured.
 *
 * NOT a real service. Never expose it publicly.
 *
 * ── Privilege tiers ──────────────────────────────────────────────────────────
 *   anonymous(0) < member(10) < manager(50) < org_admin(80) < super_admin(120)
 *
 * ── Access-control matrix ────────────────────────────────────────────────────
 *  VULNERABLE (auditor SHOULD flag):
 *   H1 GET /api/users/:id                       IDOR: full PII to any caller
 *   H2 GET /api/orgs/:orgId/projects/:projectId cross-tenant: no org membership check
 *   H3 GET /api/tickets/:ticketId               IDOR: any ticket, any tenant
 *   H4 GET /api/projects/:projectId/tasks/:taskId  IDOR (UUID ids)
 *   H5 GET /api/documents/:slug                 IDOR (slug ids)
 *   V1 GET /api/admin/metrics                   vertical: missing super_admin check
 *   V2 GET /api/orgs/:orgId/invoices            vertical: billing w/o org_admin check
 *   V3 GET /api/orgs/:orgId/export              vertical/function-level: any member exports all
 *   E1 GET /api/admin/feature-flags             mistaken exposure: reachable anonymously (network-only)
 *
 *  SECURE (auditor should NOT flag):
 *   N1 GET /api/users/:id/secure                self or same-org admin only
 *   N2 GET /api/orgs/:orgId/billing/summary     org_admin only (403 otherwise)
 *   N3 GET /api/admin/orgs                       super_admin only (403 otherwise)
 *   N4 GET /api/tickets/:ticketId/secure         owner or support only
 *   N5 GET /api/me, /api/tickets, /api/notifications  per-user content (differs)
 *   N6 GET /api/search                           public, identical for all
 *   -- POST /api/admin/orgs/:orgId/suspend       mutating; must not be replayed by default
 */
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { WebSocketServer } = require('ws');

// ── Fixture data ────────────────────────────────────────────────────────────

const ORGS = {
  1: { id: 1, name: 'Acme', plan: 'enterprise' },
  2: { id: 2, name: 'Globex', plan: 'pro' },
};

const USERS = {
  1: { id: 1, name: 'Alice', email: 'alice@acme.test', phone: '555-0101', salary: 120000, role: 'member', orgId: 1 },
  2: { id: 2, name: 'Bob', email: 'bob@acme.test', phone: '555-0102', salary: 110000, role: 'member', orgId: 1 },
  3: { id: 3, name: 'Mallory', email: 'mallory@globex.test', phone: '555-0203', salary: 90000, role: 'member', orgId: 2 },
  4: { id: 4, name: 'Mary Manager', email: 'mary@acme.test', phone: '555-0104', salary: 150000, role: 'manager', orgId: 1 },
  5: { id: 5, name: 'Adam Admin', email: 'adam@acme.test', phone: '555-0105', salary: 180000, role: 'org_admin', orgId: 1 },
  6: { id: 6, name: 'Root', email: 'root@acme.test', phone: '555-0106', salary: 250000, role: 'super_admin', orgId: 1 },
};

const TOKENS = {
  tok_alice: 1, tok_bob: 2, tok_mallory: 3, tok_manager: 4, tok_admin: 5, tok_root: 6,
};

const ROLE_LEVEL = { member: 10, manager: 50, org_admin: 80, super_admin: 120 };

const PROJECTS = {
  101: { id: 101, orgId: 1, name: 'Apollo', budget: 500000 },
  102: { id: 102, orgId: 1, name: 'Zephyr', budget: 250000 },
  201: { id: 201, orgId: 2, name: 'Nimbus', budget: 300000 },
};

// UUID-keyed tasks belonging to projects.
const TASKS = {
  'a1b2c3d4-0000-4000-8000-000000000001': { id: 'a1b2c3d4-0000-4000-8000-000000000001', projectId: 101, title: 'Design API', status: 'open', assignee: 1 },
  'a1b2c3d4-0000-4000-8000-000000000002': { id: 'a1b2c3d4-0000-4000-8000-000000000002', projectId: 101, title: 'Write tests', status: 'done', assignee: 2 },
  'a1b2c3d4-0000-4000-8000-000000000003': { id: 'a1b2c3d4-0000-4000-8000-000000000003', projectId: 201, title: 'Globex secret task', status: 'open', assignee: 3 },
};

const TICKETS = {
  5001: { id: 5001, ownerId: 1, orgId: 1, subject: 'Cannot log in', body: 'Alice private ticket' },
  5002: { id: 5002, ownerId: 2, orgId: 1, subject: 'Billing question', body: 'Bob private ticket' },
  5003: { id: 5003, ownerId: 3, orgId: 2, subject: 'Globex outage', body: 'Mallory private ticket' },
};

const INVOICES = {
  1: [
    { id: 'INV-1001', orgId: 1, amount: 4200, status: 'paid' },
    { id: 'INV-1002', orgId: 1, amount: 5300, status: 'due' },
  ],
  2: [{ id: 'INV-2001', orgId: 2, amount: 1200, status: 'paid' }],
};

const DOCUMENTS = {
  'q3-financials-8842': { slug: 'q3-financials-8842', orgId: 1, title: 'Q3 Financials', body: 'Confidential Acme financials' },
  'globex-roadmap-3310': { slug: 'globex-roadmap-3310', orgId: 2, title: 'Globex Roadmap', body: 'Confidential Globex roadmap' },
};

const CATALOG = [
  { id: 'f1', name: 'Compute' }, { id: 'f2', name: 'Storage' }, { id: 'f3', name: 'Networking' },
];

// ── Helpers ─────────────────────────────────────────────────────────────────

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}
const csrf = () => crypto.randomBytes(8).toString('hex');
const levelOf = (u) => (u ? ROLE_LEVEL[u.role] ?? 0 : 0);
function envelope(data) {
  return { ...data, _meta: { csrfToken: csrf(), serverTime: new Date().toISOString(), requestId: crypto.randomUUID() } };
}

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  app.use((req, _res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    req.user = TOKENS[cookies.session] ? USERS[TOKENS[cookies.session]] : null;
    next();
  });

  const auth = (req, res, next) => (req.user ? next() : res.status(401).json(envelope({ error: 'unauthorized' })));

  // ── Form login (for the login-recorder demo) ────────────────────────────────
  const EMAIL_TO_TOKEN = {};
  for (const [token, uid] of Object.entries(TOKENS)) EMAIL_TO_TOKEN[USERS[uid].email.toLowerCase()] = token;
  app.post('/api/login', (req, res) => {
    const email = String((req.body && req.body.email) || '').toLowerCase();
    const password = (req.body && req.body.password) || '';
    const token = EMAIL_TO_TOKEN[email];
    if (!token || password !== 'password') return res.status(401).json(envelope({ error: 'invalid_credentials' }));
    res.cookie('session', token, { httpOnly: true, sameSite: 'lax', path: '/' });
    res.json(envelope({ ok: true, user: USERS[TOKENS[token]].name }));
  });

  // ── Identity ──────────────────────────────────────────────────────────────
  app.get('/api/me', auth, (req, res) => {
    const u = req.user;
    res.json(envelope({ id: u.id, name: u.name, role: u.role, orgId: u.orgId, level: levelOf(u) }));
  });

  // ── H1 Users: IDOR (full PII to any authenticated caller, any tenant) ───────
  app.get('/api/users/:id', auth, (req, res) => {
    const u = USERS[req.params.id];
    if (!u) return res.status(404).json(envelope({ error: 'not_found' }));
    res.json(envelope({ user: u })); // VULN: no self/org/role check; leaks email, phone, salary
  });

  // ── N1 Users secure: self or same-org admin only ────────────────────────────
  app.get('/api/users/:id/secure', auth, (req, res) => {
    const target = USERS[req.params.id];
    if (!target) return res.status(404).json(envelope({ error: 'not_found' }));
    const caller = req.user;
    const isSelf = caller.id === target.id;
    const isSameOrgAdmin = caller.orgId === target.orgId && levelOf(caller) >= ROLE_LEVEL.org_admin;
    if (!isSelf && !isSameOrgAdmin) return res.status(403).json(envelope({ error: 'forbidden' }));
    res.json(envelope({ user: target }));
  });

  // ── Projects (org-nested) ───────────────────────────────────────────────────
  app.get('/api/orgs/:orgId/projects', auth, (req, res) => {
    // VULN (H2 family): no org-membership check → cross-tenant listing.
    const list = Object.values(PROJECTS).filter((p) => String(p.orgId) === String(req.params.orgId));
    res.json(envelope({ projects: list }));
  });
  app.get('/api/orgs/:orgId/projects/:projectId', auth, (req, res) => {
    const p = PROJECTS[req.params.projectId];
    if (!p) return res.status(404).json(envelope({ error: 'not_found' }));
    res.json(envelope({ project: p })); // VULN H2: no tenant check
  });

  // ── H4 Tasks: IDOR by UUID ──────────────────────────────────────────────────
  app.get('/api/projects/:projectId/tasks', auth, (req, res) => {
    const list = Object.values(TASKS).filter((t) => String(t.projectId) === String(req.params.projectId));
    res.json(envelope({ tasks: list })); // VULN: any project's tasks
  });
  app.get('/api/projects/:projectId/tasks/:taskId', auth, (req, res) => {
    const t = TASKS[req.params.taskId];
    if (!t) return res.status(404).json(envelope({ error: 'not_found' }));
    res.json(envelope({ task: t })); // VULN H4
  });

  // ── V2 Invoices: billing without org_admin check ────────────────────────────
  app.get('/api/orgs/:orgId/invoices', auth, (req, res) => {
    const list = INVOICES[req.params.orgId] || [];
    res.json(envelope({ invoices: list })); // VULN V2: any member can read billing
  });
  // ── N2 Billing summary: org_admin only ──────────────────────────────────────
  app.get('/api/orgs/:orgId/billing/summary', auth, (req, res) => {
    const caller = req.user;
    if (levelOf(caller) < ROLE_LEVEL.org_admin || String(caller.orgId) !== String(req.params.orgId)) {
      return res.status(403).json(envelope({ error: 'forbidden' }));
    }
    const list = INVOICES[req.params.orgId] || [];
    res.json(envelope({ total: list.reduce((s, i) => s + i.amount, 0), count: list.length }));
  });
  // ── V3 Export: function-level, any member exports everything ────────────────
  app.get('/api/orgs/:orgId/export', auth, (req, res) => {
    const orgId = req.params.orgId;
    res.json(envelope({ // VULN V3: should be admin-only
      org: ORGS[orgId],
      projects: Object.values(PROJECTS).filter((p) => String(p.orgId) === String(orgId)),
      invoices: INVOICES[orgId] || [],
      format: req.query.format || 'json',
    }));
  });

  // ── Tickets ─────────────────────────────────────────────────────────────────
  app.get('/api/tickets', auth, (req, res) => {
    const mine = Object.values(TICKETS).filter((t) => t.ownerId === req.user.id);
    res.json(envelope({ tickets: mine })); // per-user content (not a vuln)
  });
  app.get('/api/tickets/:ticketId', auth, (req, res) => {
    const t = TICKETS[req.params.ticketId];
    if (!t) return res.status(404).json(envelope({ error: 'not_found' }));
    res.json(envelope({ ticket: t })); // VULN H3: IDOR
  });
  app.get('/api/tickets/:ticketId/secure', auth, (req, res) => {
    const t = TICKETS[req.params.ticketId];
    if (!t) return res.status(404).json(envelope({ error: 'not_found' }));
    const caller = req.user;
    if (t.ownerId !== caller.id && caller.role !== 'super_admin') {
      return res.status(403).json(envelope({ error: 'forbidden' }));
    }
    res.json(envelope({ ticket: t }));
  });

  // ── H5 Documents: IDOR by slug ──────────────────────────────────────────────
  app.get('/api/documents/:slug', auth, (req, res) => {
    const d = DOCUMENTS[req.params.slug];
    if (!d) return res.status(404).json(envelope({ error: 'not_found' }));
    res.json(envelope({ document: d })); // VULN H5
  });

  // ── Search: public, identical for everyone ──────────────────────────────────
  app.get('/api/search', (req, res) => {
    const q = (req.query.q || '').toString().toLowerCase();
    const results = CATALOG.filter((c) => c.name.toLowerCase().includes(q));
    res.json(envelope({ query: q, page: Number(req.query.page || 1), results }));
  });

  // ── Admin / platform ────────────────────────────────────────────────────────
  app.get('/api/admin/metrics', auth, (_req, res) => {
    // VULN V1: missing super_admin check.
    res.json(envelope({ metrics: { orgs: Object.keys(ORGS).length, users: Object.keys(USERS).length, mrr: 42000 } }));
  });
  app.get('/api/admin/orgs', auth, (req, res) => {
    // N3 SECURE: super_admin only.
    if (req.user.role !== 'super_admin') return res.status(403).json(envelope({ error: 'forbidden' }));
    res.json(envelope({ orgs: Object.values(ORGS) }));
  });
  app.get('/api/admin/feature-flags', (req, res) => {
    // E1 VULN: no auth at all; referenced in no link (fetched in the background).
    res.json(envelope({ flags: { betaBilling: true, newDashboard: false, exportV2: true }, caller: req.user ? req.user.name : 'anonymous' }));
  });
  app.post('/api/admin/orgs/:orgId/suspend', auth, (req, res) => {
    if (req.user.role !== 'super_admin') return res.status(403).json(envelope({ error: 'forbidden' }));
    res.json(envelope({ suspended: Number(req.params.orgId), by: req.user.name }));
  });

  // ── Server-Sent Events: per-user notification stream (short-lived) ──────────
  app.get('/api/notifications', auth, (req, res) => {
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    let n = 0;
    const send = () => {
      n += 1;
      res.write(`data: ${JSON.stringify({ to: req.user.name, msg: `notification ${n}`, at: Date.now() })}\n\n`);
      if (n >= 2) {
        res.write('event: done\ndata: {}\n\n');
        clearInterval(timer);
        res.end();
      }
    };
    const timer = setInterval(send, 120);
    req.on('close', () => clearInterval(timer));
  });

  // ── GraphQL endpoint (tiny hand-rolled resolver) ────────────────────────────
  // All operations share this URL; authorization is per-operation, so it mirrors
  // the REST vuln matrix: ticket = IDOR, secureTicket = enforced, adminMetrics =
  // missing role check, me = per-user.
  app.post('/graphql', (req, res) => {
    const query = (req.body && req.body.query) || '';
    const vars = (req.body && req.body.variables) || {};
    const user = req.user;
    const ext = { extensions: { requestId: crypto.randomUUID() } };
    const has = (name) => new RegExp('\\b' + name + '\\b').test(query);

    if (has('adminMetrics')) {
      // VULN (vertical): no role check.
      return res.json({ data: { adminMetrics: { orgs: Object.keys(ORGS).length, users: Object.keys(USERS).length, mrr: 42000 } }, ...ext });
    }
    if (has('secureTicket')) {
      if (!user) return res.json({ errors: [{ message: 'unauthorized' }], ...ext });
      const t = TICKETS[vars.id];
      if (!t) return res.json({ data: { secureTicket: null }, ...ext });
      if (t.ownerId !== user.id && user.role !== 'super_admin') return res.json({ errors: [{ message: 'forbidden' }], ...ext });
      return res.json({ data: { secureTicket: t }, ...ext });
    }
    if (has('ticket')) {
      if (!user) return res.json({ errors: [{ message: 'unauthorized' }], ...ext });
      const t = TICKETS[vars.id];
      return res.json({ data: { ticket: t || null }, ...ext }); // VULN (IDOR): no ownership check
    }
    if (has('me')) {
      if (!user) return res.json({ errors: [{ message: 'unauthorized' }], ...ext });
      return res.json({ data: { me: { id: user.id, name: user.name, role: user.role } }, ...ext });
    }
    return res.json({ errors: [{ message: 'unknown operation' }], ...ext });
  });

  // ── Static SPA + deep-link fallback ─────────────────────────────────────────
  app.use('/', express.static(path.join(__dirname, 'public')));
  app.get(/^\/(dashboard|projects|tickets|invoices|users|admin|documents|settings|search|login).*/, (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  return app;
}

/** WebSocket presence server attached to the given http.Server. */
function attachWebSocket(server) {
  const wss = new WebSocketServer({ server, path: '/ws/presence' });
  wss.on('connection', (socket, req) => {
    const cookies = parseCookies(req.headers.cookie);
    const uid = TOKENS[cookies.session];
    const user = uid ? USERS[uid] : null;
    socket.send(JSON.stringify({ type: 'presence', you: user ? user.name : 'anonymous', online: 3 }));
    // Close shortly after; this is only to exercise WebSocket observation.
    setTimeout(() => { try { socket.close(); } catch { /* ignore */ } }, 400);
  });
  return wss;
}

function start(port = process.env.PORT ? Number(process.env.PORT) : 4200) {
  return new Promise((resolve) => {
    const server = createApp().listen(port, '127.0.0.1', () => {
      attachWebSocket(server);
      resolve({ server, port: server.address().port });
    });
  });
}

module.exports = { createApp, attachWebSocket, start, TOKENS, USERS };

if (require.main === module) {
  start().then(({ port }) => {
    // eslint-disable-next-line no-console
    console.log(`[acme-cloud] listening on http://127.0.0.1:${port}`);
  });
}
