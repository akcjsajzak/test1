'use strict';
/**
 * "Atlas ERP" — a deliberately-vulnerable, classic business-operations suite.
 *
 * The largest fixture: a two-dimensional role matrix of 5 departments × 5
 * authority levels (25 roles) plus a global admin. Departments segregate which
 * resource *types* a user may touch; authority levels gate *sensitive* resources
 * and approvals within a department. Cross-department access is admin-only.
 *
 * The point is a *complicated* authorization matrix whose enforcement is right
 * in most places and wrong in a few, so a scanner's precision and recall are
 * both measured at scale.
 *
 *   departments : sales, procurement, finance, hr, it
 *   levels      : viewer(1) < contributor(2) < approver(3) < manager(4) < director(5)
 *   + admin (global)
 *
 * Policy engine (see enforce()):
 *   SECURE_DEPT  : same department (or admin)                       [correct]
 *   SECURE_LEVEL : same department AND level >= minLevel (or admin)  [correct]
 *   VULN_NONE    : no check at all -> cross-department leak          [BROKEN]
 *   VULN_LEVEL   : department checked but level check missing        [BROKEN]
 *
 * NOT a real service — never expose it publicly.
 */
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const DEPARTMENTS = ['sales', 'procurement', 'finance', 'hr', 'it'];
const LEVELS = [['viewer', 1], ['contributor', 2], ['approver', 3], ['manager', 4], ['director', 5]];
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// ── Users: the full 5×5 matrix + admin ──────────────────────────────────────
const USERS = {};
const TOKENS = {};
let uid = 1;
for (const dept of DEPARTMENTS) {
  for (const [lname, lvl] of LEVELS) {
    const id = uid++;
    const token = `tok_${dept}_${lname}`;
    USERS[id] = { id, name: `${cap(dept)} ${cap(lname)}`, dept, level: lvl, levelName: lname, role: `${dept}_${lname}`, token };
    TOKENS[token] = id;
  }
}
const ADMIN_ID = uid++;
USERS[ADMIN_ID] = { id: ADMIN_ID, name: 'Global Admin', dept: '*', level: 99, levelName: 'admin', role: 'admin', token: 'tok_admin' };
TOKENS.tok_admin = ADMIN_ID;

// ── Resource registry (department-scoped business objects) ──────────────────
function items(list) {
  const out = {};
  for (const it of list) out[it.id] = it;
  return out;
}
const RESOURCES = {
  // finance
  'finance/invoices': { dept: 'finance', policy: 'VULN_NONE', label: 'Invoices', // BROKEN: cross-dept leak
    items: items([{ id: 9001, vendor: 'Globex', amount: 42000, status: 'due' }, { id: 9002, vendor: 'Initech', amount: 15300, status: 'paid' }]) },
  'finance/budgets': { dept: 'finance', policy: 'VULN_LEVEL', minLevel: 5, sensitiveLevel: 5, label: 'Budgets', // BROKEN: level not enforced
    items: items([{ id: 'BUD-FY-01', line: 'Engineering', total: 5000000 }, { id: 'BUD-FY-02', line: 'Marketing', total: 1200000 }]) },
  'finance/payments': { dept: 'finance', policy: 'SECURE_DEPT', label: 'Payments',
    items: items([{ id: 8801, to: 'Payroll', amount: 240000 }, { id: 8802, to: 'Globex', amount: 42000 }]) },
  // sales
  'sales/deals': { dept: 'sales', policy: 'VULN_NONE', label: 'Deals', // BROKEN: cross-dept leak (IDOR)
    items: items([{ id: 7001, account: 'Wayne Enterprises', value: 320000, stage: 'won' }, { id: 7002, account: 'Stark Industries', value: 210000, stage: 'negotiation' }]) },
  'sales/customers': { dept: 'sales', policy: 'SECURE_DEPT', label: 'Customers',
    items: items([{ id: 'C-100', name: 'Wayne Enterprises', tier: 'enterprise' }, { id: 'C-101', name: 'Stark Industries', tier: 'enterprise' }]) },
  // procurement (sequential ids -> enumeration target)
  'procurement/purchase-orders': { dept: 'procurement', policy: 'VULN_NONE', label: 'Purchase Orders', // BROKEN
    items: items([6001, 6002, 6003, 6004, 6005, 6006].map((id) => ({ id, vendor: `Vendor ${id}`, amount: 1000 * (id - 6000) }))) },
  'procurement/vendors': { dept: 'procurement', policy: 'SECURE_DEPT', label: 'Vendors',
    items: items([{ id: 'V-1', name: 'Globex' }, { id: 'V-2', name: 'Initech' }]) },
  // hr
  'hr/employees': { dept: 'hr', policy: 'SECURE_DEPT', label: 'Employees',
    items: items([{ id: 'E-1', name: 'Alice Ng', title: 'Engineer' }, { id: 'E-2', name: 'Bob Lee', title: 'Designer' }]) },
  'hr/payroll': { dept: 'hr', policy: 'SECURE_LEVEL', minLevel: 4, sensitiveLevel: 4, label: 'Payroll', // correct level-gate
    items: items([{ id: 'P-1', employee: 'Alice Ng', salary: 145000 }, { id: 'P-2', employee: 'Bob Lee', salary: 120000 }]) },
  // it
  'it/incidents': { dept: 'it', policy: 'SECURE_DEPT', label: 'Incidents',
    items: items([{ id: 'INC-1', title: 'Outage', severity: 'high' }, { id: 'INC-2', title: 'Latency', severity: 'low' }]) },
  'it/assets': { dept: 'it', policy: 'SECURE_DEPT', label: 'Assets',
    items: items([{ id: 'A-1', tag: 'LAPTOP-001' }, { id: 'A-2', tag: 'SERVER-002' }]) },
};

const APPROVAL_LIMIT = { 3: 10000, 4: 100000, 5: Infinity }; // approver/manager/director

function csrf() { return crypto.randomBytes(8).toString('hex'); }
function envelope(data) { return { ...data, _meta: { csrfToken: csrf(), requestId: crypto.randomUUID(), serverTime: new Date().toISOString() } }; }
function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach((p) => { const i = p.indexOf('='); if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}

/** The authorization decision for a resource read. */
function enforce(user, resource) {
  if (user.role === 'admin') return true;
  const sameDept = user.dept === resource.dept;
  switch (resource.policy) {
    case 'VULN_NONE': return true; // BROKEN: any authenticated user
    case 'VULN_LEVEL': return sameDept; // BROKEN: department ok, but level check omitted
    case 'SECURE_DEPT': return sameDept;
    case 'SECURE_LEVEL': return sameDept && user.level >= (resource.minLevel || 0);
    default: return false;
  }
}

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use((req, _res, next) => {
    const c = parseCookies(req.headers.cookie);
    req.user = TOKENS[c.session] ? USERS[TOKENS[c.session]] : null;
    next();
  });
  const auth = (req, res, next) => (req.user ? next() : res.status(401).json(envelope({ error: 'unauthorized' })));

  // ── Form login (for the login recorder) ─────────────────────────────────────
  const EMAIL_TO_TOKEN = {};
  Object.values(USERS).forEach((u) => { EMAIL_TO_TOKEN[`${u.role}@atlas.test`] = u.token; });
  app.post('/api/login', (req, res) => {
    const email = String((req.body && req.body.email) || '').toLowerCase();
    const token = EMAIL_TO_TOKEN[email];
    if (!token || (req.body && req.body.password) !== 'password') return res.status(401).json(envelope({ error: 'invalid_credentials' }));
    res.cookie('session', token, { httpOnly: true, sameSite: 'lax', path: '/' });
    res.json(envelope({ ok: true, user: USERS[TOKENS[token]].name }));
  });

  // ── Identity + shared surfaces (specific routes BEFORE the generic ones) ────
  app.get('/api/me', auth, (req, res) => {
    const u = req.user;
    res.json(envelope({ id: u.id, name: u.name, dept: u.dept, level: u.level, levelName: u.levelName, role: u.role }));
  });
  app.get('/api/directory', auth, (_req, res) => {
    res.json(envelope({ people: Object.values(USERS).filter((u) => u.role !== 'admin').map((u) => ({ name: u.name, dept: u.dept, role: u.role })) }));
  });
  app.get('/api/announcements', auth, (_req, res) => {
    res.json(envelope({ announcements: [{ id: 1, title: 'Q3 all-hands Friday' }, { id: 2, title: 'New expense policy' }] }));
  });
  // Mistaken exposure: no auth, referenced in no link (background fetch only).
  app.get('/api/internal/config', (req, res) => {
    res.json(envelope({ build: 'atlas-2.3.1', env: 'staging', flags: { newApprovals: true }, caller: req.user ? req.user.name : 'anonymous' }));
  });

  // ── Admin console ────────────────────────────────────────────────────────
  app.get('/api/admin/audit-log', auth, (_req, res) => {
    // BROKEN: missing admin check -> any authenticated user reads the audit log.
    res.json(envelope({ entries: [{ ts: Date.now(), actor: 'finance_manager', action: 'approve invoice 9001' }] }));
  });
  app.get('/api/admin/users', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json(envelope({ error: 'forbidden' }));
    res.json(envelope({ users: Object.values(USERS).map((u) => ({ id: u.id, name: u.name, role: u.role, dept: u.dept, level: u.level })) }));
  });
  app.get('/api/admin/roles', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json(envelope({ error: 'forbidden' }));
    res.json(envelope({ departments: DEPARTMENTS, levels: LEVELS.map(([n, v]) => ({ name: n, value: v })) }));
  });

  // ── Reports (finance report intentionally leaks cross-department) ───────────
  app.get('/api/reports/:dept/summary', auth, (req, res) => {
    const dept = req.params.dept;
    const leaks = dept === 'finance'; // BROKEN for finance only
    if (!leaks && req.user.role !== 'admin' && req.user.dept !== dept) return res.status(403).json(envelope({ error: 'forbidden' }));
    res.json(envelope({ report: { dept, totalRecords: 42, revenue: dept === 'finance' ? 4200000 : undefined } }));
  });

  // ── GraphQL (per-operation authorization) ───────────────────────────────────
  app.post('/graphql', (req, res) => {
    const query = (req.body && req.body.query) || '';
    const vars = (req.body && req.body.variables) || {};
    const user = req.user;
    const ext = { extensions: { requestId: crypto.randomUUID() } };
    const has = (n) => new RegExp('\\b' + n + '\\b').test(query);
    if (has('financials')) {
      // BROKEN: finance director-only data, no check.
      return res.json({ data: { financials: { revenue: 4200000, burn: 380000 } }, ...ext });
    }
    if (has('secureEmployee')) {
      if (!user) return res.json({ errors: [{ message: 'unauthorized' }], ...ext });
      if (user.role !== 'admin' && user.dept !== 'hr') return res.json({ errors: [{ message: 'forbidden' }], ...ext });
      const e = RESOURCES['hr/employees'].items[vars.id];
      return res.json({ data: { secureEmployee: e || null }, ...ext });
    }
    if (has('deal')) {
      if (!user) return res.json({ errors: [{ message: 'unauthorized' }], ...ext });
      const d = RESOURCES['sales/deals'].items[vars.id];
      return res.json({ data: { deal: d || null }, ...ext }); // BROKEN: cross-dept IDOR
    }
    if (has('me')) {
      if (!user) return res.json({ errors: [{ message: 'unauthorized' }], ...ext });
      return res.json({ data: { me: { id: user.id, role: user.role, dept: user.dept } }, ...ext });
    }
    return res.json({ errors: [{ message: 'unknown operation' }], ...ext });
  });

  // ── SSE notifications (short-lived, per-user) ───────────────────────────────
  app.get('/api/notifications', auth, (req, res) => {
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    let n = 0;
    const timer = setInterval(() => {
      n += 1;
      res.write(`data: ${JSON.stringify({ to: req.user.name, msg: `note ${n}` })}\n\n`);
      if (n >= 2) { res.write('event: done\ndata: {}\n\n'); clearInterval(timer); res.end(); }
    }, 120);
    req.on('close', () => clearInterval(timer));
  });

  // ── Expenses: list returns the caller's OWN, detail leaks ANY (within finance)
  // A classic enumeration IDOR — the detail endpoint omits the owner check, so a
  // finance user can read colleagues' expenses by guessing sequential ids.
  const EXPENSES = {
    3001: { id: 3001, ownerRole: 'finance_viewer', merchant: 'Cafe', amount: 12 },
    3002: { id: 3002, ownerRole: 'finance_director', merchant: 'Airline', amount: 2400 },
    3003: { id: 3003, ownerRole: 'finance_contributor', merchant: 'Hotel', amount: 640 },
    3004: { id: 3004, ownerRole: 'finance_manager', merchant: 'Taxi', amount: 55 },
  };
  app.get('/api/finance/expenses', auth, (req, res) => {
    if (req.user.role !== 'admin' && req.user.dept !== 'finance') return res.status(403).json(envelope({ error: 'forbidden' }));
    const mine = Object.values(EXPENSES).filter((e) => req.user.role === 'admin' || e.ownerRole === req.user.role);
    res.json(envelope({ items: mine })); // only your own
  });
  app.get('/api/finance/expenses/:id', auth, (req, res) => {
    if (req.user.role !== 'admin' && req.user.dept !== 'finance') return res.status(403).json(envelope({ error: 'forbidden' }));
    const e = EXPENSES[req.params.id];
    if (!e) return res.status(404).json(envelope({ error: 'not_found' }));
    res.json(envelope({ item: e })); // BROKEN: no owner check -> enumeration IDOR
  });

  // ── Generic department resource routes (registered last) ────────────────────
  const resourceFor = (req) => RESOURCES[`${req.params.dept}/${req.params.type}`];
  app.get('/api/:dept/:type', auth, (req, res, next) => {
    if (!DEPARTMENTS.includes(req.params.dept)) return next();
    const r = resourceFor(req);
    if (!r) return res.status(404).json(envelope({ error: 'not_found' }));
    if (!enforce(req.user, r)) return res.status(403).json(envelope({ error: 'forbidden' }));
    res.json(envelope({ resource: `${req.params.dept}/${req.params.type}`, items: Object.values(r.items) }));
  });
  app.get('/api/:dept/:type/:id', auth, (req, res, next) => {
    if (!DEPARTMENTS.includes(req.params.dept)) return next();
    const r = resourceFor(req);
    if (!r) return res.status(404).json(envelope({ error: 'not_found' }));
    if (!enforce(req.user, r)) return res.status(403).json(envelope({ error: 'forbidden' }));
    const item = r.items[req.params.id];
    if (!item) return res.status(404).json(envelope({ error: 'not_found' }));
    res.json(envelope({ item }));
  });
  app.post('/api/:dept/:type/:id/approve', auth, (req, res, next) => {
    if (!DEPARTMENTS.includes(req.params.dept)) return next();
    const r = resourceFor(req);
    if (!r) return res.status(404).json(envelope({ error: 'not_found' }));
    const u = req.user;
    if (u.role !== 'admin' && !(u.dept === r.dept && u.level >= 3)) return res.status(403).json(envelope({ error: 'forbidden' }));
    const item = r.items[req.params.id];
    if (!item) return res.status(404).json(envelope({ error: 'not_found' }));
    const limit = u.role === 'admin' ? Infinity : (APPROVAL_LIMIT[u.level] || 0);
    if ((item.amount || 0) > limit) return res.status(403).json(envelope({ error: 'over_approval_limit' }));
    res.json(envelope({ approved: req.params.id, by: u.name }));
  });

  // ── Static SPA + deep-link fallback ─────────────────────────────────────────
  app.use('/', express.static(path.join(__dirname, 'public')));
  app.get(/^\/(dashboard|sales|procurement|finance|hr|it|admin|reports|directory|announcements|login).*/, (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
  return app;
}

function start(port = process.env.PORT ? Number(process.env.PORT) : 4300) {
  return new Promise((resolve) => {
    const server = createApp().listen(port, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

module.exports = { createApp, start, USERS, TOKENS, RESOURCES, DEPARTMENTS, LEVELS };

if (require.main === module) {
  start().then(({ port }) => {
    // eslint-disable-next-line no-console
    console.log(`[atlas-erp] listening on http://127.0.0.1:${port}  (25 roles + admin)`);
  });
}
