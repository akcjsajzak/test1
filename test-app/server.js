'use strict';
/**
 * Deliberately-vulnerable test application.
 *
 * This app is a fixture for the auditor's automated tests. It intentionally
 * contains broken access controls so the scanner has something to find. It is
 * NOT a real service and must never be exposed publicly.
 *
 * Deliberate cases:
 *  - Horizontal (IDOR):   GET /api/orders/:id          -> returns any order, no owner check   [VULN]
 *  - Horizontal (secure): GET /api/secure/orders/:id   -> 403 unless caller owns the order    [OK]
 *  - Vertical (broken):   GET /api/admin/stats         -> no role check, any logged-in user    [VULN]
 *  - Vertical (secure):   GET /api/admin/users         -> 403 unless admin                      [OK]
 *  - Mistaken exposure:   GET /api/internal/debug      -> reachable by anyone (network-only)    [VULN]
 *  - Mutating admin op:   POST /api/admin/users/:id/disable -> admin only (not replayed safely) [OK]
 *  - Per-user content:    GET /api/me, /api/orders     -> different content per user (not a vuln)
 *  - Public content:      GET /api/products            -> identical for everyone (not a vuln)
 */
const express = require('express');
const crypto = require('crypto');
const path = require('path');

// --- Fixture data -----------------------------------------------------------

const USERS = {
  token_user_a: { id: 1, name: 'Alice', role: 'user' },
  token_user_b: { id: 2, name: 'Bob', role: 'user' },
  token_admin: { id: 3, name: 'Carol', role: 'admin' },
};

const ORDERS = {
  4815: { id: 4815, owner: 1, item: 'Blue Widget', total: 42.5, secret: 'alice-only-note' },
  1623: { id: 1623, owner: 2, item: 'Green Gadget', total: 99.9, secret: 'bob-only-note' },
  2342: { id: 2342, owner: 3, item: 'Admin Gizmo', total: 12.0, secret: 'carol-only-note' },
};

const PRODUCTS = [
  { id: 'p1', name: 'Widget', price: 9.99 },
  { id: 'p2', name: 'Gadget', price: 19.99 },
  { id: 'p3', name: 'Gizmo', price: 29.99 },
];

// --- App --------------------------------------------------------------------

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx > -1) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Identify the caller from the session cookie (or anonymous).
  app.use((req, _res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    req.user = USERS[cookies.session] || null;
    next();
  });

  const requireAuth = (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'unauthorized', message: 'login required' });
    next();
  };

  // A per-request CSRF-like token: a deliberately dynamic field, to verify the
  // comparator ignores it rather than flagging every response as different.
  const csrf = () => crypto.randomBytes(8).toString('hex');

  // Current user — different content per user (must NOT be flagged horizontal).
  app.get('/api/me', requireAuth, (req, res) => {
    res.json({ id: req.user.id, name: req.user.name, role: req.user.role, csrfToken: csrf(), ts: Date.now() });
  });

  // Public catalogue — identical for everyone (must NOT be flagged).
  app.get('/api/products', (_req, res) => {
    res.json({ products: PRODUCTS, csrfToken: csrf() });
  });

  // The caller's own orders — per-user content.
  app.get('/api/orders', requireAuth, (req, res) => {
    const mine = Object.values(ORDERS).filter((o) => o.owner === req.user.id);
    res.json({ orders: mine, csrfToken: csrf() });
  });

  // VULNERABLE horizontal: returns any order regardless of ownership (IDOR).
  app.get('/api/orders/:id', requireAuth, (req, res) => {
    const order = ORDERS[req.params.id];
    if (!order) return res.status(404).json({ error: 'not_found' });
    res.json({ order, csrfToken: csrf() });
  });

  // SECURE horizontal: enforces ownership.
  app.get('/api/secure/orders/:id', requireAuth, (req, res) => {
    const order = ORDERS[req.params.id];
    if (!order) return res.status(404).json({ error: 'not_found' });
    if (order.owner !== req.user.id) return res.status(403).json({ error: 'forbidden', message: 'not your order' });
    res.json({ order, csrfToken: csrf() });
  });

  // VULNERABLE vertical: admin stats with no role check.
  app.get('/api/admin/stats', requireAuth, (_req, res) => {
    res.json({
      stats: { users: Object.keys(USERS).length, orders: Object.keys(ORDERS).length, revenue: 154.4 },
      csrfToken: csrf(),
    });
  });

  // SECURE vertical: proper role check.
  app.get('/api/admin/users', requireAuth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden', message: 'admin only' });
    res.json({ users: Object.values(USERS).map((u) => ({ id: u.id, name: u.name, role: u.role })), csrfToken: csrf() });
  });

  // Mutating admin op — must not be replayed by default (safe-by-default policy).
  app.post('/api/admin/users/:id/disable', requireAuth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
    res.json({ disabled: Number(req.params.id), by: req.user.name });
  });

  // Mistaken exposure: reachable by anyone (even anonymous). Only discoverable
  // via a background fetch, not via any HTML link.
  app.get('/api/internal/debug', (req, res) => {
    res.json({
      build: 'test-1.0.0',
      env: 'staging',
      caller: req.user ? req.user.name : 'anonymous',
      flags: { newCheckout: true, betaAdmin: false },
    });
  });

  // Static SPA.
  app.use('/', express.static(path.join(__dirname, 'public')));
  // SPA fallback for client-side routes.
  app.get(/^\/(dashboard|orders|admin|profile).*/, (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  return app;
}

/** Start the app on a port (0 = ephemeral). Resolves with { server, port }. */
function start(port = process.env.PORT ? Number(process.env.PORT) : 4123) {
  return new Promise((resolve) => {
    const server = createApp().listen(port, '127.0.0.1', () => {
      const actual = server.address().port;
      resolve({ server, port: actual });
    });
  });
}

module.exports = { createApp, start, USERS };

if (require.main === module) {
  start().then(({ port }) => {
    // eslint-disable-next-line no-console
    console.log(`[test-app] listening on http://127.0.0.1:${port}`);
  });
}
