/* Minimal SPA for the vulnerable test fixture.
 *
 * Exercises the discovery surfaces the auditor must handle:
 *  - navigation built dynamically in JS (not in initial HTML),
 *  - client-side routing via history.pushState,
 *  - data loaded through fetch() (XHR-style), including a background request to
 *    an endpoint (/api/internal/debug) that appears in NO link or DOM text,
 *  - dynamically generated links (order detail) created via createElement.
 */
(function () {
  'use strict';

  var app = document.getElementById('app');
  var nav = document.getElementById('nav');
  var whoami = document.getElementById('whoami');
  var currentUser = null;

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      if (k === 'text') node.textContent = attrs[k];
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) {
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function api(path) {
    return fetch(path, { headers: { 'X-Requested-With': 'fetch' } }).then(function (r) {
      var ct = r.headers.get('content-type') || '';
      return ct.indexOf('json') > -1 ? r.json().then(function (b) { return { status: r.status, body: b }; })
                                     : r.text().then(function (b) { return { status: r.status, body: b }; });
    });
  }

  function navigate(path) {
    history.pushState({}, '', path);
    render();
  }

  // Build the navigation menu dynamically. The Admin link only appears for
  // admins — so lower-privilege contexts never "see" the admin route in the UI.
  function buildNav() {
    nav.innerHTML = '';
    var links = [
      { path: '/', label: 'Home' },
      { path: '/dashboard', label: 'Dashboard' },
      { path: '/profile', label: 'Profile' },
    ];
    if (currentUser && currentUser.role === 'admin') links.push({ path: '/admin', label: 'Admin' });
    links.forEach(function (l) {
      var a = el('a', { href: l.path, 'data-route': l.path, text: l.label });
      a.addEventListener('click', function (ev) {
        ev.preventDefault();
        navigate(l.path);
      });
      nav.appendChild(a);
    });
  }

  function renderHome() {
    app.innerHTML = '';
    app.appendChild(el('h1', { text: 'Welcome to Test Shop' }));
    var list = el('ul', { id: 'products' });
    app.appendChild(list);
    api('/api/products').then(function (res) {
      (res.body.products || []).forEach(function (p) {
        list.appendChild(el('li', { text: p.name + ' — $' + p.price }));
      });
    });
  }

  function renderDashboard() {
    app.innerHTML = '';
    app.appendChild(el('h1', { text: 'Your Orders' }));
    var list = el('ul', { id: 'orders' });
    app.appendChild(list);
    api('/api/orders').then(function (res) {
      var orders = (res.body && res.body.orders) || [];
      orders.forEach(function (o) {
        // Dynamically generated link to the (IDOR-vulnerable) detail endpoint.
        var a = el('a', { href: '/orders/' + o.id, 'data-route': '/orders/' + o.id, text: o.item });
        a.addEventListener('click', function (ev) {
          ev.preventDefault();
          navigate('/orders/' + o.id);
        });
        list.appendChild(el('li', {}, [a]));
      });
      // Auto-load the first owned order's detail so the concrete resource id is
      // observed even without a click (keeps the fixture deterministic). Also
      // exercise the securely-checked variant, which the auditor must NOT flag
      // (it returns 403 to non-owners) — a true-negative demonstration.
      if (orders[0]) {
        api('/api/orders/' + orders[0].id);
        api('/api/secure/orders/' + orders[0].id);
      }
    });
  }

  function renderOrder(id) {
    app.innerHTML = '';
    app.appendChild(el('h1', { text: 'Order ' + id }));
    var pre = el('pre', { id: 'order-detail', text: 'Loading…' });
    app.appendChild(pre);
    api('/api/orders/' + id).then(function (res) {
      pre.textContent = JSON.stringify(res.body, null, 2);
    });
  }

  function renderAdmin() {
    app.innerHTML = '';
    app.appendChild(el('h1', { text: 'Admin' }));
    var stats = el('pre', { id: 'admin-stats', text: 'Loading stats…' });
    var users = el('pre', { id: 'admin-users', text: 'Loading users…' });
    app.appendChild(stats);
    app.appendChild(users);
    api('/api/admin/stats').then(function (res) { stats.textContent = JSON.stringify(res.body, null, 2); });
    api('/api/admin/users').then(function (res) { users.textContent = JSON.stringify(res.body, null, 2); });
  }

  function renderProfile() {
    app.innerHTML = '';
    app.appendChild(el('h1', { text: 'Profile' }));
    var pre = el('pre', { id: 'profile', text: 'Loading…' });
    app.appendChild(pre);
    api('/api/me').then(function (res) { pre.textContent = JSON.stringify(res.body, null, 2); });
  }

  function render() {
    var path = location.pathname;
    if (path === '/' || path === '') return renderHome();
    if (path === '/dashboard') return renderDashboard();
    if (path.indexOf('/orders/') === 0) return renderOrder(path.split('/')[2]);
    if (path === '/admin') return renderAdmin();
    if (path === '/profile') return renderProfile();
    app.innerHTML = '';
    app.appendChild(el('p', { text: 'Not found: ' + path }));
  }

  window.addEventListener('popstate', render);

  // Boot: identify the user, build nav, render, and fire a background request to
  // an endpoint that is exposed by mistake and referenced nowhere in the markup.
  api('/api/me')
    .then(function (res) {
      currentUser = res.status === 200 ? res.body : null;
      whoami.textContent = currentUser ? currentUser.name + ' (' + currentUser.role + ')' : 'anonymous';
    })
    .catch(function () { whoami.textContent = 'anonymous'; })
    .then(function () {
      buildNav();
      render();
      // Background telemetry-style call to a mistakenly-exposed endpoint.
      api('/api/internal/debug').catch(function () {});
    });
})();
