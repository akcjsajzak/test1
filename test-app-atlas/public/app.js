/* Atlas ERP portal — data-driven business SPA with a department/level-aware UI.
 *
 * Each user sees only their department's modules (admin sees everything);
 * sensitive modules (finance budgets, hr payroll) are hidden below their
 * authority level — so a lower-level user's crawl never surfaces them, and the
 * auditor's cross-context replay is a genuine "capability you were never shown"
 * test. Detail pages also fire GraphQL operations.
 */
(function () {
  'use strict';
  var view = document.getElementById('view');
  var nav = document.getElementById('nav');
  var whoami = document.getElementById('whoami');
  var crumbs = document.getElementById('crumbs');
  var me = null;
  var booted = false;

  var MODULES = {
    finance: [{ type: 'invoices', label: 'Invoices' }, { type: 'payments', label: 'Payments' }, { type: 'expenses', label: 'Expenses' }, { type: 'budgets', label: 'Budgets', minLevel: 5 }],
    sales: [{ type: 'deals', label: 'Deals' }, { type: 'customers', label: 'Customers' }],
    procurement: [{ type: 'purchase-orders', label: 'Purchase Orders' }, { type: 'vendors', label: 'Vendors' }],
    hr: [{ type: 'employees', label: 'Employees' }, { type: 'payroll', label: 'Payroll', minLevel: 4 }],
    it: [{ type: 'incidents', label: 'Incidents' }, { type: 'assets', label: 'Assets' }],
  };

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) { if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]); });
    (kids || []).forEach(function (c) { n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }
  function link(path, label) {
    var a = el('a', { href: path, 'data-link': path, class: 'nav-item', text: label });
    a.addEventListener('click', function (e) { e.preventDefault(); navigate(path); });
    return a;
  }
  function pre(o) { return el('pre', { text: typeof o === 'string' ? o : JSON.stringify(o, null, 2) }); }
  function api(p) { return fetch(p, { headers: { 'X-Requested-With': 'fetch', Accept: 'application/json' } }).then(function (r) { return r.json().then(function (b) { return { status: r.status, body: b }; }).catch(function () { return { status: r.status, body: null }; }); }); }
  function gql(query, variables) { return fetch('/graphql', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: query, variables: variables || {} }) }).catch(function () {}); }

  function navigate(p) { history.pushState({}, '', p); render(); }
  window.addEventListener('popstate', render);

  var depts = Object.keys(MODULES);
  function visibleModules(dept) {
    if (!me) return [];
    return (MODULES[dept] || []).filter(function (m) { return me.role === 'admin' || !m.minLevel || me.level >= m.minLevel; });
  }

  function buildNav() {
    nav.innerHTML = '';
    if (!me) { nav.appendChild(link('/login', 'Sign in')); return; }
    nav.appendChild(link('/dashboard', 'Dashboard'));
    var myDepts = me.role === 'admin' ? depts : [me.dept];
    myDepts.forEach(function (d) {
      nav.appendChild(el('div', { class: 'nav-group', text: d.toUpperCase() }));
      visibleModules(d).forEach(function (m) { nav.appendChild(link('/' + d + '/' + m.type, '· ' + m.label)); });
      nav.appendChild(link('/reports/' + d, '· Reports'));
    });
    nav.appendChild(el('div', { class: 'nav-group', text: 'COMPANY' }));
    nav.appendChild(link('/directory', '· Directory'));
    nav.appendChild(link('/announcements', '· Announcements'));
    if (me.role === 'admin') { nav.appendChild(link('/admin', '· Admin console')); }
  }

  // ── views ─────────────────────────────────────────────────────────────────
  function renderDashboard() {
    view.appendChild(el('h1', { text: 'Dashboard' }));
    api('/api/me').then(function (r) { view.appendChild(el('div', { class: 'card' }, [pre(r.body)])); });
    gql('query { me { id role dept } }');
    // A director/admin financial widget (GraphQL). Lower levels never load it.
    if (me && (me.role === 'admin' || me.level >= 5)) gql('query { financials { revenue burn } }');
  }
  function renderList(dept, type) {
    view.appendChild(el('h1', { text: cap(dept) + ' · ' + cap(type) }));
    var box = el('div', { class: 'card' }); view.appendChild(box);
    var list = el('ul', { class: 'list' }); view.appendChild(list);
    api('/api/' + dept + '/' + type).then(function (r) {
      if (r.status !== 200) { box.appendChild(pre(r.body)); return; }
      var itemsArr = (r.body && r.body.items) || [];
      itemsArr.forEach(function (it) { list.appendChild(el('li', {}, [link('/' + dept + '/' + type + '/' + it.id, String(it.id) + (it.name || it.vendor || it.account || it.title || ''))])); });
      if (itemsArr[0]) api('/api/' + dept + '/' + type + '/' + itemsArr[0].id); // observe a concrete detail
    });
  }
  function renderDetail(dept, type, id) {
    view.appendChild(el('h1', { text: cap(dept) + ' · ' + cap(type) + ' #' + id }));
    var box = el('div', { class: 'card' }); view.appendChild(box);
    api('/api/' + dept + '/' + type + '/' + id).then(function (r) { box.appendChild(pre(r.body)); });
    if (dept === 'sales' && type === 'deals') gql('query D($id: ID!){ deal(id:$id){ id account value stage } }', { id: id });
    if (dept === 'hr' && type === 'employees') gql('query E($id: ID!){ secureEmployee(id:$id){ id name title } }', { id: id });
  }
  function renderReports(dept) {
    view.appendChild(el('h1', { text: 'Reports · ' + cap(dept) }));
    var box = el('div', { class: 'card' }); view.appendChild(box);
    api('/api/reports/' + dept + '/summary').then(function (r) { box.appendChild(pre(r.body)); });
  }
  function renderAdmin() {
    view.appendChild(el('h1', { text: 'Admin console' }));
    ['audit-log', 'users', 'roles'].forEach(function (seg) {
      var box = el('div', { class: 'card' }); view.appendChild(box);
      box.appendChild(el('h3', { text: seg }));
      api('/api/admin/' + seg).then(function (r) { box.appendChild(pre(r.body)); });
    });
  }
  function renderSimple(title, path) {
    view.appendChild(el('h1', { text: title }));
    var box = el('div', { class: 'card' }); view.appendChild(box);
    api(path).then(function (r) { box.appendChild(pre(r.body)); });
  }
  function renderLogin() {
    view.appendChild(el('h1', { text: 'Sign in' }));
    var card = el('div', { class: 'card' });
    var email = el('input', { type: 'email', id: 'email', placeholder: 'role@atlas.test' });
    var pass = el('input', { type: 'password', id: 'password', placeholder: 'password' });
    var btn = el('button', { id: 'login-submit', text: 'Sign in' });
    var msg = el('div', { id: 'login-msg', class: 'whoami' });
    btn.addEventListener('click', function () {
      fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email.value, password: pass.value }) })
        .then(function (r) { return r.json().then(function (b) { return { status: r.status, body: b }; }); })
        .then(function (res) { if (res.status === 200) location.href = '/dashboard'; else msg.textContent = 'Invalid credentials'; })
        .catch(function () { msg.textContent = 'Login error'; });
    });
    [email, pass, btn, msg].forEach(function (n) { card.appendChild(n); });
    view.appendChild(card);
  }

  function render() {
    var path = location.pathname === '/' ? '/dashboard' : location.pathname;
    crumbs.textContent = path;
    view.innerHTML = '';
    var seg = path.split('/').filter(Boolean);
    if (path === '/dashboard') return renderDashboard();
    if (path === '/login') return renderLogin();
    if (path === '/directory') return renderSimple('Directory', '/api/directory');
    if (path === '/announcements') return renderSimple('Announcements', '/api/announcements');
    if (path === '/admin') return renderAdmin();
    if (seg[0] === 'reports' && seg[1]) return renderReports(seg[1]);
    if (depts.indexOf(seg[0]) > -1 && seg[1] && seg[2]) return renderDetail(seg[0], seg[1], seg.slice(2).join('/'));
    if (depts.indexOf(seg[0]) > -1 && seg[1]) return renderList(seg[0], seg[1]);
    view.appendChild(el('p', { text: 'Not found: ' + path }));
  }

  function cap(s) { return String(s).charAt(0).toUpperCase() + String(s).slice(1); }

  function startStreams() {
    try { var es = new EventSource('/api/notifications'); es.addEventListener('done', function () { try { es.close(); } catch (e) {} }); es.onerror = function () { try { es.close(); } catch (e) {} }; } catch (e) {}
    api('/api/internal/config').catch(function () {}); // background call to a mistakenly-exposed endpoint
  }

  api('/api/me').then(function (r) {
    me = r.status === 200 ? r.body : null;
    whoami.textContent = me ? me.name + ' · ' + me.role : 'anonymous';
    buildNav();
    if (!booted) { booted = true; startStreams(); }
    render();
  }).catch(function () { whoami.textContent = 'anonymous'; buildNav(); render(); });
})();
