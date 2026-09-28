/* Acme Cloud SPA — a deliberately-rich single-page app for end-to-end testing.
 *
 * Exercises: a client-side pushState router with parameterized + nested routes,
 * role-varying navigation built in JS, tabs and a modal that lazy-load via fetch,
 * a searchable + paginated table (query-string XHR), an EventSource stream, a
 * WebSocket, dynamically-generated links, and a background request to an endpoint
 * that appears in no markup. Each route fetches its own data so the crawler
 * observes the full API surface per user context.
 */
(function () {
  'use strict';

  var view = document.getElementById('view');
  var nav = document.getElementById('nav');
  var whoami = document.getElementById('whoami');
  var crumbs = document.getElementById('crumbs');
  var presence = document.getElementById('presence');
  var modal = document.getElementById('modal');
  var modalBody = document.getElementById('modal-body');
  var me = null;
  var booted = false;

  // ── tiny DOM helper ─────────────────────────────────────────────────────────
  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      if (k === 'text') n.textContent = attrs[k];
      else if (k === 'html') n.innerHTML = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }
  function link(path, label, cls) {
    var a = el('a', { href: path, 'data-link': path, text: label });
    if (cls) a.className = cls;
    a.addEventListener('click', function (e) { e.preventDefault(); navigate(path); });
    return a;
  }
  function pre(obj) { return el('pre', { text: typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2) }); }

  function api(path) {
    return fetch(path, { headers: { 'X-Requested-With': 'fetch', Accept: 'application/json' } }).then(function (r) {
      return r.json().then(function (b) { return { status: r.status, body: b }; }).catch(function () { return { status: r.status, body: null }; });
    });
  }

  // ── routing ─────────────────────────────────────────────────────────────────
  var routes = [
    ['/dashboard', renderDashboard],
    ['/projects', renderProjects],
    ['/projects/:id', renderProjectDetail],
    ['/tickets', renderTickets],
    ['/tickets/:id', renderTicketDetail],
    ['/users/:id', renderUserProfile],
    ['/documents/:slug', renderDocument],
    ['/invoices', renderInvoices],
    ['/admin', renderAdmin],
    ['/admin/metrics', renderPlatform],
    ['/search', renderSearch],
    ['/settings', renderSettings],
  ];
  function match(path) {
    for (var i = 0; i < routes.length; i++) {
      var pat = routes[i][0].split('/'), seg = path.split('/');
      if (pat.length !== seg.length) continue;
      var params = {}, ok = true;
      for (var j = 0; j < pat.length; j++) {
        if (pat[j].charAt(0) === ':') params[pat[j].slice(1)] = decodeURIComponent(seg[j]);
        else if (pat[j] !== seg[j]) { ok = false; break; }
      }
      if (ok) return { handler: routes[i][1], params: params };
    }
    return null;
  }
  function navigate(path) { history.pushState({}, '', path); render(); }
  window.addEventListener('popstate', render);

  function render() {
    var path = location.pathname === '/' ? '/dashboard' : location.pathname;
    crumbs.textContent = path;
    var m = match(path);
    view.innerHTML = '';
    if (!m) { view.appendChild(el('p', { text: 'Not found: ' + path })); return; }
    m.handler(m.params);
  }

  // ── navigation (role-aware) ──────────────────────────────────────────────────
  function orgDocSlug() { return me && me.orgId === 2 ? 'globex-roadmap-3310' : 'q3-financials-8842'; }
  function buildNav() {
    nav.innerHTML = '';
    var items = [
      ['/dashboard', 'Dashboard'], ['/projects', 'Projects'], ['/tickets', 'Tickets'],
      ['/search', 'Search'], ['/users/' + (me ? me.id : 0), 'My Profile'],
      ['/documents/' + orgDocSlug(), 'Docs'],
    ];
    if (me && me.level >= 80) { items.push(['/invoices', 'Invoices']); items.push(['/admin', 'Admin']); }
    if (me && me.level >= 120) { items.push(['/admin/metrics', 'Platform']); }
    items.forEach(function (it) { nav.appendChild(link(it[0], it[1], 'nav-item')); });
  }

  // ── views ─────────────────────────────────────────────────────────────────
  function renderDashboard() {
    view.appendChild(el('h1', { text: 'Dashboard' }));
    api('/api/me').then(function (r) {
      view.appendChild(el('div', { class: 'card' }, [pre(r.body)]));
    });
    var quick = el('div', { class: 'quick' }, [
      link('/projects', 'Open projects →', 'chip'),
      link('/tickets', 'My tickets →', 'chip'),
      link('/users/' + (me ? me.id : 0), 'My profile →', 'chip'),
      link('/documents/' + orgDocSlug(), 'Org document →', 'chip'),
    ]);
    view.appendChild(quick);
  }

  function renderProjects() {
    view.appendChild(el('h1', { text: 'Projects' }));
    var searchRow = el('div', { class: 'searchbar' });
    var input = el('input', { type: 'search', placeholder: 'Search catalog…', 'data-search': '1' });
    input.addEventListener('input', debounce(function () { api('/api/search?q=' + encodeURIComponent(input.value) + '&page=1'); }, 250));
    var next = el('button', { text: 'Next page' });
    next.addEventListener('click', function () { api('/api/search?q=' + encodeURIComponent(input.value) + '&page=2'); });
    searchRow.appendChild(input); searchRow.appendChild(next);
    view.appendChild(searchRow);

    var list = el('ul', { class: 'list', id: 'project-list' });
    view.appendChild(list);
    api('/api/orgs/' + (me ? me.orgId : 1) + '/projects').then(function (r) {
      var projects = (r.body && r.body.projects) || [];
      projects.forEach(function (p) {
        list.appendChild(el('li', {}, [link('/projects/' + p.id, p.name + ' (#' + p.id + ')')]));
      });
      // Background: observe concrete nested resources without navigating.
      if (projects[0]) {
        var pid = projects[0].id;
        api('/api/orgs/' + (me ? me.orgId : 1) + '/projects/' + pid);
        api('/api/projects/' + pid + '/tasks').then(function (tr) {
          var tasks = (tr.body && tr.body.tasks) || [];
          if (tasks[0]) api('/api/projects/' + pid + '/tasks/' + tasks[0].id);
        });
      }
    });
  }

  function renderProjectDetail(params) {
    view.appendChild(el('h1', { text: 'Project #' + params.id }));
    var tabs = el('div', { class: 'tabs' });
    ['overview', 'tasks', 'members'].forEach(function (name) {
      var b = el('button', { class: 'tab', role: 'tab', text: name[0].toUpperCase() + name.slice(1) });
      b.addEventListener('click', function () { showTab(name); });
      tabs.appendChild(b);
    });
    view.appendChild(tabs);
    var panel = el('div', { class: 'panel', id: 'panel' });
    view.appendChild(panel);

    function showTab(name) {
      panel.innerHTML = 'Loading ' + name + '…';
      if (name === 'overview') {
        api('/api/orgs/' + (me ? me.orgId : 1) + '/projects/' + params.id).then(function (r) { panel.innerHTML = ''; panel.appendChild(pre(r.body)); });
      } else if (name === 'tasks') {
        api('/api/projects/' + params.id + '/tasks').then(function (r) {
          panel.innerHTML = '';
          var tasks = (r.body && r.body.tasks) || [];
          var ul = el('ul', { class: 'list' });
          tasks.forEach(function (t) {
            var openBtn = el('a', { href: '#', 'data-task': t.id, text: t.title });
            openBtn.addEventListener('click', function (e) { e.preventDefault(); openTaskModal(params.id, t.id); });
            ul.appendChild(el('li', {}, [openBtn]));
          });
          panel.appendChild(ul);
        });
      } else {
        panel.innerHTML = '<em>Members tab (static)</em>';
      }
    }
    showTab('overview');
  }

  function openTaskModal(projectId, taskId) {
    modal.classList.remove('hidden');
    modalBody.innerHTML = 'Loading task…';
    api('/api/projects/' + projectId + '/tasks/' + taskId).then(function (r) { modalBody.innerHTML = ''; modalBody.appendChild(pre(r.body)); });
  }

  function renderTickets() {
    view.appendChild(el('h1', { text: 'My Tickets' }));
    var list = el('ul', { class: 'list', id: 'ticket-list' });
    view.appendChild(list);
    api('/api/tickets').then(function (r) {
      var tickets = (r.body && r.body.tickets) || [];
      tickets.forEach(function (t) { list.appendChild(el('li', {}, [link('/tickets/' + t.id, t.subject)])); });
      if (tickets[0]) { api('/api/tickets/' + tickets[0].id); api('/api/tickets/' + tickets[0].id + '/secure'); }
    });
  }

  function renderTicketDetail(params) {
    view.appendChild(el('h1', { text: 'Ticket #' + params.id }));
    var box = el('div', { class: 'card' }); view.appendChild(box);
    api('/api/tickets/' + params.id).then(function (r) { box.appendChild(pre(r.body)); });
    api('/api/tickets/' + params.id + '/secure');
  }

  function renderUserProfile(params) {
    view.appendChild(el('h1', { text: 'User #' + params.id }));
    var box = el('div', { class: 'card' }); view.appendChild(box);
    api('/api/users/' + params.id).then(function (r) { box.appendChild(pre(r.body)); });
    api('/api/users/' + params.id + '/secure');
  }

  function renderDocument(params) {
    view.appendChild(el('h1', { text: 'Document: ' + params.slug }));
    var box = el('div', { class: 'card' }); view.appendChild(box);
    api('/api/documents/' + params.slug).then(function (r) { box.appendChild(pre(r.body)); });
  }

  function renderInvoices() {
    view.appendChild(el('h1', { text: 'Invoices' }));
    var a = el('div', { class: 'card' }), b = el('div', { class: 'card' });
    view.appendChild(a); view.appendChild(b);
    api('/api/orgs/' + (me ? me.orgId : 1) + '/invoices').then(function (r) { a.appendChild(el('h3', { text: 'Invoices' })); a.appendChild(pre(r.body)); });
    api('/api/orgs/' + (me ? me.orgId : 1) + '/billing/summary').then(function (r) { b.appendChild(el('h3', { text: 'Billing summary (secured)' })); b.appendChild(pre(r.body)); });
  }

  function renderAdmin() {
    view.appendChild(el('h1', { text: 'Org Admin' }));
    var box = el('div', { class: 'card' }); view.appendChild(box);
    var btn = el('button', { text: 'Export org data' });
    btn.addEventListener('click', function () { api('/api/orgs/' + (me ? me.orgId : 1) + '/export?format=json').then(function (r) { box.appendChild(pre(r.body)); }); });
    view.appendChild(btn);
    // Also fetch on render so the capability is observed deterministically.
    api('/api/orgs/' + (me ? me.orgId : 1) + '/export?format=json').then(function (r) { box.appendChild(pre(r.body)); });
  }

  function renderPlatform() {
    view.appendChild(el('h1', { text: 'Platform (super-admin)' }));
    var a = el('div', { class: 'card' }), b = el('div', { class: 'card' });
    view.appendChild(a); view.appendChild(b);
    api('/api/admin/metrics').then(function (r) { a.appendChild(el('h3', { text: 'Metrics' })); a.appendChild(pre(r.body)); });
    api('/api/admin/orgs').then(function (r) { b.appendChild(el('h3', { text: 'Orgs (secured)' })); b.appendChild(pre(r.body)); });
  }

  function renderSearch() {
    view.appendChild(el('h1', { text: 'Search' }));
    var input = el('input', { type: 'search', placeholder: 'Query…' });
    var out = el('div', { class: 'card' });
    input.addEventListener('input', debounce(function () {
      api('/api/search?q=' + encodeURIComponent(input.value) + '&page=1').then(function (r) { out.innerHTML = ''; out.appendChild(pre(r.body)); });
    }, 250));
    view.appendChild(input); view.appendChild(out);
    api('/api/search?q=&page=1').then(function (r) { out.appendChild(pre(r.body)); });
  }

  function renderSettings() {
    view.appendChild(el('h1', { text: 'Settings' }));
    view.appendChild(el('p', { text: 'Static settings page.' }));
  }

  // ── background streams / one-time boot side effects ─────────────────────────
  function startStreams() {
    try {
      var es = new EventSource('/api/notifications');
      es.addEventListener('done', function () { try { es.close(); } catch (e) {} });
      es.onerror = function () { try { es.close(); } catch (e) {} };
    } catch (e) { /* SSE unsupported */ }
    try {
      var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      var ws = new WebSocket(proto + '//' + location.host + '/ws/presence');
      ws.onmessage = function (ev) { try { presence.textContent = 'presence: ' + JSON.parse(ev.data).online + ' online'; } catch (e) {} };
      ws.onerror = function () { presence.textContent = 'presence: offline'; };
    } catch (e) { /* WS unsupported */ }
    // Background call to a mistakenly-exposed endpoint referenced in no markup.
    api('/api/admin/feature-flags').catch(function () {});
  }

  // ── modal close ─────────────────────────────────────────────────────────────
  document.getElementById('modal-close').addEventListener('click', function () { modal.classList.add('hidden'); });

  function debounce(fn, ms) { var t; return function () { clearTimeout(t); t = setTimeout(fn, ms); }; }

  // ── boot ────────────────────────────────────────────────────────────────────
  api('/api/me').then(function (r) {
    me = r.status === 200 ? r.body : null;
    whoami.textContent = me ? me.name + ' · ' + me.role : 'anonymous';
    buildNav();
    if (!booted) { booted = true; startStreams(); }
    render();
  }).catch(function () { whoami.textContent = 'anonymous'; buildNav(); render(); });
})();
