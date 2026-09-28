# Acme Cloud — complex multi-tenant fixture

A deliberately-vulnerable, realistic **multi-tenant SaaS** used as the auditor's
end-to-end target. It is much richer than `test-app/`: multiple tenants, four
privilege tiers, nested resources, three id formats (numeric / UUID / slug),
pagination + search, Server-Sent Events and a WebSocket. **Not a real service —
never expose it publicly.**

```bash
PORT=4200 node server.js      # or: npm run test:app:enterprise
```

## Roles & sessions

Privilege tiers: `anonymous(0) < member(10) < manager(50) < org_admin(80) < super_admin(120)`

| Cookie `session=` | User | Role | Org (tenant) |
| --- | --- | --- | --- |
| `tok_alice` | Alice | member | Acme (1) |
| `tok_bob` | Bob | member | Acme (1) |
| `tok_mallory` | Mallory | member | **Globex (2)** |
| `tok_manager` | Mary | manager | Acme (1) |
| `tok_admin` | Adam | org_admin | Acme (1) |
| `tok_root` | Root | super_admin | Acme (1) |

## Access-control matrix

**Vulnerable — the auditor should flag these:**

| Id | Endpoint | Flaw |
| --- | --- | --- |
| H1 | `GET /api/users/:id` | IDOR — full PII (email/phone/salary) to any caller |
| H2 | `GET /api/orgs/:orgId/projects/:projectId` | Cross-tenant — no org-membership check |
| H3 | `GET /api/tickets/:ticketId` | IDOR — any user's private ticket |
| H4 | `GET /api/projects/:projectId/tasks/:taskId` | IDOR with **UUID** ids |
| H5 | `GET /api/documents/:slug` | IDOR with **slug** ids |
| V1 | `GET /api/admin/metrics` | Vertical — missing `super_admin` check |
| V2 | `GET /api/orgs/:orgId/invoices` | Vertical — billing without `org_admin` check |
| V3 | `GET /api/orgs/:orgId/export` | Function-level — any member exports all org data |
| E1 | `GET /api/admin/feature-flags` | Mistaken exposure — reachable anonymously; in no HTML link (background fetch) |

**Secure — the auditor should NOT flag these (true negatives):**

| Id | Endpoint | Control |
| --- | --- | --- |
| N1 | `GET /api/users/:id/secure` | self or same-org admin only (403 otherwise) |
| N2 | `GET /api/orgs/:orgId/billing/summary` | `org_admin` only |
| N3 | `GET /api/admin/orgs` | `super_admin` only |
| N4 | `GET /api/tickets/:ticketId/secure` | owner or `super_admin` only |
| — | `GET /api/me`, `/api/tickets`, `/api/notifications` | per-user content (differs, not a finding) |
| — | `GET /api/search` | public, identical for everyone |
| — | `POST /api/admin/orgs/:orgId/suspend` | mutating — never replayed by default |

**GraphQL** (`POST /graphql`, per-operation authorization):

| Operation | Behavior | Auditor should |
| --- | --- | --- |
| `query ticket(id)` | IDOR — any ticket | **flag horizontal** |
| `query secureTicket(id)` | owner/super-admin only | not flag (true negative) |
| `query adminMetrics` | no role check | **flag vertical** (and no-auth for anonymous) |
| `query me` | per-user | not flag |

**Form login** (`POST /api/login`, `/login` page) lets the login recorder script
authentication (`fill #email/#password`, click `#login-submit`) with the fixed
password `password`.

## SPA characteristics exercised

- Client-side **pushState router** with parameterized + nested routes.
- **Role-varying** navigation built in JavaScript (Invoices/Admin/Platform appear only for higher tiers).
- **Tabs** (project Overview/Tasks/Members) and a **modal** (task detail) that lazy-load via `fetch`.
- A **searchable + paginated** control issuing query-string XHR (`/api/search?q=…&page=…`).
- An **EventSource** notification stream and a **WebSocket** presence channel.
- A background request to `/api/admin/feature-flags`, referenced in no markup.

## Interpreting org-scoped findings (triage note)

Org-scoped resources (`/api/orgs/1/projects/…`) legitimately lack per-user
differentiation, so the auditor reports access from **same-org peers** as well as
the genuinely-dangerous **cross-tenant** case (e.g. Globex's Mallory reaching an
Acme resource). This is expected in black-box authorization testing: the endpoint
performs *no* membership check, and the tool surfaces every context that reached
it.

When users declare a `tenant` (as in `examples/enterprise.yaml`), these are
separated automatically via finding **tags**: `cross-tenant` stays high-severity,
`same-tenant-shared` (a peer reaching a tenant-scoped resource of their own
tenant) is downgraded to `info`, and `same-tenant` (a peer reaching another
user's *per-user* resource, e.g. a private ticket) stays a real finding. Filter
by tag to focus on the cross-tenant breaches. With `idor.enabled`, the active
enumeration analyzer additionally shows which endpoints let a user retrieve
records by guessing sequential ids (and correctly ignores the secured ones,
which deny some ids).

## Scan it

```bash
export ALICE=tok_alice BOB=tok_bob MALLORY=tok_mallory ADMIN=tok_admin ROOT=tok_root
node dist/cli.js scan --config examples/enterprise.yaml --output ./results
```
