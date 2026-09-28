# Vulnerable test application (fixture)

A deliberately-insecure SPA + JSON API used to exercise the auditor's automated
tests. **It is not a real service and must never be exposed publicly.**

```bash
PORT=4123 node server.js      # or: npm run test:app
```

## Sessions

The session cookie maps to a fixed user:

| Cookie `session=` | User | Role | Owns order |
| --- | --- | --- | --- |
| `token_user_a` | Alice | user | 4815 |
| `token_user_b` | Bob | user | 1623 |
| `token_admin` | Carol | admin | 2342 |
| _(none)_ | anonymous | — | — |

## Deliberate cases

| Endpoint | Intended behavior | Auditor should |
| --- | --- | --- |
| `GET /api/orders/:id` | **IDOR** — returns any order, no owner check | **flag horizontal** |
| `GET /api/secure/orders/:id` | Ownership enforced (403 otherwise) | not flag (true negative) |
| `GET /api/admin/stats` | **Broken vertical** — no role check | **flag vertical** |
| `GET /api/admin/users` | Role enforced (403 otherwise) | not flag (true negative) |
| `POST /api/admin/users/:id/disable` | Admin-only mutation | not replay by default |
| `GET /api/internal/debug` | **Mistaken exposure** — reachable by anyone; referenced in no HTML link | **flag vertical**, discovered via network only |
| `GET /api/me`, `GET /api/orders` | Per-user content | not flag (different content) |
| `GET /api/products` | Public catalogue | not flag |

## SPA characteristics exercised

- Navigation menu built dynamically in JavaScript (not in the initial HTML).
- Client-side routing via `history.pushState`.
- Data loaded via `fetch()` (XHR-style), including a **background** call to
  `/api/internal/debug` that appears in no link or DOM text.
- Order-detail links generated dynamically with `createElement`.
- The admin route/link only rendered for admins — so lower-privilege contexts
  never "see" it in the UI, which is exactly the setup for vertical testing.

Per-request `csrfToken` and `ts` fields are included to verify the comparator
ignores dynamic values rather than flagging every response as different.
