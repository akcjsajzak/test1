# Atlas ERP — 5×5 role-matrix fixture

The largest and most complex fixture: a classic business-operations suite with a
**two-dimensional role matrix** — 5 departments × 5 authority levels = **25 roles**
plus a **global admin** (26 total). Departments segregate which resource *types* a
user may touch; authority levels gate *sensitive* resources and approvals within a
department. Cross-department access is admin-only.

The point is a *complicated* authorization matrix whose enforcement is correct in
most places and wrong in a few, so a scanner's precision and recall are both
measured at scale. **Not a real service — never expose it publicly.**

```bash
PORT=4300 node server.js      # or: npm run test:app:atlas
```

## The matrix

| | viewer (1) | contributor (2) | approver (3) | manager (4) | director (5) |
| --- | --- | --- | --- | --- | --- |
| **sales** | `tok_sales_viewer` | `tok_sales_contributor` | … | … | `tok_sales_director` |
| **procurement** | `tok_procurement_viewer` | … | `tok_procurement_approver` | … | … |
| **finance** | `tok_finance_viewer` | … | … | … | `tok_finance_director` |
| **hr** | `tok_hr_viewer` | … | … | `tok_hr_manager` | … |
| **it** | `tok_it_viewer` | … | … | … | … |

…and `tok_admin` (global). Every cell has a token `tok_<dept>_<level>`. Session
cookie = one of these tokens. Login form: `<role>@atlas.test` / `password`.

**Policy engine** (`enforce()`): `SECURE_DEPT` (same department), `SECURE_LEVEL`
(same department AND level ≥ min), `VULN_NONE` (no check → cross-department leak),
`VULN_LEVEL` (department checked but level check omitted).

## Broken cells — the auditor should flag these

| Endpoint | Flaw | Detected as |
| --- | --- | --- |
| `GET /api/finance/invoices` | `VULN_NONE` — cross-department leak | horizontal (cross-tenant) / vertical |
| `GET /api/sales/deals/:id` | `VULN_NONE` — cross-department IDOR | horizontal |
| `GET /api/finance/budgets` | `VULN_LEVEL` — director-only, level not enforced | vertical (within department) |
| `GET /api/finance/expenses/:id` | list returns own, detail leaks any | **enumeration** IDOR |
| `GET /api/admin/audit-log` | missing admin check | vertical (to admin) |
| `GET /api/reports/finance/summary` | cross-department report leak | vertical |
| `GET /api/internal/config` | no authentication (background fetch) | **auth-state** |
| GraphQL `deal(id)` | cross-department IDOR | horizontal |
| GraphQL `financials` | director-only leak | vertical / auth-state |

## Correctly-enforced cells — the auditor should NOT flag these

`GET /api/finance/payments`, `/api/sales/customers`, `/api/procurement/vendors`,
`/api/it/incidents`, `/api/it/assets` (all `SECURE_DEPT`), `/api/hr/employees`
(`SECURE_DEPT`), `/api/hr/payroll` (`SECURE_LEVEL`, manager+), `/api/admin/users`
and `/api/admin/roles` (admin only), `/api/reports/hr/summary` (dept-enforced),
and GraphQL `secureEmployee(id)`.

## SPA characteristics

- Department/level-aware navigation built in JS: each user sees only their own
  department's modules (admin sees all); **sensitive modules are hidden below
  their level** (finance *budgets* = director-only; hr *payroll* = manager+), so a
  lower-level user's crawl never surfaces them and the auditor's cross-context
  replay is a genuine "capability you were never shown" test.
- Generic list/detail routing, reports, company directory/announcements, an admin
  console, a login form, GraphQL calls and an SSE stream.

See `examples/atlas.yaml` for a representative 9-user scan config (and how to
expand it to the full 25-role matrix).
