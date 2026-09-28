# Configuration reference

Config is YAML or JSON, validated with Zod. Unknown-but-valid fields get sensible
defaults; invalid configs fail fast with a precise error. Secrets should be
referenced as `${ENV_VAR}` (or `${ENV_VAR:-default}`) and injected at runtime.

## Top level

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `authorizedTesting` | bool | `false` | **Must be `true`** or the scan refuses to run. |
| `target.url` | url | — | Required. Starting URL; its host is always in scope. |
| `users[]` | list | — | Required, ≥1. Authenticated (or anonymous) contexts. |
| `proxy` | object | — | Optional browser proxy. |
| `scope` | object | see below | Safety boundary and budgets. |
| `crawl` | object | see below | Exploration budgets and behavior. |
| `replay` | object | see below | Cross-context replay policy. |
| `compare` | object | see below | Dynamic fields/headers to ignore. |
| `browser` | object | see below | Chromium launch settings. |
| `output` | object | see below | Report directory and formats. |

## `users[]`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | — | Logical id (`user_a`, `admin`, …). |
| `role` | string | — | Reporting label; also used to infer privilege. |
| `privilegeLevel` | int ≥0 | inferred | Higher = more privileged. `anonymous`=0. Drives vertical analysis. |
| `cookies[]` | list | `[]` | `{ name, value, domain?, path?, httpOnly?, secure?, sameSite? }`. |
| `headers[]` | list | `[]` | `{ name, value }` extra HTTP headers (e.g. `Authorization`). |
| `localStorage[]` | list | `[]` | `{ name, value }` seeded into the isolated context. |

Privilege inference (when `privilegeLevel` is omitted): `anonymous/guest`=0,
`user/member`=10, `editor`=30, `manager/staff/moderator`=50, `admin`=100,
`superadmin/root`=120; a context named `anon*` is treated as 0.

## `scope`

| Field | Default | Notes |
| --- | --- | --- |
| `allowedDomains` | `[]` | Extra in-scope hosts (target host is always allowed). |
| `allowSubdomains` | `true` | Allow subdomains of allowed hosts. |
| `deniedDomains` | `[]` | Never navigated/replayed (wins over allow). |
| `deniedIpRanges` | RFC1918 + loopback + link-local | Discovered hosts in these ranges are blocked. |
| `excludeHosts` | analytics/telemetry hosts | Excluded from **analysis** (still allowed to load). |
| `excludeUrlPatterns` | `/analytics`,`/telemetry`,`/collect`,`/beacon` | Path substrings excluded from analysis. |
| `maxRequests` | `2000` | Global request budget. |
| `maxDurationSeconds` | `600` | Global time budget. |
| `requestsPerSecond` | `8` | Soft rate limit for crawl + replay. |

## `crawl`

| Field | Default | Notes |
| --- | --- | --- |
| `maxDepth` | `3` | Navigation depth from the seed. |
| `maxPages` | `60` | Max distinct pages/routes visited. |
| `maxActions` | `400` | Max interactions triggered. |
| `maxRequests` | `1500` | Stop crawling after this many observed requests. |
| `maxDurationSeconds` | `300` | Per-crawl time budget. |
| `interact` | `true` | Trigger safe interactive elements. |
| `submitForms` | `false` | Forms can mutate state; off by default. |
| `includeDestructive` | `false` | Never auto-trigger destructive actions even if `true` (only enables `confirm`-class). |
| `settleMs` | `400` | Wait after each action for async work. |

## `replay`

| Field | Default | Notes |
| --- | --- | --- |
| `enabled` | `true` | Master switch for cross-context replay. |
| `allowedMethods` | `[GET, HEAD, OPTIONS]` | Only these are replayed… |
| `allowDestructive` | `false` | …and mutating methods need this opt-in too. |
| `maxReplays` | `500` | Replay budget. |

## `compare`

| Field | Default | Notes |
| --- | --- | --- |
| `ignoreFields` | csrf/token/timestamp/nonce/requestId/… | JSON keys ignored when diffing. |
| `ignoreHeaders` | date/set-cookie/etag/x-request-id/… | Response headers ignored when diffing. |

## `browser`

| Field | Default | Notes |
| --- | --- | --- |
| `headless` | `true` | `--headful` CLI flag overrides. |
| `executablePath` | auto-detected | Path to Chromium. |
| `extraArgs` | `[]` | Extra Chromium args. |
| `navigationTimeoutMs` | `20000` | Per-navigation timeout. |
| `userAgent` | — | Optional UA override. |

## `output`

| Field | Default | Notes |
| --- | --- | --- |
| `dir` | `./results` | Report directory (CLI `--output` overrides). |
| `formats` | `[json, html]` | Any of `json`, `html`. |

See `examples/config.example.yaml` for a fully-commented template and
`examples/localhost.yaml` for a ready-to-run config against the test app.
