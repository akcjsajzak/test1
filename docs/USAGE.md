# Usage

> **Authorized testing only.** Only run this against applications you own or are
> explicitly authorized to test. The scanner refuses to start unless the config
> sets `authorizedTesting: true`, and it never leaves the configured scope.

## Commands

```bash
web-auth-auditor scan     --config config.yaml --output ./results   # full audit
web-auth-auditor discover --config config.yaml --output ./results   # crawl + inventory only (no replay)
web-auth-auditor compare  --config config.yaml --output ./results   # full scan, findings-focused output
web-auth-auditor report   --input ./results/report.json --output .  # re-render HTML from a JSON report
```

(When running from source without a global install, use `node dist/cli.js …`.)

### Common options

| Option | Meaning |
| --- | --- |
| `-c, --config <path>` | YAML or JSON config (required). |
| `-o, --output <dir>` | Output directory (overrides `output.dir`). |
| `--log-level <level>` | `trace`\|`debug`\|`info`\|`warn`\|`error` (default `info`). |
| `--pretty` | Human-readable logs instead of NDJSON. |
| `--headful` | Show the browser window (needs a display / Xvfb). |
| `--fail-on <severity>` | Exit non-zero if any finding is at/above this severity (CI gate). |

## Typical workflow

1. **Obtain session material** for each role you want to test (see below) and
   export it as environment variables.
2. **Write a config** (start from `examples/config.example.yaml`).
3. **Discover first** (optional): `discover` crawls and inventories endpoints
   without any cross-context replay — useful to review coverage and scope before
   the active phase.
4. **Scan**: `scan` performs the safe cross-context replay and analysis, then
   writes `report.json` and `report.html`.
5. **Review** the HTML report. Every finding is an *observation to validate*,
   not a confirmed exploit — read the evidence and the request/response
   snapshots.

## Obtaining session cookies

Log in as each role in a normal browser and copy the session cookie value
(DevTools → Application → Cookies), then inject it via an environment variable so
it never lands in the config file:

```bash
export USER_A_SESSION="<cookie value for a normal user>"
export USER_B_SESSION="<cookie value for a different normal user>"
export ADMIN_SESSION="<cookie value for an admin>"
web-auth-auditor scan --config config.yaml --output ./results
```

The config references these as `${USER_A_SESSION}` etc. Extra HTTP headers
(e.g. a bearer token in `Authorization`) are supported per user the same way.

## Proxy usage and limitations

Configure a proxy under `proxy:` to route browser traffic through an intercepting
tool (Burp, mitmproxy) or a forwarder:

```yaml
proxy:
  type: "http"          # http | https | socks5 | socks4
  url: "http://127.0.0.1:8080"
```

Documented limitations (Chromium/CDP):

- **HTTP/HTTPS** proxies are fully supported for browser traffic. TLS
  interception works because the engine sets `ignoreHTTPSErrors`.
- **SOCKS5**: Chromium routes TCP through the proxy but **does not support SOCKS
  proxy authentication**, and by default performs **DNS resolution locally**
  rather than over the proxy. If DNS must egress through the proxy, chain through
  a local resolver/forwarder.
- The in-process replay engine issues requests through each user's *browser
  context*, so it inherits the same proxy and cookie jar as the crawl.

## Interpreting findings

- **AUTHZ-HORIZONTAL** — a user reached a resource (by concrete id) that was
  discovered in another *same-privilege* user's context. `high` confidence means
  the shared resource identifier was echoed back to the test user.
- **AUTHZ-VERTICAL** — a lower-privilege (or anonymous) context was served a
  capability observed in a higher-privilege context, with no denial. `high` when
  the path is clearly privileged (`/admin`, `/internal`, …) or the tester is
  anonymous.
- **AUTHZ-IDOR-ENUM** *(opt-in via `idor.enabled`)* — the observing user could
  retrieve records it was never linked to by guessing sequential numeric ids;
  the endpoint enforces no per-object authorization.

**Tenant-awareness.** When users declare a `tenant`, findings are tagged for
triage: `cross-tenant` (one tenant reached another's resource — high signal),
`same-tenant-shared` (a peer reached a tenant-scoped resource of their own
tenant — downgraded to `info` as likely-legitimate sharing), and `same-tenant`
(a peer reached another user's *per-user* resource — still a real finding).
Filter the report by tag to separate genuine cross-tenant breaches from expected
intra-tenant sharing.

Findings are sorted most-severe first, with graded confidence (`info`/`low`/
`medium`/`high`). Denials, login redirects, per-user content differences and
dynamic fields (CSRF tokens, timestamps, request ids) are treated as
non-findings to keep false positives low.

## Reducing load

The tool favors reproducible observations over request volume. Tune budgets in
`crawl:` and `scope:` (`maxPages`, `maxActions`, `maxRequests`,
`maxDurationSeconds`, `requestsPerSecond`) to bound impact on the target.
