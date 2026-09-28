# web-auth-auditor

An **authorized** authorization / access-control auditor for web applications.

It drives Chromium through the Chrome DevTools Protocol to observe an application
exactly as a browser sees it — including SPA navigation and dynamic `fetch`/XHR
calls that never appear in the HTML — builds a per-user inventory of endpoints,
then **carefully** replays safe requests across user contexts to detect broken
**horizontal** (user A ↔ user B) and **vertical** (low ↔ high privilege) access
controls.

> ⚠️ **Authorized testing only.** This tool is intended solely for applications
> you own or have explicit written permission to test. It refuses to run unless
> the config sets `authorizedTesting: true`, and it stays strictly within the
> configured scope. See [docs/USAGE.md](docs/USAGE.md).

## Why these technologies

| Concern | Choice | Rationale |
| --- | --- | --- |
| Observation fidelity | **Chromium via CDP** (`playwright-core`) | CDP exposes the request *initiator*, resource type, precise sizes/timing, WebSocket/EventSource frames and redirects natively — the highest-fidelity view of what the app actually does. |
| User isolation | **One Playwright `BrowserContext` per user** | Hard isolation of cookies, `localStorage`, `sessionStorage` and cache — one session can never contaminate another. |
| Language | **TypeScript / Node 20+** | First-class CDP ecosystem, strong typing for the data model, easy reproducible install on Debian. |
| Config validation | **Zod** | Fail-fast, well-explained config errors; secrets injected from env vars. |
| Extensibility | **Analyzer registry** | New detection engines implement one interface and register — no core changes. |

## Quick start (Debian)

```bash
# Prerequisites: Node.js 20+ and a Chromium build.
npm install
npm run build

# Run a scan (see examples/config.example.yaml)
export USER_A_SESSION=... USER_B_SESSION=... ADMIN_SESSION=...
node dist/cli.js scan --config examples/config.example.yaml --output ./results
```

Full instructions: [docs/INSTALL-debian.md](docs/INSTALL-debian.md) ·
[docs/USAGE.md](docs/USAGE.md) · [docs/CONFIG.md](docs/CONFIG.md) ·
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · [test-app/](test-app/README.md).

## Architecture (overview)

```
CLI ─▶ Scan Orchestrator ─▶ Browser Engine (isolated contexts) ─▶ Network Collector (CDP)
                         └▶ Crawler/Explorer ─▶ Discovery Graph
                         └▶ Inventory ─▶ Normalizer ─▶ Replay ─▶ Comparator ─▶ AuthZ Analyzers ─▶ Reporter
```

## Test fixtures

Two deliberately-vulnerable apps back the automated tests:

- [`test-app/`](test-app/README.md) — a compact SPA covering the core horizontal,
  vertical and mistaken-exposure cases.
- [`test-app-enterprise/`](test-app-enterprise/README.md) — **Acme Cloud**, a
  realistic multi-tenant SaaS (4 privilege tiers, nested resources, numeric/UUID/
  slug ids, pagination, SSE and WebSocket) with a full matrix of broken and
  correct access controls. The end-to-end test scans it and asserts every planted
  issue is found and every secured endpoint is not.

```bash
npm test          # unit + integration + both end-to-end scans
```

## License

MIT. Provided for lawful, authorized security testing only.
