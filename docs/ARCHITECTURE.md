# Architecture

The auditor is a modular pipeline. Each stage depends on data shapes
(`src/core/types.ts`), not on sibling engines, so stages can be tested in
isolation and new detection engines can be added without touching the core.

```
                ┌─────────────────┐
                │       CLI       │  src/cli.ts
                └────────┬────────┘
                ┌────────▼────────┐
                │ Scan Orchestrator│  src/orchestrator/scan.ts
                └────────┬────────┘
        ┌───────────────┼──────────────────┐
   ┌────▼─────┐   ┌──────▼──────┐    ┌──────▼──────┐
   │ Browser  │   │  Network    │    │   Scope     │
   │ Engine   │   │  Collector  │    │   Guard     │
   │(isolated │   │   (CDP)     │    │ (safety)    │
   │ contexts)│   └──────┬──────┘    └─────────────┘
   └────┬─────┘          │
        │        ┌───────▼────────┐
        └───────▶│  Crawler /     │  src/crawler/*
                 │  Explorer      │──▶ Discovery Graph  src/graph/model.ts
                 └───────┬────────┘
                 ┌───────▼────────┐
                 │  Normalizer    │  src/analysis/normalize.ts
                 └───────┬────────┘
                 ┌───────▼────────┐
                 │  Inventory     │  src/analysis/inventory.ts
                 └───────┬────────┘
                 ┌───────▼────────┐   ┌───────────────┐
                 │  AuthZ Engine  │──▶│ Replay Engine │  src/analysis/replay.ts
                 │  (analyzers)   │◀──│  + Comparator │  src/analysis/compare.ts
                 └───────┬────────┘   └───────────────┘
                 ┌───────▼────────┐
                 │   Reporter     │  src/report/*  (JSON + HTML)
                 └────────────────┘
```

## Data flow

1. **Orchestrator** validates the config, enforces the authorized-testing gate,
   and builds a `ScopeGuard` and a shared `RequestLog`.
2. **Browser Engine** launches Chromium and mints one isolated `BrowserContext`
   per user (`UserSession`). Isolation covers cookies, `localStorage`,
   `sessionStorage` and cache.
3. **Network Collector** attaches to each page's CDP session and records every
   request/response (navigations, XHR, `fetch`, redirects, WebSocket,
   EventSource) with method, URL, initiator, resource type, timing and size —
   redacting secrets before anything is stored.
4. **Crawler** drives each session within budgets, discovering routes from many
   sources (anchors, DOM URL attributes, form actions, `history.pushState`, and
   the network) and triggering only *safe* interactions. It records a
   **Discovery Graph** so every observation is explainable.
5. **Normalizer** turns concrete URLs into signatures (`/api/users/{id}`) using
   rule-based templating plus a stateful pass that only collapses
   identifier-like segments (REST collection names are preserved).
6. **Inventory** groups normalized requests per user.
7. **AuthZ Engine** runs the registered analyzers. Each uses the **Replay
   Engine** (safe-by-default, secret-free, scoped) and the **Comparator**
   (content-type-aware, dynamic-field-ignoring, denial-detecting) to decide
   findings with graded confidence.
8. **Reporter** emits `report.json` (machine-readable) and `report.html`
   (human-readable), each finding carrying evidence and redacted request/response
   snapshots.

## Key data structures (`src/core/types.ts`)

- `ObservedRequest` — a captured request/response with redacted headers/params/
  body, initiator, source route and (after normalization) a `NormalizedRequest`.
- `NavigationGraph` (`GraphNode` + `GraphEdge`) — states and the actions/events
  between them; edges carry the ids of requests they produced.
- `EndpointObservation` / `UserInventory` — per-user endpoint groupings.
- `ResponseDiff` — a structured, explainable comparison verdict + similarity.
- `Finding` — the reported detection, with evidence, diff and response
  snapshots.
- `ReplayResult` — the outcome (or skip reason) of a controlled replay.

## Extensibility: adding a detection engine

Implement `Analyzer` and register it:

```ts
import type { Analyzer, AnalysisContext } from 'web-auth-auditor';

export class MyAnalyzer implements Analyzer {
  id = 'MY-CHECK';
  title = 'My custom check';
  async analyze(ctx: AnalysisContext) {
    // ctx.inventory, ctx.requestsById, ctx.graphs, ctx.replayer, ctx.scope …
    return []; // Finding[]
  }
}
```

Pass it via `runScan({ …, extraAnalyzers: new AnalyzerRegistry().register(new MyAnalyzer()) })`,
or register it directly in the orchestrator. Analyzers get everything they need
from the `AnalysisContext` and never touch the browser layer, so they are pure,
fast and unit-testable.

## Why TypeScript + Playwright/CDP

- **CDP** gives the highest-fidelity view of application behavior (native
  initiator, resource type, sizes, WebSocket/EventSource frames), which is the
  top priority for reliable observation.
- **Playwright `BrowserContext`** provides hard, first-class user isolation.
- **TypeScript** gives a strongly-typed data model shared across stages and a
  reproducible build/install on Debian.

## Safety model

- Default-deny scope; the target host and explicit allow-list are the only
  navigable/replayable hosts. Private IP ranges are denied for discovered hosts.
- Replay is safe-methods-only by default; mutating methods require an explicit
  opt-in and are otherwise skipped.
- The source user's secrets are never forwarded during replay — each replay uses
  the target user's own session.
- Request/time budgets and a soft rate limiter bound load; interactions never
  auto-trigger destructive actions (including logout).
