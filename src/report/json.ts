/**
 * Machine-readable JSON reporter.
 *
 * Emits a single self-describing document: scan metadata and stats, the config
 * echo (secrets stripped), the per-user endpoint inventory, the navigation
 * graphs, and the full findings (each with its evidence, diff and redacted
 * request/response snapshots).
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { ReportBundle } from './bundle';
import { sortFindings } from './bundle';

export function buildJsonReport(bundle: ReportBundle): Record<string, unknown> {
  return {
    tool: 'web-auth-auditor',
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    scan: {
      target: bundle.scan.target,
      startedAt: new Date(bundle.scan.startedAt).toISOString(),
      finishedAt: new Date(bundle.scan.finishedAt).toISOString(),
      durationMs: bundle.scan.finishedAt - bundle.scan.startedAt,
      users: bundle.scan.users,
      stats: bundle.scan.stats,
    },
    config: bundle.configEcho,
    inventory: bundle.inventory,
    findings: sortFindings(bundle.scan.findings),
    graphs: bundle.graphs.map((g) => ({
      user: g.user,
      nodes: g.nodes.length,
      edges: g.edges.length,
      detail: g,
    })),
  };
}

export function writeJsonReport(outputDir: string, bundle: ReportBundle): string {
  const path = join(outputDir, 'report.json');
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(buildJsonReport(bundle), null, 2), 'utf8');
  return path;
}
