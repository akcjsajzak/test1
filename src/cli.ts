#!/usr/bin/env node
/**
 * web-auth-auditor command-line interface.
 *
 *   web-auth-auditor scan     --config config.yaml --output ./results
 *   web-auth-auditor discover --config config.yaml --output ./results   (crawl + inventory, no replay)
 *   web-auth-auditor compare  --config config.yaml --output ./results   (scan, focused on findings)
 *   web-auth-auditor report   --input ./results/report.json --output ./results  (re-render HTML)
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { Command } from 'commander';
import { createLogger } from './core/logger';
import { loadConfig, ConfigError } from './config/loader';
import { runScan, AuthorizationError } from './orchestrator/scan';
import { recordLogins } from './orchestrator/record-login';
import { writeHtmlReport } from './report';
import type { Finding, Severity } from './core/types';
import { SEVERITY_ORDER } from './report';

const program = new Command();
program
  .name('web-auth-auditor')
  .description('Authorized authorization/access-control auditor for web applications')
  .version('0.1.0');

interface CommonOpts {
  config: string;
  output?: string;
  logLevel: string;
  pretty?: boolean;
  headful?: boolean;
  failOn?: string;
}

function attachCommon(cmd: Command): Command {
  return cmd
    .requiredOption('-c, --config <path>', 'path to the YAML/JSON config file')
    .option('-o, --output <dir>', 'output directory for reports (overrides config)')
    .option('--log-level <level>', 'log level (trace|debug|info|warn|error)', 'info')
    .option('--pretty', 'human-readable (pretty) logs')
    .option('--headful', 'run the browser with a visible window')
    .option('--fail-on <severity>', 'exit non-zero if a finding at/above this severity is present');
}

async function doScan(opts: CommonOpts, mode: 'scan' | 'discover' | 'compare'): Promise<void> {
  const logger = createLogger({ level: opts.logLevel, pretty: opts.pretty });
  let config;
  try {
    config = loadConfig(opts.config);
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(`Configuration error:\n${e.message}\n`);
      process.exitCode = 2;
      return;
    }
    throw e;
  }
  if (opts.headful) config.browser.headless = false;

  try {
    const outcome = await runScan({
      config,
      logger,
      outputDir: opts.output,
      analyze: mode !== 'discover',
      report: true,
    });
    printSummary(outcome.scan.findings, outcome.reportPaths, mode);
    if (opts.failOn && hasSeverityAtLeast(outcome.scan.findings, opts.failOn as Severity)) {
      process.exitCode = 1;
    }
  } catch (e) {
    if (e instanceof AuthorizationError) {
      process.stderr.write(`\n${e.message}\n`);
      process.exitCode = 3;
      return;
    }
    process.stderr.write(`Scan failed: ${(e as Error).message}\n`);
    process.exitCode = 1;
  }
}

attachCommon(program.command('scan').description('crawl, replay safely across contexts, analyze and report')).action(
  (opts: CommonOpts) => doScan(opts, 'scan'),
);
attachCommon(
  program.command('discover').description('crawl and inventory endpoints only (no cross-context replay)'),
).action((opts: CommonOpts) => doScan(opts, 'discover'));
attachCommon(
  program.command('compare').description('run a full scan and focus output on cross-context findings'),
).action((opts: CommonOpts) => doScan(opts, 'compare'));

program
  .command('record-login')
  .description('run scripted logins from the config and capture session cookies to a file')
  .requiredOption('-c, --config <path>', 'config file with per-user `login` blocks')
  .option('-o, --out <path>', 'output file for captured cookies (contains secrets)', './sessions.json')
  .option('-u, --user <name>', 'only record this user')
  .option('--log-level <level>', 'log level', 'info')
  .option('--pretty', 'human-readable logs')
  .action(async (opts: { config: string; out: string; user?: string; logLevel: string; pretty?: boolean }) => {
    const logger = createLogger({ level: opts.logLevel, pretty: opts.pretty });
    let config;
    try {
      config = loadConfig(opts.config);
    } catch (e) {
      if (e instanceof ConfigError) {
        process.stderr.write(`Configuration error:\n${e.message}\n`);
        process.exitCode = 2;
        return;
      }
      throw e;
    }
    try {
      const results = await recordLogins(config, logger, { onlyUser: opts.user });
      if (results.length === 0) {
        process.stdout.write('No users with a `login` block were found in the config.\n');
        return;
      }
      const out: { warning: string; users: Record<string, unknown> } = {
        warning: 'Contains live session cookies — treat as secret; do not commit.',
        users: {},
      };
      for (const r of results) {
        process.stdout.write(`  ${r.ok ? '✓' : '✗'} ${r.user}${r.error ? ': ' + r.error : ''}\n`);
        if (r.ok) out.users[r.user] = { cookies: r.cookies };
      }
      writeFileSync(opts.out, JSON.stringify(out, null, 2), 'utf8');
      const okCount = results.filter((r) => r.ok).length;
      process.stdout.write(`Captured ${okCount}/${results.length} session(s) to ${opts.out} (contains secrets)\n`);
      if (okCount < results.length) process.exitCode = 1;
    } catch (e) {
      process.stderr.write(`record-login failed: ${(e as Error).message}\n`);
      process.exitCode = 1;
    }
  });

program
  .command('report')
  .description('re-render an HTML report from a previously produced report.json')
  .requiredOption('-i, --input <path>', 'path to a report.json produced by a scan')
  .option('-o, --output <dir>', 'output directory', './results')
  .action((opts: { input: string; output: string }) => {
    try {
      const json = JSON.parse(readFileSync(opts.input, 'utf8'));
      const bundle = bundleFromJson(json);
      const path = writeHtmlReport(opts.output, bundle);
      process.stdout.write(`HTML report written to ${path}\n`);
    } catch (e) {
      process.stderr.write(`Report rendering failed: ${(e as Error).message}\n`);
      process.exitCode = 1;
    }
  });

function printSummary(findings: Finding[], reportPaths: string[], mode: string): void {
  const bySev: Record<string, number> = {};
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
  process.stdout.write(`\n=== ${mode} complete ===\n`);
  if (mode === 'discover') {
    process.stdout.write('Discovery + inventory only (no cross-context replay performed).\n');
  }
  process.stdout.write(`Findings: ${findings.length}`);
  const parts = Object.entries(bySev).map(([s, n]) => `${s}=${n}`);
  if (parts.length) process.stdout.write(`  (${parts.join(', ')})`);
  process.stdout.write('\n');
  for (const f of sortForCli(findings).slice(0, 25)) {
    process.stdout.write(`  [${f.severity}/${f.confidence}] ${f.type}  ${f.testUser ?? '?'} → ${f.method ?? ''} ${pathOf(f.url)}\n`);
  }
  if (findings.length > 25) process.stdout.write(`  … and ${findings.length - 25} more (see report)\n`);
  for (const p of reportPaths) process.stdout.write(`Report: ${p}\n`);
}

function sortForCli(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
}

function hasSeverityAtLeast(findings: Finding[], threshold: Severity): boolean {
  const t = SEVERITY_ORDER[threshold] ?? 0;
  return findings.some((f) => (SEVERITY_ORDER[f.severity] ?? 9) <= t);
}

function pathOf(url?: string): string {
  if (!url) return '';
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

function bundleFromJson(json: any) {
  return {
    scan: {
      target: json.scan?.target ?? 'unknown',
      startedAt: Date.parse(json.scan?.startedAt ?? '') || Date.now(),
      finishedAt: Date.parse(json.scan?.finishedAt ?? '') || Date.now(),
      users: json.scan?.users ?? [],
      stats: json.scan?.stats ?? { nodes: 0, edges: 0, requests: 0, endpoints: 0, replays: 0, outOfScopeBlocked: 0 },
      findings: json.findings ?? [],
      inventorySummary: (json.inventory ?? []).map((i: any) => ({ user: i.user, role: i.role, endpoints: i.endpoints?.length ?? 0 })),
    },
    graphs: (json.graphs ?? []).map((g: any) => g.detail).filter(Boolean),
    inventory: json.inventory ?? [],
    configEcho: json.config ?? {},
  };
}

program.parseAsync(process.argv);
