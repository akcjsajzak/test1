/**
 * Human-readable HTML reporter. Produces a single self-contained page (inline
 * CSS, no external assets) summarizing stats, findings with full evidence, and
 * the per-user endpoint inventory.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { Finding, ResponseSnapshot } from '../core/types';
import type { ReportBundle } from './bundle';
import { sortFindings } from './bundle';

function esc(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const SEV_COLOR: Record<string, string> = {
  critical: '#7f1d1d',
  high: '#dc2626',
  medium: '#d97706',
  low: '#2563eb',
  info: '#6b7280',
};
const CONF_COLOR: Record<string, string> = {
  high: '#dc2626',
  medium: '#d97706',
  low: '#2563eb',
  info: '#6b7280',
};

function badge(text: string, color: string): string {
  return `<span class="badge" style="background:${color}">${esc(text)}</span>`;
}

function snapshotHtml(title: string, snap?: ResponseSnapshot): string {
  if (!snap) return '';
  return `<div class="snap"><div class="snap-h">${esc(title)}</div>
    <div class="snap-meta">HTTP ${esc(snap.status ?? '?')} · ${esc(snap.contentType ?? 'n/a')} · ${esc(snap.size ?? '?')} bytes</div>
    ${snap.bodyPreview ? `<pre>${esc(snap.bodyPreview)}</pre>` : ''}</div>`;
}

function findingHtml(f: Finding): string {
  const ev = f.evidence.map((e) => `<li><b>${esc(e.label)}:</b> ${esc(e.detail)}</li>`).join('');
  const diff = f.diff;
  const diffHtml = diff
    ? `<div class="diff">
        <div>verdict: <b>${esc(diff.verdict)}</b> · similarity ${(diff.similarity * 100).toFixed(0)}%
          ${diff.statusChanged ? ` · status ${esc(diff.sourceStatus)}→${esc(diff.testStatus)}` : ''}</div>
        ${diff.jsonKeyDiffs && diff.jsonKeyDiffs.length ? `<details><summary>${diff.jsonKeyDiffs.length} JSON field diff(s)</summary><pre>${esc(diff.jsonKeyDiffs.join('\n'))}</pre></details>` : ''}
      </div>`
    : '';
  return `<article class="finding">
    <header>
      <div class="f-title">${esc(f.title)}</div>
      <div class="f-badges">${badge(f.severity, SEV_COLOR[f.severity] ?? '#6b7280')} ${badge('conf: ' + f.confidence, CONF_COLOR[f.confidence] ?? '#6b7280')}</div>
    </header>
    <div class="f-id">${esc(f.id)} · ${esc(f.type)}</div>
    <table class="kv">
      <tr><td>Source context</td><td>${esc(f.sourceUser ?? '-')}</td></tr>
      <tr><td>Test context</td><td>${esc(f.testUser ?? '-')}</td></tr>
      <tr><td>Request</td><td><code>${esc(f.method ?? '')} ${esc(f.url ?? '')}</code></td></tr>
      <tr><td>Normalized route</td><td><code>${esc(f.normalizedRoute ?? '-')}</code></td></tr>
      <tr><td>Discovery action</td><td>${esc(f.triggeringAction ?? '-')}</td></tr>
      <tr><td>Detected at</td><td>${esc(new Date(f.timestamp).toISOString())}</td></tr>
    </table>
    ${diffHtml}
    <div class="snaps">${snapshotHtml('Observed (source) response', f.observedResponse)}${snapshotHtml('Comparison (test) response', f.comparisonResponse)}</div>
    <details class="evidence"><summary>Evidence (${f.evidence.length})</summary><ul>${ev}</ul></details>
  </article>`;
}

export function buildHtmlReport(bundle: ReportBundle): string {
  const findings = sortFindings(bundle.scan.findings);
  const s = bundle.scan.stats;
  const bySeverity = countBy(findings.map((f) => f.severity));

  const statCards = [
    ['Findings', String(findings.length)],
    ['Users', String(bundle.scan.users.length)],
    ['Endpoints', String(s.endpoints)],
    ['Requests', String(s.requests)],
    ['Replays', String(s.replays)],
    ['Graph nodes', String(s.nodes)],
    ['Out-of-scope blocked', String(s.outOfScopeBlocked)],
  ]
    .map(([k, v]) => `<div class="card"><div class="card-v">${esc(v)}</div><div class="card-k">${esc(k)}</div></div>`)
    .join('');

  const sevSummary = Object.entries(bySeverity)
    .map(([sev, n]) => badge(`${sev}: ${n}`, SEV_COLOR[sev] ?? '#6b7280'))
    .join(' ');

  const findingsHtml = findings.length
    ? findings.map(findingHtml).join('\n')
    : '<p class="empty">No authorization findings were produced. This is not proof of a secure application; review the inventory and coverage.</p>';

  const inventoryHtml = bundle.inventory
    .map((inv) => {
      const rows = inv.endpoints
        .map(
          (e) =>
            `<tr><td><code>${esc(e.method)}</code></td><td><code>${esc(e.pathTemplate)}</code></td><td>${esc(e.sources.join(', '))}</td></tr>`,
        )
        .join('');
      return `<details class="inv"><summary>${esc(inv.user)}${inv.role ? ` (${esc(inv.role)})` : ''} — ${inv.endpoints.length} endpoint(s)</summary>
        <table class="ep"><thead><tr><th>Method</th><th>Route</th><th>Discovery</th></tr></thead><tbody>${rows}</tbody></table></details>`;
    })
    .join('\n');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auth Audit Report — ${esc(bundle.scan.target)}</title>
<style>
  :root { color-scheme: light dark; --bg:#fff; --fg:#111; --muted:#666; --line:#0002; --card:#f6f7f9; }
  @media (prefers-color-scheme: dark){ :root{ --bg:#0f1115; --fg:#e8eaed; --muted:#9aa0a6; --line:#fff2; --card:#1a1d23; } }
  *{box-sizing:border-box} body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.5}
  header.top{padding:1.25rem 1.5rem;border-bottom:1px solid var(--line)}
  h1{margin:.2rem 0;font-size:1.3rem} .sub{color:var(--muted);font-size:.9rem}
  main{padding:1.5rem;max-width:1000px;margin:0 auto}
  .notice{background:#d9770622;border:1px solid #d9770655;padding:.6rem .8rem;border-radius:8px;font-size:.85rem;margin:1rem 0}
  .cards{display:flex;flex-wrap:wrap;gap:.6rem;margin:1rem 0}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:.7rem 1rem;min-width:120px}
  .card-v{font-size:1.5rem;font-weight:700} .card-k{color:var(--muted);font-size:.8rem}
  .badge{display:inline-block;color:#fff;padding:.1rem .5rem;border-radius:999px;font-size:.72rem;font-weight:600;white-space:nowrap}
  h2{margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
  .finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:10px;padding:1rem;margin:1rem 0}
  .finding header{display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;flex-wrap:wrap}
  .f-title{font-weight:700} .f-id{color:var(--muted);font-size:.78rem;margin:.2rem 0 .6rem;font-family:ui-monospace,monospace}
  table.kv{border-collapse:collapse;width:100%;font-size:.88rem;margin:.3rem 0}
  table.kv td{padding:.2rem .4rem;vertical-align:top;border-bottom:1px solid var(--line)}
  table.kv td:first-child{color:var(--muted);width:150px}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;word-break:break-all}
  pre{background:#0001;padding:.6rem;border-radius:6px;overflow:auto;font-size:.8rem;max-height:260px}
  .diff{margin:.6rem 0;font-size:.85rem}
  .snaps{display:flex;gap:.8rem;flex-wrap:wrap;margin:.6rem 0}
  .snap{flex:1;min-width:260px} .snap-h{font-weight:600;font-size:.82rem} .snap-meta{color:var(--muted);font-size:.78rem;margin-bottom:.2rem}
  details{margin:.4rem 0} summary{cursor:pointer} .evidence ul{margin:.4rem 0;padding-left:1.2rem;font-size:.85rem}
  table.ep{border-collapse:collapse;width:100%;font-size:.83rem;margin:.4rem 0}
  table.ep th,table.ep td{padding:.25rem .5rem;text-align:left;border-bottom:1px solid var(--line)}
  .empty{color:var(--muted)} footer{color:var(--muted);font-size:.8rem;padding:1.5rem;text-align:center}
</style></head>
<body>
<header class="top">
  <h1>Web Authorization Audit</h1>
  <div class="sub">Target: <code>${esc(bundle.scan.target)}</code> · Generated ${esc(new Date().toISOString())}</div>
</header>
<main>
  <div class="notice">⚠️ Authorized testing only. This report concerns an application the operator is authorized to assess. Findings are observations requiring human validation, not confirmed exploits.</div>
  <div>${sevSummary || '<span class="sub">no findings</span>'}</div>
  <div class="cards">${statCards}</div>
  <h2>Findings</h2>
  ${findingsHtml}
  <h2>Endpoint inventory</h2>
  ${inventoryHtml || '<p class="empty">No endpoints inventoried.</p>'}
</main>
<footer>web-auth-auditor · authorized security testing</footer>
</body></html>`;
}

export function writeHtmlReport(outputDir: string, bundle: ReportBundle): string {
  const path = join(outputDir, 'report.html');
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, buildHtmlReport(bundle), 'utf8');
  return path;
}

function countBy(items: string[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const i of items) out[i] = (out[i] ?? 0) + 1;
  return out;
}
