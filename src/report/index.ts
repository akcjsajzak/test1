/**
 * Reporter facade: writes the configured report formats and structured logs.
 */
import type { Logger } from '../core/logger';
import type { OutputSpec } from '../config/schema';
import type { ReportBundle } from './bundle';
import { writeJsonReport } from './json';
import { writeHtmlReport } from './html';

export type { ReportBundle, InventoryReportEntry } from './bundle';
export { buildJsonReport, writeJsonReport } from './json';
export { buildHtmlReport, writeHtmlReport } from './html';
export { sortFindings, SEVERITY_ORDER } from './bundle';

/** Write all requested report formats; returns the written paths. */
export function writeReports(output: OutputSpec, bundle: ReportBundle, logger?: Logger): string[] {
  const written: string[] = [];
  for (const fmt of output.formats) {
    if (fmt === 'json') written.push(writeJsonReport(output.dir, bundle));
    if (fmt === 'html') written.push(writeHtmlReport(output.dir, bundle));
  }
  logger?.info({ paths: written }, 'reports written');
  return written;
}
