/**
 * The data bundle handed to reporters. Assembled by the orchestrator so the
 * JSON and HTML reporters render from the same, fully-redacted structure.
 */
import type {
  EndpointObservation,
  Finding,
  NavigationGraph,
  ScanResult,
} from '../core/types';

export interface InventoryReportEntry {
  user: string;
  role?: string;
  privilegeLevel?: number;
  endpoints: Array<Pick<EndpointObservation, 'signature' | 'method' | 'pathTemplate' | 'sources'>>;
}

export interface ReportBundle {
  scan: ScanResult;
  graphs: NavigationGraph[];
  inventory: InventoryReportEntry[];
  /** config echo with secrets stripped (target, users, budgets). */
  configEcho: Record<string, unknown>;
}

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const CONFIDENCE_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 };

/** Sort findings most-serious first (severity, then confidence). */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const s = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (s !== 0) return s;
    return (CONFIDENCE_ORDER[a.confidence] ?? 9) - (CONFIDENCE_ORDER[b.confidence] ?? 9);
  });
}
