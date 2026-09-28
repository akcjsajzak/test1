/**
 * Library entry point. Re-exports the stable surface so the auditor can be
 * embedded programmatically as well as run from the CLI.
 */
export * from './core/types';
export * from './core/scope';
export { createLogger, silentLogger, type Logger } from './core/logger';
export * from './config/schema';
export { loadConfig, validateConfig, substituteEnv, ConfigError } from './config/loader';
export * as redaction from './config/redaction';
export { normalizeRequest, NormalizerState, classifySegment } from './analysis/normalize';
export { compareResponses, detectDenial, textSimilarity } from './analysis/compare';
export { EndpointInventory } from './analysis/inventory';
export {
  AnalyzerRegistry,
  type Analyzer,
  type AnalysisContext,
  type Replayer,
} from './analysis/engine';
export { BrowserEngine } from './browser/engine';
export { UserSession } from './browser/session';
export { NetworkCollector } from './browser/network';
export { RequestLog } from './core/request-log';
export { GraphBuilder } from './graph/model';
export { Explorer } from './crawler/explorer';
export { classifyInteraction, shouldTrigger } from './crawler/interactions';
export { ReplayEngine } from './analysis/replay';
export { HorizontalAnalyzer } from './analysis/horizontal';
export { VerticalAnalyzer } from './analysis/vertical';
export { runScan, AuthorizationError, type ScanOptions, type ScanOutcome } from './orchestrator/scan';
export {
  writeReports,
  buildJsonReport,
  buildHtmlReport,
  type ReportBundle,
} from './report';
