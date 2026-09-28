/**
 * Lightweight GraphQL detection and parsing (no dependency).
 *
 * GraphQL puts every operation behind one URL (e.g. POST /graphql), so URL-based
 * normalization can't tell operations apart. This module recognizes GraphQL
 * requests and derives a per-operation signature (operation type + root field)
 * plus the operation variables, so the inventory and analyzers treat each
 * operation as its own endpoint and a variable-bearing operation as an object
 * reference (enabling horizontal/vertical checks on GraphQL).
 */
import type { GraphqlOperation, ObservedRequest } from '../core/types';

export interface GraphqlParse {
  info: GraphqlOperation;
  /** flattened operation variables as strings (for markers). */
  variables: Record<string, string>;
}

/** Detect and parse a GraphQL request, or return null if it is not one. */
export function detectGraphql(req: ObservedRequest): GraphqlParse | null {
  if (req.method.toUpperCase() !== 'POST') return null;
  const looksLikePath = /graphql/i.test(req.url);
  const body = req.requestBody;
  if (!body) return null;
  let parsed: any;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  const doc = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!doc || typeof doc.query !== 'string') return null;
  // Require either a graphql-ish URL or a query containing an operation body.
  if (!looksLikePath && !/\{/.test(doc.query)) return null;

  const query: string = doc.query;
  const operationType = detectOperationType(query);
  const operationName = doc.operationName || matchOperationName(query) || undefined;
  const rootFields = extractRootFields(query);
  const variables = flattenVariables(doc.variables);

  return {
    info: { operationType, operationName, rootFields, variableCount: Object.keys(variables).length },
    variables,
  };
}

/** Build a stable per-operation signature. */
export function graphqlSignature(host: string, path: string, info: GraphqlOperation): string {
  const field = info.rootFields[0] ?? info.operationName ?? 'anonymous';
  return `GRAPHQL ${info.operationType} ${field} @ ${host}${path}`;
}

function detectOperationType(query: string): GraphqlOperation['operationType'] {
  const m = query.match(/\b(query|mutation|subscription)\b/i);
  if (m) return m[1].toLowerCase() as GraphqlOperation['operationType'];
  return 'query'; // shorthand `{ ... }` is a query
}

function matchOperationName(query: string): string | undefined {
  const m = query.match(/\b(?:query|mutation|subscription)\s+([A-Za-z_]\w*)/);
  return m ? m[1] : undefined;
}

/**
 * Extract top-level (root) field names. Strips argument groups first (so arg
 * names aren't mistaken for fields), then walks braces collecting identifiers at
 * selection depth 1, honoring aliases (`alias: field`).
 */
export function extractRootFields(query: string): string[] {
  // Remove balanced parenthesized argument groups (iteratively for nesting).
  let s = query;
  let prev: string;
  do {
    prev = s;
    s = s.replace(/\([^()]*\)/g, '');
  } while (s !== prev);

  const start = s.indexOf('{');
  if (start < 0) return [];
  const fields: string[] = [];
  let depth = 0;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (c === '{') {
      depth += 1;
      continue;
    }
    if (c === '}') {
      depth -= 1;
      if (depth === 0) break;
      continue;
    }
    if (depth === 1 && /[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < s.length && /[A-Za-z0-9_]/.test(s[j])) j += 1;
      let name = s.slice(i, j);
      let k = j;
      while (k < s.length && /\s/.test(s[k])) k += 1;
      if (s[k] === ':') {
        // alias — the real field follows the colon
        k += 1;
        while (k < s.length && /\s/.test(s[k])) k += 1;
        let l = k;
        while (l < s.length && /[A-Za-z0-9_]/.test(s[l])) l += 1;
        name = s.slice(k, l);
        i = l - 1;
      } else {
        i = j - 1;
      }
      if (name && name !== '__typename' && !fields.includes(name)) fields.push(name);
    }
  }
  return fields;
}

function flattenVariables(vars: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (vars && typeof vars === 'object' && !Array.isArray(vars)) {
    for (const [k, v] of Object.entries(vars as Record<string, unknown>)) {
      if (v === null || v === undefined) continue;
      out[k] = typeof v === 'object' ? JSON.stringify(v) : String(v);
    }
  }
  return out;
}
