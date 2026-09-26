#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import process from 'node:process';
import ts from 'typescript';

const ROOT = process.cwd();
const BASELINE_PATH = 'downstream/mcp-security-baseline.json';
const POLICY_PATH = 'downstream/mcp-security-policy.json';

const CRITICAL_FILES = [
  'src/mcp-instructions.ts',
  'src/endpoints.json',
  'src/auth.ts',
  'src/cloud-config.ts',
  'src/graph-client.ts',
  'src/graph-tools.ts',
  'src/oauth-provider.ts',
  'src/lib/microsoft-auth.ts',
  'src/token-cache-storage.ts',
  'src/secrets.ts',
  'src/logger.ts',
  'src/lib/log-redactor.ts',
  'src/request-context.ts',
  'src/server.ts',
  'src/cli.ts',
];

const NETWORK_FILES = [
  'src/auth.ts',
  'src/cloud-config.ts',
  'src/graph-client.ts',
  'src/oauth-provider.ts',
  'src/lib/microsoft-auth.ts',
  'src/lib/graph-resilience.ts',
  'src/secrets.ts',
];

const FS_WRITE_CALLEES = new Set([
  'appendFile',
  'appendFileSync',
  'chmod',
  'chmodSync',
  'copyFile',
  'copyFileSync',
  'createWriteStream',
  'mkdir',
  'mkdirSync',
  'open',
  'openSync',
  'rename',
  'renameSync',
  'rm',
  'rmSync',
  'unlink',
  'unlinkSync',
  'writeFile',
  'writeFileSync',
]);

const CHILD_PROCESS_MODULES = new Set(['child_process', 'node:child_process']);

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256File(path) {
  return sha256Bytes(readFileSync(path));
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stable(value[key])])
    );
  }
  return value;
}

function stableJson(value) {
  return JSON.stringify(stable(value));
}

function flattenStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const item of value) flattenStrings(item, out);
  return out;
}

function walkFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const st = statSync(path);
    if (st.isDirectory()) {
      if (name === '__tests__' || name === 'generated') continue;
      out.push(...walkFiles(path));
    } else if (['.ts', '.mts', '.js', '.mjs'].includes(extname(path))) {
      out.push(path);
    }
  }
  return out;
}

function scriptKind(path) {
  const ext = extname(path);
  if (ext === '.ts' || ext === '.mts') return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function scanCode(files) {
  const processExecution = [];
  const dynamicImports = [];
  const nonLiteralDynamicImports = [];
  const dynamicCode = [];
  const filesystemWrites = [];
  const staticUrlHosts = new Set();

  for (const path of files) {
    const source = readFileSync(path, 'utf8');
    const rel = relative(ROOT, path).replaceAll('\\', '/');
    const sf = ts.createSourceFile(rel, source, ts.ScriptTarget.Latest, true, scriptKind(path));
    const childImports = new Map();
    const childNamespaces = new Set();
    const fsImports = new Map();
    const fsNamespaces = new Set();

    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const mod = stmt.moduleSpecifier.text;
      const clause = stmt.importClause;
      if (!clause) continue;

      if (CHILD_PROCESS_MODULES.has(mod)) {
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            childImports.set(el.name.text, el.propertyName?.text ?? el.name.text);
          }
        } else if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
          childNamespaces.add(clause.namedBindings.name.text);
        }
      }

      if (['fs', 'node:fs', 'fs/promises', 'node:fs/promises'].includes(mod)) {
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            fsImports.set(el.name.text, el.propertyName?.text ?? el.name.text);
          }
        } else if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
          fsNamespaces.add(clause.namedBindings.name.text);
        }
      }
    }

    function recordHost(text) {
      const re = /https?:\/\/[A-Za-z0-9.-]+(?::\d+)?/g;
      for (const match of text.matchAll(re)) {
        try {
          staticUrlHosts.add(new URL(match[0]).hostname.toLowerCase());
        } catch {
          // Ignore malformed literals; this is inventory, not URL validation.
        }
      }
    }

    function visit(node) {
      if (ts.isStringLiteralLike(node) && NETWORK_FILES.includes(rel)) {
        recordHost(node.text);
      }

      if (ts.isCallExpression(node)) {
        if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
          const arg = node.arguments[0];
          if (arg && ts.isStringLiteralLike(arg)) {
            dynamicImports.push({ file: rel, specifier: arg.text });
          } else {
            nonLiteralDynamicImports.push({ file: rel, expression: arg?.getText(sf) ?? '<missing>' });
          }
        }

        if (ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
          dynamicCode.push({ file: rel, kind: 'eval' });
        }

        if (ts.isIdentifier(node.expression) && childImports.has(node.expression.text)) {
          processExecution.push({
            file: rel,
            module: 'child_process',
            callee: childImports.get(node.expression.text),
          });
        } else if (ts.isPropertyAccessExpression(node.expression)) {
          const owner = node.expression.expression;
          const name = node.expression.name.text;
          if (ts.isIdentifier(owner) && childNamespaces.has(owner.text)) {
            processExecution.push({ file: rel, module: 'child_process', callee: name });
          }
        }

        if (ts.isIdentifier(node.expression) && fsImports.has(node.expression.text)) {
          const callee = fsImports.get(node.expression.text);
          if (FS_WRITE_CALLEES.has(callee)) filesystemWrites.push({ file: rel, callee });
        } else if (ts.isPropertyAccessExpression(node.expression)) {
          const owner = node.expression.expression;
          const callee = node.expression.name.text;
          if (ts.isIdentifier(owner) && fsNamespaces.has(owner.text) && FS_WRITE_CALLEES.has(callee)) {
            filesystemWrites.push({ file: rel, callee });
          } else if (FS_WRITE_CALLEES.has(callee)) {
            filesystemWrites.push({ file: rel, callee });
          }
        }
      }

      if (
        ts.isNewExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === 'Function'
      ) {
        dynamicCode.push({ file: rel, kind: 'new Function' });
      }

      ts.forEachChild(node, visit);
    }

    visit(sf);
  }

  const uniq = (items, keyFn) =>
    [...new Map(items.map((item) => [keyFn(item), item])).values()].sort((a, b) =>
      keyFn(a).localeCompare(keyFn(b))
    );

  return {
    processExecution: uniq(processExecution, (x) => `${x.file}:${x.module}:${x.callee}`),
    dynamicImports: uniq(dynamicImports, (x) => `${x.file}:${x.specifier}`),
    nonLiteralDynamicImports: uniq(
      nonLiteralDynamicImports,
      (x) => `${x.file}:${x.expression}`
    ),
    dynamicCode: uniq(dynamicCode, (x) => `${x.file}:${x.kind}`),
    filesystemWrites: uniq(filesystemWrites, (x) => `${x.file}:${x.callee}`),
    staticUrlHosts: [...staticUrlHosts].sort(),
  };
}

export function buildSnapshot() {
  const endpoints = JSON.parse(readFileSync('src/endpoints.json', 'utf8'));
  const scopes = new Set();
  const toolFingerprints = {};
  const writeCapableTools = [];

  for (const endpoint of endpoints) {
    for (const scope of flattenStrings(endpoint.scopes)) scopes.add(scope);
    for (const scope of flattenStrings(endpoint.workScopes)) scopes.add(scope);

    const key = `${endpoint.toolName}|${String(endpoint.method).toUpperCase()}|${endpoint.pathPattern}`;
    toolFingerprints[key] = sha256Bytes(Buffer.from(stableJson(endpoint)));

    const method = String(endpoint.method).toLowerCase();
    if (method !== 'get' && endpoint.readOnly !== true) writeCapableTools.push(endpoint.toolName);
  }

  const codeFiles = [
    ...walkFiles(join(ROOT, 'src')),
    ...walkFiles(join(ROOT, 'bin')),
    ...walkFiles(join(ROOT, 'scripts')).filter(
      (path) => !path.endsWith('mcp-security-snapshot.mjs')
    ),
  ];

  const scan = scanCode(codeFiles);

  return stable({
    schemaVersion: 1,
    generatedSchemaCoverage: {
      status: 'deferred-to-SM-5',
      reason:
        'src/generated/client.ts is generated from mutable Microsoft Graph OpenAPI input and is not tracked; complete generated tool-schema fingerprinting becomes deterministic only after SM-5 pins the generation inputs.',
    },
    criticalFileSha256: Object.fromEntries(
      CRITICAL_FILES.map((path) => [path, sha256File(path)])
    ),
    mcpInstructionsSha256: sha256File('src/mcp-instructions.ts'),
    endpointsSha256: sha256File('src/endpoints.json'),
    endpointCount: endpoints.length,
    graphScopes: [...scopes].sort(),
    writeLikeScopes: [...scopes]
      .filter((scope) => /(Write|Send|Create|Delete|Manage)/.test(scope))
      .sort(),
    writeCapableTools: [...new Set(writeCapableTools)].sort(),
    toolFingerprints,
    staticUrlHosts: scan.staticUrlHosts,
    processExecution: scan.processExecution,
    dynamicImports: scan.dynamicImports,
    nonLiteralDynamicImports: scan.nonLiteralDynamicImports,
    dynamicCode: scan.dynamicCode,
    filesystemWrites: scan.filesystemWrites,
  });
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function keys(items, fields) {
  return new Set(items.map((item) => fields.map((field) => item[field]).join('|')));
}

function diffSet(expected, actual) {
  const e = new Set(expected);
  const a = new Set(actual);
  return {
    added: [...a].filter((x) => !e.has(x)).sort(),
    removed: [...e].filter((x) => !a.has(x)).sort(),
  };
}

export function validatePolicy(snapshot, policy) {
  const failures = [];

  if (policy.schemaVersion !== 1) failures.push(`unsupported policy schemaVersion ${policy.schemaVersion}`);

  const graphScopeDiff = diffSet(policy.approvedGraphScopes, snapshot.graphScopes);
  if (graphScopeDiff.added.length) {
    failures.push(`unapproved Graph scopes: ${graphScopeDiff.added.join(', ')}`);
  }

  const hostDiff = diffSet(policy.approvedStaticUrlHosts, snapshot.staticUrlHosts);
  if (hostDiff.added.length) {
    failures.push(`unapproved static URL hosts: ${hostDiff.added.join(', ')}`);
  }

  const approvedProcess = keys(policy.approvedProcessExecution, ['file', 'module', 'callee']);
  for (const site of snapshot.processExecution) {
    const key = `${site.file}|${site.module}|${site.callee}`;
    if (!approvedProcess.has(key)) failures.push(`unapproved process execution site: ${key}`);
  }

  const approvedFs = keys(policy.approvedFilesystemWrites, ['file', 'callee']);
  for (const site of snapshot.filesystemWrites) {
    const key = `${site.file}|${site.callee}`;
    if (!approvedFs.has(key)) failures.push(`unapproved filesystem write site: ${key}`);
  }

  const approvedImports = keys(policy.approvedDynamicImports, ['file', 'specifier']);
  for (const site of snapshot.dynamicImports) {
    const key = `${site.file}|${site.specifier}`;
    if (!approvedImports.has(key)) failures.push(`unapproved dynamic import: ${key}`);
  }

  if (snapshot.nonLiteralDynamicImports.length) {
    failures.push(
      `non-literal dynamic imports are forbidden: ${JSON.stringify(snapshot.nonLiteralDynamicImports)}`
    );
  }
  if (snapshot.dynamicCode.length) {
    failures.push(`dynamic code execution is forbidden: ${JSON.stringify(snapshot.dynamicCode)}`);
  }

  const expectedProfile = {
    mode: 'stdio',
    orgMode: true,
    readOnly: true,
    allowedScopes: [
      'User.Read',
      'Mail.Read',
      'Calendars.Read',
      'Chat.Read',
      'Team.ReadBasic.All',
    ],
  };
  if (stableJson(policy.productionProfile) !== stableJson(expectedProfile)) {
    failures.push('productionProfile differs from the approved first-production contract');
  }

  return failures;
}

export function compareSnapshots(expected, actual) {
  const changes = [];
  const expectedTools = expected.toolFingerprints ?? {};
  const actualTools = actual.toolFingerprints ?? {};

  const toolKeys = [...new Set([...Object.keys(expectedTools), ...Object.keys(actualTools)])].sort();
  const changedTools = toolKeys.filter((key) => expectedTools[key] !== actualTools[key]);
  if (changedTools.length) changes.push(`tool metadata changed: ${changedTools.join(', ')}`);

  for (const field of [
    'graphScopes',
    'writeLikeScopes',
    'writeCapableTools',
    'staticUrlHosts',
    'processExecution',
    'dynamicImports',
    'nonLiteralDynamicImports',
    'dynamicCode',
    'filesystemWrites',
  ]) {
    if (stableJson(expected[field]) !== stableJson(actual[field])) {
      changes.push(`${field} changed`);
    }
  }

  for (const field of ['mcpInstructionsSha256', 'endpointsSha256', 'endpointCount']) {
    if (expected[field] !== actual[field]) changes.push(`${field} changed`);
  }

  const fileKeys = [...new Set([
    ...Object.keys(expected.criticalFileSha256 ?? {}),
    ...Object.keys(actual.criticalFileSha256 ?? {}),
  ])].sort();
  for (const file of fileKeys) {
    if (expected.criticalFileSha256?.[file] !== actual.criticalFileSha256?.[file]) {
      changes.push(`critical file changed: ${file}`);
    }
  }

  return changes;
}

function writeSummary(lines) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  const body = ['## MCP security baseline', '', ...lines.map((line) => `- ${line}`), ''].join('\n');
  writeFileSync(summaryPath, body, { flag: 'a' });
}

function main() {
  const mode = process.argv[2] ?? '--check';
  const snapshot = buildSnapshot();

  if (mode === '--write') {
    writeFileSync(BASELINE_PATH, JSON.stringify(snapshot, null, 2) + '\n');
    console.log(`Wrote ${BASELINE_PATH}`);
    return;
  }

  if (mode !== '--check') {
    console.error('usage: node scripts/mcp-security-snapshot.mjs [--check|--write]');
    process.exit(2);
  }

  const baseline = readJson(BASELINE_PATH);
  const policy = readJson(POLICY_PATH);
  const changes = compareSnapshots(baseline, snapshot);
  const policyFailures = validatePolicy(snapshot, policy);

  const summary = [
    `endpoint count: ${snapshot.endpointCount}`,
    `Graph scopes: ${snapshot.graphScopes.length}`,
    `write-capable tools: ${snapshot.writeCapableTools.length}`,
    `static URL hosts: ${snapshot.staticUrlHosts.length}`,
    `process execution sites: ${snapshot.processExecution.length}`,
    `filesystem write sites: ${snapshot.filesystemWrites.length}`,
    `dynamic imports: ${snapshot.dynamicImports.length}`,
    `generated schema coverage: ${snapshot.generatedSchemaCoverage.status}`,
  ];
  writeSummary(summary);

  if (changes.length || policyFailures.length) {
    if (changes.length) {
      console.error('Checked-in MCP security baseline does not match current source:');
      for (const change of changes) console.error(`- ${change}`);
      console.error('Run: node scripts/mcp-security-snapshot.mjs --write');
      console.error('Then review the baseline diff as a security artifact.');
    }
    if (policyFailures.length) {
      console.error('MCP security policy FAILED:');
      for (const failure of policyFailures) console.error(`- ${failure}`);
    }
    process.exit(1);
  }

  console.log('MCP security baseline PASS');
  for (const line of summary) console.log(line);
}

const invoked = process.argv[1] && new URL(import.meta.url).pathname === process.argv[1];
if (invoked) main();
