#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import process from 'node:process';
import ts from 'typescript';

const ROOT = process.cwd();
const BASELINE_PATH = 'downstream/mcp-security-baseline.json';
const POLICY_PATH = 'downstream/mcp-security-policy.json';

function listCriticalFiles() {
  const codeFiles = [
    ...walkFiles(join(ROOT, 'src')),
    ...walkFiles(join(ROOT, 'bin')),
    ...walkFiles(join(ROOT, 'scripts')),
  ].map((path) => relative(ROOT, path).replaceAll('\\', '/'));
  return [...new Set([...codeFiles, 'src/endpoints.json'])].sort();
}

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
const FS_MODULES = new Set(['fs', 'node:fs', 'fs/promises', 'node:fs/promises']);
const CREATE_REQUIRE_MODULES = new Set(['module', 'node:module']);
const NETWORK_ENV_NAME_RE =
  /^[A-Z][A-Z0-9_]*(?:_URLS?|_URIS?|_ENDPOINTS?|_HOSTS?|_ORIGINS?|_URL_BASES?)$/;
const MUTABLE_GENERATED_FILES = new Set(['src/generated/client.ts']);
const CODE_EXTENSIONS = new Set(['.ts', '.mts', '.cts', '.js', '.mjs', '.cjs']);

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
      if (name === '__tests__') continue;
      out.push(...walkFiles(path));
      continue;
    }

    const rel = relative(ROOT, path).replaceAll('\\', '/');
    if (MUTABLE_GENERATED_FILES.has(rel)) continue;
    if (CODE_EXTENSIONS.has(extname(path))) out.push(path);
  }
  return out;
}

function scriptKind(path) {
  const ext = extname(path);
  if (ext === '.ts' || ext === '.mts' || ext === '.cts') return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

export function scanCode(files) {
  const processExecution = [];
  const dynamicImports = [];
  const nonLiteralDynamicImports = [];
  const dynamicCode = [];
  const filesystemWrites = [];
  const staticUrlHosts = new Set();
  const networkUrlEnvVars = new Set();

  for (const path of files) {
    const source = readFileSync(path, 'utf8');
    const rel = relative(ROOT, path).replaceAll('\\', '/');
    const sf = ts.createSourceFile(rel, source, ts.ScriptTarget.Latest, true, scriptKind(path));
    const childImports = new Map();
    const childNamespaces = new Map();
    const fsImports = new Map();
    const fsNamespaces = new Set();
    const createRequireImports = new Set();
    const moduleNamespaces = new Set();
    const requireAliases = new Set(['require']);
    const envAliases = new Set();

    function addEnvBinding(name) {
      if (ts.isIdentifier(name)) {
        envAliases.add(name.text);
        return;
      }
      if (ts.isObjectBindingPattern(name)) {
        for (const element of name.elements) {
          const key = element.propertyName?.getText(sf) ?? element.name.getText(sf);
          const normalized = key.replace(/^['"]|['"]$/g, '');
          if (NETWORK_ENV_NAME_RE.test(normalized)) networkUrlEnvVars.add(normalized);
        }
      }
    }

    function isProcessEnvObject(node) {
      const expr = unwrapExpression(node);
      if (!expr) return false;
      return (
        (ts.isPropertyAccessExpression(expr) &&
          ts.isIdentifier(unwrapExpression(expr.expression)) &&
          unwrapExpression(expr.expression).text === 'process' &&
          expr.name.text === 'env') ||
        (ts.isElementAccessExpression(expr) &&
          ts.isIdentifier(unwrapExpression(expr.expression)) &&
          unwrapExpression(expr.expression).text === 'process' &&
          expr.argumentExpression &&
          ts.isStringLiteralLike(expr.argumentExpression) &&
          expr.argumentExpression.text === 'env')
      );
    }

    function isEnvObject(node) {
      const expr = unwrapExpression(node);
      return (
        isProcessEnvObject(expr) || (expr && ts.isIdentifier(expr) && envAliases.has(expr.text))
      );
    }

    function envAccessName(node) {
      const expr = unwrapExpression(node);
      if (!expr) return undefined;

      if (ts.isPropertyAccessExpression(expr) && NETWORK_ENV_NAME_RE.test(expr.name.text)) {
        return expr.name.text;
      }

      if (
        ts.isElementAccessExpression(expr) &&
        expr.argumentExpression &&
        ts.isStringLiteralLike(expr.argumentExpression) &&
        NETWORK_ENV_NAME_RE.test(expr.argumentExpression.text)
      ) {
        return expr.argumentExpression.text;
      }

      return undefined;
    }

    function requireModule(node) {
      const call = unwrapExpression(node);
      if (!call || !ts.isCallExpression(call) || call.arguments.length === 0) return undefined;
      const arg = call.arguments[0];
      if (!ts.isStringLiteralLike(arg)) return undefined;

      const callee = unwrapExpression(call.expression);
      if (ts.isIdentifier(callee) && requireAliases.has(callee.text)) {
        return arg.text;
      }

      if (
        ts.isCallExpression(callee) &&
        ts.isIdentifier(unwrapExpression(callee.expression)) &&
        createRequireImports.has(unwrapExpression(callee.expression).text)
      ) {
        return arg.text;
      }

      if (
        ts.isPropertyAccessExpression(callee) &&
        ts.isIdentifier(unwrapExpression(callee.expression)) &&
        unwrapExpression(callee.expression).text === 'process' &&
        callee.name.text === 'getBuiltinModule'
      ) {
        return arg.text;
      }

      if (
        ts.isElementAccessExpression(callee) &&
        ts.isIdentifier(unwrapExpression(callee.expression)) &&
        unwrapExpression(callee.expression).text === 'process' &&
        callee.argumentExpression &&
        ts.isStringLiteralLike(callee.argumentExpression) &&
        callee.argumentExpression.text === 'getBuiltinModule'
      ) {
        return arg.text;
      }

      return undefined;
    }

    function bindRequiredModule(name, mod) {
      if (CREATE_REQUIRE_MODULES.has(mod)) {
        if (ts.isIdentifier(name)) {
          moduleNamespaces.add(name.text);
        } else if (ts.isObjectBindingPattern(name)) {
          for (const element of name.elements) {
            const imported = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            if (imported === 'createRequire' && ts.isIdentifier(element.name)) {
              createRequireImports.add(element.name.text);
            }
          }
        }
      }

      if (CHILD_PROCESS_MODULES.has(mod)) {
        if (ts.isIdentifier(name)) {
          childNamespaces.set(name.text, mod);
          processExecution.push({ file: rel, module: mod, callee: '*' });
        } else if (ts.isObjectBindingPattern(name)) {
          for (const element of name.elements) {
            const imported = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            const local = element.name.getText(sf);
            childImports.set(local, { module: mod, callee: imported });
            processExecution.push({ file: rel, module: mod, callee: imported });
          }
        }
      }

      if (FS_MODULES.has(mod)) {
        if (ts.isIdentifier(name)) {
          fsNamespaces.add(name.text);
        } else if (ts.isObjectBindingPattern(name)) {
          for (const element of name.elements) {
            const imported = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            const local = element.name.getText(sf);
            fsImports.set(local, imported);
          }
        }
      }
    }

    function unwrapExpression(node) {
      let current = node;
      while (
        current &&
        (ts.isParenthesizedExpression(current) ||
          ts.isAsExpression(current) ||
          ts.isTypeAssertionExpression(current) ||
          ts.isSatisfiesExpression(current) ||
          ts.isNonNullExpression(current))
      ) {
        current = current.expression;
      }
      return current;
    }

    function dynamicCodeTarget(node) {
      const expr = unwrapExpression(node);
      if (!expr) return undefined;

      if (ts.isIdentifier(expr) && (expr.text === 'eval' || expr.text === 'Function')) {
        return expr.text;
      }

      if (
        ts.isPropertyAccessExpression(expr) &&
        ts.isIdentifier(expr.expression) &&
        expr.expression.text === 'globalThis' &&
        (expr.name.text === 'eval' || expr.name.text === 'Function')
      ) {
        return 'globalThis.' + expr.name.text;
      }

      if (
        ts.isElementAccessExpression(expr) &&
        ts.isIdentifier(expr.expression) &&
        expr.expression.text === 'globalThis' &&
        expr.argumentExpression &&
        ts.isStringLiteralLike(expr.argumentExpression) &&
        (expr.argumentExpression.text === 'eval' || expr.argumentExpression.text === 'Function')
      ) {
        return "globalThis['" + expr.argumentExpression.text + "']";
      }

      if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.CommaToken) {
        return dynamicCodeTarget(expr.right);
      }

      return undefined;
    }

    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) continue;
      const mod = stmt.moduleSpecifier.text;
      const clause = stmt.importClause;
      if (!clause) continue;

      if (clause.isTypeOnly) continue;

      if (CREATE_REQUIRE_MODULES.has(mod)) {
        if (clause.name) moduleNamespaces.add(clause.name.text);
        if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
          moduleNamespaces.add(clause.namedBindings.name.text);
        }
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            if (el.isTypeOnly) continue;
            const imported = el.propertyName?.text ?? el.name.text;
            if (imported === 'createRequire') createRequireImports.add(el.name.text);
          }
        }
      }

      if (
        (mod === 'process' || mod === 'node:process') &&
        clause.namedBindings &&
        ts.isNamedImports(clause.namedBindings)
      ) {
        for (const el of clause.namedBindings.elements) {
          if (el.isTypeOnly) continue;
          const imported = el.propertyName?.text ?? el.name.text;
          if (imported === 'env') envAliases.add(el.name.text);
        }
      }

      if (CHILD_PROCESS_MODULES.has(mod)) {
        if (clause.name) {
          childNamespaces.set(clause.name.text, mod);
          processExecution.push({ file: rel, module: mod, callee: '*' });
        }
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            if (el.isTypeOnly) continue;
            const imported = el.propertyName?.text ?? el.name.text;
            childImports.set(el.name.text, { module: mod, callee: imported });
            processExecution.push({ file: rel, module: mod, callee: imported });
          }
        } else if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
          childNamespaces.set(clause.namedBindings.name.text, mod);
          processExecution.push({ file: rel, module: mod, callee: '*' });
        }
      }

      if (FS_MODULES.has(mod)) {
        if (clause.name) fsNamespaces.add(clause.name.text);
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            fsImports.set(el.name.text, el.propertyName?.text ?? el.name.text);
          }
        } else if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
          fsNamespaces.add(clause.namedBindings.name.text);
        }
      }
    }

    for (const stmt of sf.statements) {
      if (
        ts.isImportEqualsDeclaration(stmt) &&
        !stmt.isTypeOnly &&
        ts.isExternalModuleReference(stmt.moduleReference) &&
        stmt.moduleReference.expression &&
        ts.isStringLiteralLike(stmt.moduleReference.expression)
      ) {
        bindRequiredModule(stmt.name, stmt.moduleReference.expression.text);
      }

      if (
        ts.isExportDeclaration(stmt) &&
        !stmt.isTypeOnly &&
        stmt.moduleSpecifier &&
        ts.isStringLiteralLike(stmt.moduleSpecifier) &&
        CHILD_PROCESS_MODULES.has(stmt.moduleSpecifier.text)
      ) {
        if (!stmt.exportClause) {
          processExecution.push({ file: rel, module: stmt.moduleSpecifier.text, callee: '*' });
        } else if (ts.isNamedExports(stmt.exportClause)) {
          for (const el of stmt.exportClause.elements) {
            const exported = el.propertyName?.text ?? el.name.text;
            processExecution.push({
              file: rel,
              module: stmt.moduleSpecifier.text,
              callee: exported,
            });
          }
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
      if (
        (ts.isVariableDeclaration(node) || ts.isParameter(node)) &&
        ts.isObjectBindingPattern(node.name)
      ) {
        for (const element of node.name.elements) {
          const key = element.propertyName?.getText(sf) ?? element.name.getText(sf);
          const normalized = key.replace(/^['"]|['"]$/g, '');
          if (NETWORK_ENV_NAME_RE.test(normalized)) networkUrlEnvVars.add(normalized);
        }
      }

      if ((ts.isVariableDeclaration(node) || ts.isParameter(node)) && node.initializer) {
        const initializer = unwrapExpression(node.initializer);
        if (isEnvObject(initializer)) addEnvBinding(node.name);

        if (
          ts.isVariableDeclaration(node) &&
          ts.isObjectBindingPattern(node.name) &&
          initializer &&
          ts.isIdentifier(initializer) &&
          initializer.text === 'process'
        ) {
          for (const element of node.name.elements) {
            const key = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            if (key === 'env' && ts.isIdentifier(element.name)) envAliases.add(element.name.text);
          }
        }

        if (
          ts.isVariableDeclaration(node) &&
          ts.isIdentifier(node.name) &&
          initializer &&
          ts.isIdentifier(initializer) &&
          requireAliases.has(initializer.text)
        ) {
          requireAliases.add(node.name.text);
        }

        if (
          ts.isVariableDeclaration(node) &&
          ts.isIdentifier(node.name) &&
          initializer &&
          ts.isCallExpression(initializer)
        ) {
          const callee = unwrapExpression(initializer.expression);
          if (ts.isIdentifier(callee) && createRequireImports.has(callee.text)) {
            requireAliases.add(node.name.text);
          } else if (
            ts.isPropertyAccessExpression(callee) &&
            ts.isIdentifier(unwrapExpression(callee.expression)) &&
            moduleNamespaces.has(unwrapExpression(callee.expression).text) &&
            callee.name.text === 'createRequire'
          ) {
            requireAliases.add(node.name.text);
          }
        }

        if (ts.isVariableDeclaration(node)) {
          const mod = requireModule(initializer);
          if (mod) bindRequiredModule(node.name, mod);
        }

        const aliasTarget = dynamicCodeTarget(node.initializer);
        if (aliasTarget) dynamicCode.push({ file: rel, kind: 'alias ' + aliasTarget });

        if (
          ts.isVariableDeclaration(node) &&
          ts.isObjectBindingPattern(node.name) &&
          ts.isIdentifier(node.initializer) &&
          node.initializer.text === 'globalThis'
        ) {
          for (const element of node.name.elements) {
            const key = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            if (key === 'eval' || key === 'Function') {
              dynamicCode.push({ file: rel, kind: 'alias globalThis.' + key });
            }
          }
        }
      }

      if (ts.isStringLiteralLike(node) && NETWORK_FILES.includes(rel)) {
        recordHost(node.text);
      }

      const envName = envAccessName(node);
      if (envName && NETWORK_ENV_NAME_RE.test(envName)) networkUrlEnvVars.add(envName);

      if (ts.isCallExpression(node)) {
        if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
          const arg = node.arguments[0];
          if (arg && ts.isStringLiteralLike(arg)) {
            dynamicImports.push({ file: rel, specifier: arg.text });
          } else {
            nonLiteralDynamicImports.push({
              file: rel,
              expression: arg?.getText(sf) ?? '<missing>',
            });
          }
        }

        const dynamicTarget = dynamicCodeTarget(node.expression);
        if (dynamicTarget) dynamicCode.push({ file: rel, kind: 'call ' + dynamicTarget });

        const callExpr = unwrapExpression(node.expression);
        if (ts.isPropertyAccessExpression(callExpr)) {
          const method = callExpr.name.text;
          const ownerTarget = dynamicCodeTarget(callExpr.expression);
          if (ownerTarget && ['call', 'apply', 'bind'].includes(method)) {
            dynamicCode.push({ file: rel, kind: method + ' ' + ownerTarget });
          }
          if (
            ts.isIdentifier(unwrapExpression(callExpr.expression)) &&
            unwrapExpression(callExpr.expression).text === 'Reflect' &&
            method === 'apply' &&
            node.arguments[0]
          ) {
            const reflectTarget = dynamicCodeTarget(node.arguments[0]);
            if (reflectTarget)
              dynamicCode.push({ file: rel, kind: 'Reflect.apply ' + reflectTarget });
          }
        }

        const required = requireModule(node);
        if (required && CHILD_PROCESS_MODULES.has(required)) {
          processExecution.push({ file: rel, module: required, callee: '*' });
        }

        if (ts.isIdentifier(node.expression) && childImports.has(node.expression.text)) {
          const capability = childImports.get(node.expression.text);
          processExecution.push({
            file: rel,
            module: capability.module,
            callee: capability.callee,
          });
        } else if (ts.isPropertyAccessExpression(node.expression)) {
          const owner = node.expression.expression;
          const name = node.expression.name.text;
          if (ts.isIdentifier(owner) && childNamespaces.has(owner.text)) {
            processExecution.push({
              file: rel,
              module: childNamespaces.get(owner.text),
              callee: name,
            });
          } else {
            const mod = requireModule(owner);
            if (mod && CHILD_PROCESS_MODULES.has(mod)) {
              processExecution.push({ file: rel, module: mod, callee: name });
            }
          }
        }

        if (ts.isIdentifier(node.expression) && fsImports.has(node.expression.text)) {
          const callee = fsImports.get(node.expression.text);
          if (FS_WRITE_CALLEES.has(callee)) filesystemWrites.push({ file: rel, callee });
        } else if (ts.isPropertyAccessExpression(node.expression)) {
          const owner = node.expression.expression;
          const callee = node.expression.name.text;
          if (
            ts.isIdentifier(owner) &&
            fsNamespaces.has(owner.text) &&
            FS_WRITE_CALLEES.has(callee)
          ) {
            filesystemWrites.push({ file: rel, callee });
          } else {
            const mod = requireModule(owner);
            if (mod && FS_MODULES.has(mod) && FS_WRITE_CALLEES.has(callee)) {
              filesystemWrites.push({ file: rel, callee });
            } else if (FS_WRITE_CALLEES.has(callee)) {
              filesystemWrites.push({ file: rel, callee });
            }
          }
        }
      }

      if (ts.isNewExpression(node)) {
        const dynamicTarget = dynamicCodeTarget(node.expression);
        if (dynamicTarget) dynamicCode.push({ file: rel, kind: 'new ' + dynamicTarget });
      }

      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const aliasTarget = dynamicCodeTarget(node.right);
        if (aliasTarget) dynamicCode.push({ file: rel, kind: 'alias ' + aliasTarget });
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
    processExecution: uniq(processExecution, (x) => x.file + ':' + x.module + ':' + x.callee),
    dynamicImports: uniq(dynamicImports, (x) => x.file + ':' + x.specifier),
    nonLiteralDynamicImports: uniq(nonLiteralDynamicImports, (x) => x.file + ':' + x.expression),
    dynamicCode: uniq(dynamicCode, (x) => x.file + ':' + x.kind),
    filesystemWrites: uniq(filesystemWrites, (x) => x.file + ':' + x.callee),
    staticUrlHosts: [...staticUrlHosts].sort(),
    networkUrlEnvVars: [...networkUrlEnvVars].sort(),
  };
}

export function extractImplicitAuthScopesFromSource(source, path = 'src/server.ts') {
  const sf = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const candidates = new Map();
  const usedScopeSets = new Set();
  const inlineScopes = new Set();
  const addedScopes = new Map();

  function setInventory(node) {
    const inventory = { literals: [], dynamic: [] };
    if (
      !node ||
      !ts.isNewExpression(node) ||
      !ts.isIdentifier(node.expression) ||
      node.expression.text !== 'Set'
    ) {
      return inventory;
    }
    const first = node.arguments?.[0];
    if (!first || !ts.isArrayLiteralExpression(first)) return inventory;
    for (const element of first.elements) {
      if (ts.isStringLiteralLike(element)) inventory.literals.push(element.text);
      else if (!ts.isSpreadElement(element))
        inventory.dynamic.push(`<dynamic:${element.getText(sf)}>`);
    }
    return inventory;
  }

  function findScopeSetReferences(node) {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'Array' &&
      node.expression.name.text === 'from' &&
      node.arguments[0]
    ) {
      const arg = node.arguments[0];
      if (ts.isIdentifier(arg)) {
        usedScopeSets.add(arg.text);
      } else {
        const inventory = setInventory(arg);
        for (const scope of inventory.literals) inlineScopes.add(scope);
        for (const scope of inventory.dynamic) inlineScopes.add(scope);
      }
    }
    ts.forEachChild(node, findScopeSetReferences);
  }

  function visit(node) {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const inventory = setInventory(node.initializer);
      if (inventory.literals.length || inventory.dynamic.length) {
        candidates.set(node.name.text, [...inventory.literals, ...inventory.dynamic]);
      }
    }

    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.name.text === 'add' &&
      node.arguments[0]
    ) {
      const name = node.expression.expression.text;
      const value = ts.isStringLiteralLike(node.arguments[0])
        ? node.arguments[0].text
        : `<dynamic:${node.arguments[0].getText(sf)}>`;
      const values = addedScopes.get(name) ?? [];
      values.push(value);
      addedScopes.set(name, values);
    }

    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'set' &&
      node.arguments[0] &&
      ts.isStringLiteralLike(node.arguments[0]) &&
      node.arguments[0].text === 'scope' &&
      node.arguments[1]
    ) {
      findScopeSetReferences(node.arguments[1]);
    }

    ts.forEachChild(node, visit);
  }

  visit(sf);

  const scopes = new Set(inlineScopes);
  for (const name of usedScopeSets) {
    for (const scope of candidates.get(name) ?? []) scopes.add(scope);
    for (const scope of addedScopes.get(name) ?? []) scopes.add(scope);
  }
  return [...scopes].sort();
}

function extractImplicitAuthScopes() {
  const path = 'src/server.ts';
  return extractImplicitAuthScopesFromSource(readFileSync(path, 'utf8'), path);
}

function extractCloudNetworkHosts() {
  const path = 'src/cloud-config.ts';
  const source = readFileSync(path, 'utf8');
  const sf = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const hosts = new Set();

  function visit(node) {
    if (
      ts.isPropertyAssignment(node) &&
      ((ts.isIdentifier(node.name) && ['authority', 'graphApi'].includes(node.name.text)) ||
        (ts.isStringLiteral(node.name) && ['authority', 'graphApi'].includes(node.name.text))) &&
      ts.isStringLiteralLike(node.initializer)
    ) {
      try {
        hosts.add(new URL(node.initializer.text).hostname.toLowerCase());
      } catch {
        // Invalid endpoint literals are caught by runtime/config tests; this is inventory only.
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sf);
  return [...hosts].sort();
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
      listCriticalFiles().map((path) => [path, sha256File(path)])
    ),
    mcpInstructionsSha256: sha256File('src/mcp-instructions.ts'),
    endpointsSha256: sha256File('src/endpoints.json'),
    endpointCount: endpoints.length,
    graphScopes: [...scopes].sort(),
    implicitAuthScopes: extractImplicitAuthScopes(),
    writeLikeScopes: [...scopes]
      .filter((scope) => /(Write|Send|Create|Delete|Manage)/.test(scope))
      .sort(),
    writeCapableTools: [...new Set(writeCapableTools)].sort(),
    toolFingerprints,
    staticUrlHosts: scan.staticUrlHosts,
    cloudNetworkHosts: extractCloudNetworkHosts(),
    networkUrlEnvVars: scan.networkUrlEnvVars,
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

  if (policy.schemaVersion !== 1)
    failures.push(`unsupported policy schemaVersion ${policy.schemaVersion}`);

  const graphScopeDiff = diffSet(policy.approvedGraphScopes, snapshot.graphScopes);
  if (graphScopeDiff.added.length) {
    failures.push(`unapproved Graph scopes: ${graphScopeDiff.added.join(', ')}`);
  }

  const implicitScopeDiff = diffSet(policy.approvedImplicitAuthScopes, snapshot.implicitAuthScopes);
  if (implicitScopeDiff.added.length) {
    failures.push('unapproved implicit auth scopes: ' + implicitScopeDiff.added.join(', '));
  }
  if (implicitScopeDiff.removed.length) {
    failures.push(
      'approved implicit auth scopes missing from source: ' + implicitScopeDiff.removed.join(', ')
    );
  }
  if (snapshot.implicitAuthScopes.length === 0) {
    failures.push('implicit auth scope inventory unexpectedly empty');
  }

  const hostDiff = diffSet(policy.approvedCloudNetworkHosts, snapshot.cloudNetworkHosts);
  if (hostDiff.added.length) {
    failures.push(`unapproved cloud network hosts: ${hostDiff.added.join(', ')}`);
  }

  const envDiff = diffSet(policy.approvedNetworkUrlEnvVars, snapshot.networkUrlEnvVars);
  if (envDiff.added.length) {
    failures.push(`unapproved URL-bearing network env vars: ${envDiff.added.join(', ')}`);
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
    allowedScopes: ['User.Read', 'Mail.Read', 'Calendars.Read', 'Chat.Read', 'Team.ReadBasic.All'],
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

  const toolKeys = [
    ...new Set([...Object.keys(expectedTools), ...Object.keys(actualTools)]),
  ].sort();
  const changedTools = toolKeys.filter((key) => expectedTools[key] !== actualTools[key]);
  if (changedTools.length) changes.push(`tool metadata changed: ${changedTools.join(', ')}`);

  for (const field of [
    'graphScopes',
    'implicitAuthScopes',
    'writeLikeScopes',
    'writeCapableTools',
    'staticUrlHosts',
    'cloudNetworkHosts',
    'networkUrlEnvVars',
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

  const fileKeys = [
    ...new Set([
      ...Object.keys(expected.criticalFileSha256 ?? {}),
      ...Object.keys(actual.criticalFileSha256 ?? {}),
    ]),
  ].sort();
  for (const file of fileKeys) {
    if (expected.criticalFileSha256?.[file] !== actual.criticalFileSha256?.[file]) {
      changes.push(`critical file changed: ${file}`);
    }
  }

  return changes;
}

export function describeBaselineDelta(before, after) {
  const lines = compareSnapshots(before, after);

  for (const field of [
    'graphScopes',
    'implicitAuthScopes',
    'cloudNetworkHosts',
    'networkUrlEnvVars',
    'writeCapableTools',
  ]) {
    const delta = diffSet(before[field] ?? [], after[field] ?? []);
    if (delta.added.length) lines.push(`${field} added: ${delta.added.join(', ')}`);
    if (delta.removed.length) lines.push(`${field} removed: ${delta.removed.join(', ')}`);
  }

  for (const [field, keyFields] of [
    ['processExecution', ['file', 'module', 'callee']],
    ['filesystemWrites', ['file', 'callee']],
    ['dynamicImports', ['file', 'specifier']],
  ]) {
    const beforeKeys = [...keys(before[field] ?? [], keyFields)].sort();
    const afterKeys = [...keys(after[field] ?? [], keyFields)].sort();
    const delta = diffSet(beforeKeys, afterKeys);
    if (delta.added.length) lines.push(`${field} added: ${delta.added.join(', ')}`);
    if (delta.removed.length) lines.push(`${field} removed: ${delta.removed.join(', ')}`);
  }

  return [...new Set(lines)];
}

function writeSummary(lines) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  const body = ['## MCP security baseline', '', ...lines.map((line) => `- ${line}`), ''].join('\n');
  writeFileSync(summaryPath, body, { flag: 'a' });
}

function main() {
  const mode = process.argv[2] ?? '--check';

  if (mode === '--report-diff') {
    const beforePath = process.argv[3];
    if (!beforePath) {
      console.error('usage: node scripts/mcp-security-snapshot.mjs --report-diff <baseline.json>');
      process.exit(2);
    }
    const before = readJson(beforePath);
    const after = readJson(BASELINE_PATH);
    const delta = describeBaselineDelta(before, after);
    if (!delta.length) {
      console.log('MCP security baseline delta: none');
      writeSummary(['baseline delta vs base: none']);
      return;
    }
    console.log('MCP security baseline delta vs base:');
    for (const line of delta) console.log(`- ${line}`);
    writeSummary(['baseline delta vs base:', ...delta]);
    return;
  }

  const snapshot = buildSnapshot();

  if (mode === '--write') {
    writeFileSync(BASELINE_PATH, JSON.stringify(snapshot, null, 2) + '\n');
    console.log(`Wrote ${BASELINE_PATH}`);
    return;
  }

  if (mode !== '--check') {
    console.error(
      'usage: node scripts/mcp-security-snapshot.mjs [--check|--write|--report-diff <baseline.json>]'
    );
    process.exit(2);
  }

  const baseline = readJson(BASELINE_PATH);
  const policy = readJson(POLICY_PATH);
  const changes = compareSnapshots(baseline, snapshot);
  const policyFailures = validatePolicy(snapshot, policy);

  const summary = [
    `endpoint count: ${snapshot.endpointCount}`,
    `Graph endpoint scopes: ${snapshot.graphScopes.length}`,
    `implicit auth scopes: ${snapshot.implicitAuthScopes.join(', ') || 'none'}`,
    `write-capable tools: ${snapshot.writeCapableTools.length}`,
    `static URL hosts: ${snapshot.staticUrlHosts.length}`,
    `cloud network hosts: ${snapshot.cloudNetworkHosts.length}`,
    `URL-bearing network env vars: ${snapshot.networkUrlEnvVars.length}`,
    `process execution capabilities: ${snapshot.processExecution.length}`,
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
