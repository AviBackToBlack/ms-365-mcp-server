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
    ...walkFiles(join(ROOT, 'src'), { includeTestSources: true }),
    ...walkFiles(join(ROOT, 'bin'), { includeTestSources: true }),
    ...walkFiles(join(ROOT, 'scripts'), { includeTestSources: true }),
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
  'WriteStream',
  'appendFile',
  'appendFileSync',
  'chmod',
  'chmodSync',
  'chown',
  'chownSync',
  'copyFile',
  'copyFileSync',
  'cp',
  'cpSync',
  'createWriteStream',
  'fchmod',
  'fchmodSync',
  'fchown',
  'fchownSync',
  'fdatasync',
  'fdatasyncSync',
  'fsync',
  'fsyncSync',
  'ftruncate',
  'ftruncateSync',
  'futimes',
  'futimesSync',
  'lchmod',
  'lchmodSync',
  'lchown',
  'lchownSync',
  'link',
  'linkSync',
  'lutimes',
  'lutimesSync',
  'mkdir',
  'mkdirSync',
  'mkdtemp',
  'mkdtempSync',
  'open',
  'openSync',
  'rename',
  'renameSync',
  'rm',
  'rmSync',
  'rmdir',
  'rmdirSync',
  'symlink',
  'symlinkSync',
  'truncate',
  'truncateSync',
  'unlink',
  'unlinkSync',
  'utimes',
  'utimesSync',
  'write',
  'writeFile',
  'writeFileSync',
  'writeSync',
  'writev',
  'writevSync',
]);

const CHILD_PROCESS_MODULES = new Set(['child_process', 'node:child_process']);
const VM_MODULES = new Set(['vm', 'node:vm']);
const WORKER_THREAD_MODULES = new Set(['worker_threads', 'node:worker_threads']);
const PROCESS_MODULES = new Set(['process', 'node:process']);
const FS_MODULES = new Set(['fs', 'node:fs', 'fs/promises', 'node:fs/promises']);
const CREATE_REQUIRE_MODULES = new Set(['module', 'node:module']);
const NETWORK_ENV_NAME_RE =
  /^[A-Z][A-Z0-9_]*(?:_URLS?|_URIS?|_ENDPOINTS?|_HOSTS?|_HOSTNAMES?|_DOMAINS?|_ORIGINS?|_URL_BASES?)$/;
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

function isTestSource(path) {
  return /(?:^|\/)[^/]+\.(?:test|spec)\.(?:ts|mts|cts|js|mjs|cjs)$/.test(
    relative(ROOT, path).replaceAll('\\', '/')
  );
}

function walkFiles(dir, { includeTestSources = false } = {}) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const st = statSync(path);
    if (st.isDirectory()) {
      out.push(...walkFiles(path, { includeTestSources }));
      continue;
    }

    const rel = relative(ROOT, path).replaceAll('\\', '/');
    if (MUTABLE_GENERATED_FILES.has(rel)) continue;
    if (CODE_EXTENSIONS.has(extname(path)) && (includeTestSources || !isTestSource(path))) {
      out.push(path);
    }
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
  const nonLiteralModuleAcquisitions = [];
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
    const processAliases = new Set(['process']);
    const getBuiltinModuleAliases = new Set();
    const envAliases = new Set();
    const globalObjectAliases = new Set(['globalThis', 'global']);

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

    function isGlobalThisObject(node) {
      const expr = unwrapExpression(node);
      return !!expr && ts.isIdentifier(expr) && globalObjectAliases.has(expr.text);
    }

    function isGlobalBuiltinObject(node, name) {
      const expr = unwrapExpression(node);
      if (!expr) return false;
      if (ts.isIdentifier(expr) && expr.text === name) return true;
      return (
        (ts.isPropertyAccessExpression(expr) &&
          isGlobalThisObject(expr.expression) &&
          expr.name.text === name) ||
        (ts.isElementAccessExpression(expr) &&
          isGlobalThisObject(expr.expression) &&
          expr.argumentExpression &&
          ts.isStringLiteralLike(expr.argumentExpression) &&
          expr.argumentExpression.text === name)
      );
    }

    function isProcessObject(node) {
      const expr = unwrapExpression(node);
      if (!expr) return false;
      if (ts.isIdentifier(expr) && processAliases.has(expr.text)) return true;
      if (
        (ts.isPropertyAccessExpression(expr) &&
          isGlobalThisObject(expr.expression) &&
          expr.name.text === 'process') ||
        (ts.isElementAccessExpression(expr) &&
          isGlobalThisObject(expr.expression) &&
          expr.argumentExpression &&
          ts.isStringLiteralLike(expr.argumentExpression) &&
          expr.argumentExpression.text === 'process')
      ) {
        return true;
      }

      const mod = requireModule(expr);
      return !!mod && PROCESS_MODULES.has(mod);
    }

    function isProcessEnvObject(node) {
      const expr = unwrapExpression(node);
      if (!expr) return false;

      function processOwner(owner) {
        if (isProcessObject(owner)) return true;
        const mod = requireModule(owner);
        return PROCESS_MODULES.has(mod);
      }

      return (
        (ts.isPropertyAccessExpression(expr) &&
          processOwner(expr.expression) &&
          expr.name.text === 'env') ||
        (ts.isElementAccessExpression(expr) &&
          processOwner(expr.expression) &&
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

    function isEnvShapedObject(node) {
      const expr = unwrapExpression(node);
      return (
        isEnvObject(expr) ||
        (expr && ts.isIdentifier(expr) && (expr.text === 'env' || expr.text === 'environment'))
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

    function literalMemberName(node) {
      const expr = unwrapExpression(node);
      if (!expr) return undefined;
      if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
      if (
        ts.isElementAccessExpression(expr) &&
        expr.argumentExpression &&
        ts.isStringLiteralLike(expr.argumentExpression)
      ) {
        return expr.argumentExpression.text;
      }
      return undefined;
    }

    function memberOwner(node) {
      const expr = unwrapExpression(node);
      if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
        return unwrapExpression(expr.expression);
      }
      return undefined;
    }

    function isCreateRequireFactory(node) {
      const expr = unwrapExpression(node);
      if (!expr) return false;
      if (ts.isIdentifier(expr) && createRequireImports.has(expr.text)) return true;
      if (literalMemberName(expr) !== 'createRequire') return false;
      const owner = memberOwner(expr);
      return (
        (!!owner && ts.isIdentifier(owner) && moduleNamespaces.has(owner.text)) ||
        CREATE_REQUIRE_MODULES.has(requireModule(owner))
      );
    }

    function requireLikeTargetKind(node) {
      const expr = unwrapExpression(node);
      if (!expr) return undefined;

      if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.CommaToken) {
        return requireLikeTargetKind(expr.right);
      }

      if (ts.isIdentifier(expr) && requireAliases.has(expr.text)) {
        return 'require';
      }
      if (ts.isIdentifier(expr) && getBuiltinModuleAliases.has(expr.text)) {
        return 'getBuiltinModule';
      }

      if (ts.isCallExpression(expr)) {
        const factory = unwrapExpression(expr.expression);
        if (isCreateRequireFactory(factory)) return 'createRequire';
        if (literalMemberName(factory) === 'bind') {
          return requireLikeTargetKind(memberOwner(factory));
        }
      }

      if (literalMemberName(expr) === 'getBuiltinModule' && isProcessObject(memberOwner(expr))) {
        return 'getBuiltinModule';
      }

      return undefined;
    }

    function appliedArgument(arrayNode) {
      const expr = unwrapExpression(arrayNode);
      if (!expr || !ts.isArrayLiteralExpression(expr) || expr.elements.length === 0) {
        return undefined;
      }
      const first = expr.elements[0];
      return ts.isSpreadElement(first) ? undefined : first;
    }

    function requireLikeCallInfo(node) {
      const call = unwrapExpression(node);
      if (!call || !ts.isCallExpression(call)) return undefined;

      const directKind = requireLikeTargetKind(call.expression);
      if (directKind) {
        return { kind: directKind, argument: call.arguments[0] };
      }

      const callee = unwrapExpression(call.expression);
      if (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) {
        const method = ts.isPropertyAccessExpression(callee)
          ? callee.name.text
          : callee.argumentExpression && ts.isStringLiteralLike(callee.argumentExpression)
            ? callee.argumentExpression.text
            : undefined;
        if (method === 'call' || method === 'apply') {
          const kind = requireLikeTargetKind(callee.expression);
          if (kind) {
            return {
              kind,
              argument: method === 'call' ? call.arguments[1] : appliedArgument(call.arguments[1]),
            };
          }
        }
      }

      if (
        literalMemberName(callee) === 'apply' &&
        isGlobalBuiltinObject(memberOwner(callee), 'Reflect') &&
        call.arguments[0]
      ) {
        const kind = requireLikeTargetKind(call.arguments[0]);
        if (kind) {
          return { kind, argument: appliedArgument(call.arguments[2]) };
        }
      }

      return undefined;
    }

    function requireModule(node) {
      const info = requireLikeCallInfo(node);
      if (!info?.argument || !ts.isStringLiteralLike(info.argument)) return undefined;
      return info.argument.text;
    }

    function bindRequiredModule(name, mod) {
      if (PROCESS_MODULES.has(mod)) {
        if (ts.isIdentifier(name)) {
          processAliases.add(name.text);
        } else if (ts.isObjectBindingPattern(name)) {
          for (const element of name.elements) {
            if (!ts.isIdentifier(element.name)) continue;
            if (element.dotDotDotToken) {
              processAliases.add(element.name.text);
              continue;
            }
            const imported = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            const normalized = imported.replace(/^['"]|['"]$/g, '');
            if (normalized === 'env') envAliases.add(element.name.text);
            if (normalized === 'getBuiltinModule') {
              getBuiltinModuleAliases.add(element.name.text);
            }
          }
        }
      }

      if (CREATE_REQUIRE_MODULES.has(mod)) {
        if (ts.isIdentifier(name)) {
          moduleNamespaces.add(name.text);
        } else if (ts.isObjectBindingPattern(name)) {
          for (const element of name.elements) {
            if (!ts.isIdentifier(element.name)) continue;
            if (element.dotDotDotToken) {
              moduleNamespaces.add(element.name.text);
              continue;
            }
            const imported = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            if (imported === 'createRequire') createRequireImports.add(element.name.text);
          }
        }
      }

      if (VM_MODULES.has(mod)) {
        dynamicCode.push({ file: rel, kind: 'module ' + mod });
      }

      if (CHILD_PROCESS_MODULES.has(mod) || WORKER_THREAD_MODULES.has(mod)) {
        if (ts.isIdentifier(name)) {
          childNamespaces.set(name.text, mod);
          processExecution.push({ file: rel, module: mod, callee: '*' });
        } else if (ts.isObjectBindingPattern(name)) {
          for (const element of name.elements) {
            if (!ts.isIdentifier(element.name)) continue;
            if (element.dotDotDotToken) {
              childNamespaces.set(element.name.text, mod);
              processExecution.push({ file: rel, module: mod, callee: '*' });
              continue;
            }
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
            if (!ts.isIdentifier(element.name)) continue;
            if (element.dotDotDotToken) {
              fsNamespaces.add(element.name.text);
              continue;
            }
            const imported = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            const local = element.name.getText(sf);
            fsImports.set(local, imported);
          }
        }
      }
    }

    function isFsNamespaceObject(node) {
      const expr = unwrapExpression(node);
      if (!expr) return false;
      if (ts.isIdentifier(expr) && fsNamespaces.has(expr.text)) return true;

      if (
        ((ts.isPropertyAccessExpression(expr) && expr.name.text === 'promises') ||
          (ts.isElementAccessExpression(expr) &&
            expr.argumentExpression &&
            ts.isStringLiteralLike(expr.argumentExpression) &&
            expr.argumentExpression.text === 'promises')) &&
        isFsNamespaceObject(expr.expression)
      ) {
        return true;
      }

      const mod = requireModule(expr);
      return !!mod && FS_MODULES.has(mod);
    }

    function fsWriteMember(node) {
      const expr = unwrapExpression(node);
      if (!expr) return undefined;

      let owner;
      let callee;
      if (ts.isPropertyAccessExpression(expr)) {
        owner = unwrapExpression(expr.expression);
        callee = expr.name.text;
      } else if (
        ts.isElementAccessExpression(expr) &&
        expr.argumentExpression &&
        ts.isStringLiteralLike(expr.argumentExpression)
      ) {
        owner = unwrapExpression(expr.expression);
        callee = expr.argumentExpression.text;
      } else {
        return undefined;
      }

      if (!FS_WRITE_CALLEES.has(callee)) return undefined;

      if (isFsNamespaceObject(owner)) return callee;

      return undefined;
    }

    function fsWriteTarget(node) {
      const expr = unwrapExpression(node);
      if (!expr) return undefined;
      if (ts.isIdentifier(expr) && fsImports.has(expr.text)) {
        const callee = fsImports.get(expr.text);
        return FS_WRITE_CALLEES.has(callee) ? callee : undefined;
      }
      if (ts.isCallExpression(expr) && literalMemberName(expr.expression) === 'bind') {
        return fsWriteTarget(memberOwner(expr.expression));
      }
      return fsWriteMember(expr);
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
        isGlobalThisObject(expr.expression) &&
        (expr.name.text === 'eval' || expr.name.text === 'Function')
      ) {
        return 'globalThis.' + expr.name.text;
      }

      if (
        ts.isElementAccessExpression(expr) &&
        isGlobalThisObject(expr.expression) &&
        expr.argumentExpression &&
        ts.isStringLiteralLike(expr.argumentExpression) &&
        (expr.argumentExpression.text === 'eval' || expr.argumentExpression.text === 'Function')
      ) {
        return "globalThis['" + expr.argumentExpression.text + "']";
      }

      if (literalMemberName(expr) === 'constructor') {
        const constructorOwner = memberOwner(expr);
        if (
          literalMemberName(constructorOwner) === 'prototype' &&
          isGlobalBuiltinObject(memberOwner(constructorOwner), 'Function')
        ) {
          return 'Function.prototype.constructor';
        }
        if (literalMemberName(constructorOwner) === 'constructor') {
          return 'constructor.constructor';
        }
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

      if (PROCESS_MODULES.has(mod)) {
        if (clause.name) processAliases.add(clause.name.text);
        if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
          processAliases.add(clause.namedBindings.name.text);
        }
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            if (el.isTypeOnly) continue;
            const imported = el.propertyName?.text ?? el.name.text;
            if (imported === 'env') envAliases.add(el.name.text);
            if (imported === 'getBuiltinModule') getBuiltinModuleAliases.add(el.name.text);
          }
        }
      }

      if (VM_MODULES.has(mod)) {
        dynamicCode.push({ file: rel, kind: 'module ' + mod });
      }

      if (CHILD_PROCESS_MODULES.has(mod) || WORKER_THREAD_MODULES.has(mod)) {
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
        stmt.moduleReference.expression
      ) {
        if (ts.isStringLiteralLike(stmt.moduleReference.expression)) {
          bindRequiredModule(stmt.name, stmt.moduleReference.expression.text);
        } else {
          nonLiteralModuleAcquisitions.push({
            file: rel,
            kind: 'importEquals',
            expression: stmt.moduleReference.expression.getText(sf),
          });
        }
      }

      if (
        ts.isExportDeclaration(stmt) &&
        !stmt.isTypeOnly &&
        stmt.moduleSpecifier &&
        ts.isStringLiteralLike(stmt.moduleSpecifier)
      ) {
        const mod = stmt.moduleSpecifier.text;

        if (VM_MODULES.has(mod)) {
          dynamicCode.push({ file: rel, kind: 'module ' + mod });
        }

        if (CHILD_PROCESS_MODULES.has(mod) || WORKER_THREAD_MODULES.has(mod)) {
          if (!stmt.exportClause || ts.isNamespaceExport(stmt.exportClause)) {
            processExecution.push({ file: rel, module: mod, callee: '*' });
          } else if (ts.isNamedExports(stmt.exportClause)) {
            for (const el of stmt.exportClause.elements) {
              if (el.isTypeOnly) continue;
              const exported = el.propertyName?.text ?? el.name.text;
              processExecution.push({ file: rel, module: mod, callee: exported });
            }
          }
        }

        if (FS_MODULES.has(mod)) {
          if (!stmt.exportClause || ts.isNamespaceExport(stmt.exportClause)) {
            filesystemWrites.push({ file: rel, callee: '*' });
          } else if (ts.isNamedExports(stmt.exportClause)) {
            for (const el of stmt.exportClause.elements) {
              if (el.isTypeOnly) continue;
              const exported = el.propertyName?.text ?? el.name.text;
              if (FS_WRITE_CALLEES.has(exported)) {
                filesystemWrites.push({ file: rel, callee: exported });
              }
            }
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
          if (element.dotDotDotToken && node.initializer && isEnvShapedObject(node.initializer)) {
            networkUrlEnvVars.add('<dynamic>');
            continue;
          }
          if (element.propertyName && ts.isComputedPropertyName(element.propertyName)) {
            if (node.initializer && isEnvShapedObject(node.initializer)) {
              networkUrlEnvVars.add('<dynamic>');
            }
            continue;
          }
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
          isProcessObject(initializer)
        ) {
          for (const element of node.name.elements) {
            if (!ts.isIdentifier(element.name)) continue;
            if (element.dotDotDotToken) {
              processAliases.add(element.name.text);
              continue;
            }
            const key = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            if (key === 'env') envAliases.add(element.name.text);
            if (key === 'getBuiltinModule') getBuiltinModuleAliases.add(element.name.text);
          }
        }

        if (
          ts.isVariableDeclaration(node) &&
          ts.isObjectBindingPattern(node.name) &&
          initializer &&
          isGlobalThisObject(initializer)
        ) {
          for (const element of node.name.elements) {
            const key = element.propertyName?.getText(sf) ?? element.name.getText(sf);
            if (key === 'process' && ts.isIdentifier(element.name)) {
              processAliases.add(element.name.text);
            }
          }
        }

        if (
          ts.isVariableDeclaration(node) &&
          ts.isIdentifier(node.name) &&
          initializer &&
          isProcessObject(initializer)
        ) {
          processAliases.add(node.name.text);
        }

        if (
          ts.isVariableDeclaration(node) &&
          ts.isIdentifier(node.name) &&
          initializer &&
          literalMemberName(initializer) === 'getBuiltinModule' &&
          isProcessObject(memberOwner(initializer))
        ) {
          getBuiltinModuleAliases.add(node.name.text);
        }

        if (
          ts.isVariableDeclaration(node) &&
          ts.isIdentifier(node.name) &&
          initializer &&
          ts.isIdentifier(initializer) &&
          getBuiltinModuleAliases.has(initializer.text)
        ) {
          getBuiltinModuleAliases.add(node.name.text);
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

        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && initializer) {
          if (ts.isIdentifier(initializer) && globalObjectAliases.has(initializer.text)) {
            globalObjectAliases.add(node.name.text);
          }
          if (ts.isIdentifier(initializer) && moduleNamespaces.has(initializer.text)) {
            moduleNamespaces.add(node.name.text);
          }
          if (ts.isIdentifier(initializer) && createRequireImports.has(initializer.text)) {
            createRequireImports.add(node.name.text);
          }
          if (ts.isIdentifier(initializer) && fsNamespaces.has(initializer.text)) {
            fsNamespaces.add(node.name.text);
          }
          if (ts.isIdentifier(initializer) && childNamespaces.has(initializer.text)) {
            childNamespaces.set(node.name.text, childNamespaces.get(initializer.text));
          }

          const boundKind =
            ts.isCallExpression(initializer) && literalMemberName(initializer.expression) === 'bind'
              ? requireLikeTargetKind(memberOwner(initializer.expression))
              : undefined;
          if (boundKind === 'require') requireAliases.add(node.name.text);
          if (boundKind === 'getBuiltinModule') getBuiltinModuleAliases.add(node.name.text);
          if (boundKind === 'createRequire') createRequireImports.add(node.name.text);
        }

        if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name) && initializer) {
          if (isGlobalThisObject(initializer)) {
            for (const element of node.name.elements) {
              if (element.dotDotDotToken && ts.isIdentifier(element.name)) {
                globalObjectAliases.add(element.name.text);
              }
            }
          }
          if (ts.isIdentifier(initializer) && moduleNamespaces.has(initializer.text)) {
            for (const element of node.name.elements) {
              if (!ts.isIdentifier(element.name)) continue;
              if (element.dotDotDotToken) moduleNamespaces.add(element.name.text);
              else {
                const key = element.propertyName?.getText(sf) ?? element.name.getText(sf);
                if (key.replace(/^['"]|['"]$/g, '') === 'createRequire') {
                  createRequireImports.add(element.name.text);
                }
              }
            }
          }
          if (isFsNamespaceObject(initializer)) {
            for (const element of node.name.elements) {
              if (element.dotDotDotToken && ts.isIdentifier(element.name)) {
                fsNamespaces.add(element.name.text);
              }
            }
          }
          if (ts.isIdentifier(initializer) && childNamespaces.has(initializer.text)) {
            for (const element of node.name.elements) {
              if (!ts.isIdentifier(element.name)) continue;
              if (element.dotDotDotToken) {
                childNamespaces.set(element.name.text, childNamespaces.get(initializer.text));
              }
            }
          }
        }

        if (
          ts.isVariableDeclaration(node) &&
          ts.isObjectBindingPattern(node.name) &&
          initializer &&
          isFsNamespaceObject(initializer)
        ) {
          for (const element of node.name.elements) {
            if (element.dotDotDotToken || !ts.isIdentifier(element.name)) continue;
            const imported = element.propertyName?.getText(sf) ?? element.name.text;
            const normalized = imported.replace(/^['"]|['"]$/g, '');
            if (FS_WRITE_CALLEES.has(normalized)) {
              fsImports.set(element.name.text, normalized);
            }
          }
        }

        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && initializer) {
          if (ts.isIdentifier(initializer) && fsImports.has(initializer.text)) {
            fsImports.set(node.name.text, fsImports.get(initializer.text));
          } else if (
            ts.isCallExpression(initializer) &&
            literalMemberName(initializer.expression) === 'bind'
          ) {
            const boundFsWrite = fsWriteTarget(memberOwner(initializer.expression));
            if (boundFsWrite) fsImports.set(node.name.text, boundFsWrite);
          } else {
            const reboundFsWrite = fsWriteMember(initializer);
            if (reboundFsWrite) fsImports.set(node.name.text, reboundFsWrite);
          }
        }

        if (
          ts.isVariableDeclaration(node) &&
          ts.isIdentifier(node.name) &&
          initializer &&
          ts.isCallExpression(initializer)
        ) {
          const callee = unwrapExpression(initializer.expression);
          if (isCreateRequireFactory(callee)) requireAliases.add(node.name.text);
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

      if (
        ts.isElementAccessExpression(node) &&
        isEnvShapedObject(node.expression) &&
        node.argumentExpression &&
        !ts.isStringLiteralLike(node.argumentExpression)
      ) {
        networkUrlEnvVars.add('<dynamic>');
      }

      if (
        (ts.isSpreadAssignment(node) || ts.isSpreadElement(node)) &&
        isEnvShapedObject(node.expression)
      ) {
        networkUrlEnvVars.add('<dynamic>');
      }

      if (ts.isForInStatement(node) && isEnvShapedObject(node.expression)) {
        networkUrlEnvVars.add('<dynamic>');
      }

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

        const requireInfo = requireLikeCallInfo(node);
        if (
          requireInfo &&
          (!requireInfo.argument || !ts.isStringLiteralLike(requireInfo.argument))
        ) {
          nonLiteralModuleAcquisitions.push({
            file: rel,
            kind: requireInfo.kind,
            expression: requireInfo.argument?.getText(sf) ?? '<dynamic-arguments>',
          });
        }

        const dynamicTarget = dynamicCodeTarget(node.expression);
        if (dynamicTarget) dynamicCode.push({ file: rel, kind: 'call ' + dynamicTarget });

        const callExpr = unwrapExpression(node.expression);
        let callOwner;
        let callMethod;
        if (ts.isPropertyAccessExpression(callExpr)) {
          callOwner = unwrapExpression(callExpr.expression);
          callMethod = callExpr.name.text;
        } else if (
          ts.isElementAccessExpression(callExpr) &&
          callExpr.argumentExpression &&
          ts.isStringLiteralLike(callExpr.argumentExpression)
        ) {
          callOwner = unwrapExpression(callExpr.expression);
          callMethod = callExpr.argumentExpression.text;
        }

        if (
          ((ts.isIdentifier(callExpr) && callExpr.text === 'structuredClone') ||
            (callOwner && callMethod === 'structuredClone' && isGlobalThisObject(callOwner))) &&
          node.arguments.some((arg) => isEnvShapedObject(arg))
        ) {
          networkUrlEnvVars.add('<dynamic>');
        }

        if (
          ts.isElementAccessExpression(callExpr) &&
          isFsNamespaceObject(callExpr.expression) &&
          callExpr.argumentExpression &&
          !ts.isStringLiteralLike(callExpr.argumentExpression)
        ) {
          filesystemWrites.push({ file: rel, callee: '<dynamic>' });
        }

        if (callOwner && callMethod) {
          if (callMethod === 'dlopen' && isProcessObject(callOwner)) {
            dynamicCode.push({ file: rel, kind: 'process.dlopen' });
          }

          const reboundFsWrite = fsWriteTarget(callOwner);
          if (reboundFsWrite && ['call', 'apply'].includes(callMethod)) {
            filesystemWrites.push({ file: rel, callee: reboundFsWrite });
          }

          const ownerTarget = dynamicCodeTarget(callOwner);
          if (ownerTarget && ['call', 'apply', 'bind'].includes(callMethod)) {
            dynamicCode.push({ file: rel, kind: callMethod + ' ' + ownerTarget });
          }
          if (
            ts.isIdentifier(callOwner) &&
            callOwner.text === 'Reflect' &&
            ['apply', 'construct'].includes(callMethod) &&
            node.arguments[0]
          ) {
            const reflectTarget = dynamicCodeTarget(node.arguments[0]);
            if (reflectTarget) {
              dynamicCode.push({
                file: rel,
                kind: 'Reflect.' + callMethod + ' ' + reflectTarget,
              });
            }
          }
          if (
            isGlobalBuiltinObject(callOwner, 'Reflect') &&
            ['apply', 'construct'].includes(callMethod) &&
            node.arguments[0]
          ) {
            const reflectFsWrite = fsWriteTarget(node.arguments[0]);
            if (reflectFsWrite) {
              filesystemWrites.push({ file: rel, callee: reflectFsWrite });
            }
          }

          const wholesaleEnvCall =
            (isGlobalBuiltinObject(callOwner, 'Object') &&
              [
                'entries',
                'keys',
                'values',
                'getOwnPropertyNames',
                'getOwnPropertySymbols',
                'getOwnPropertyDescriptor',
                'getOwnPropertyDescriptors',
                'assign',
              ].includes(callMethod)) ||
            (isGlobalBuiltinObject(callOwner, 'JSON') && callMethod === 'stringify') ||
            (isGlobalBuiltinObject(callOwner, 'Reflect') &&
              ['ownKeys', 'getOwnPropertyDescriptor'].includes(callMethod));

          if (wholesaleEnvCall && node.arguments.some((arg) => isEnvShapedObject(arg))) {
            networkUrlEnvVars.add('<dynamic>');
          }

          if (
            isGlobalBuiltinObject(callOwner, 'Reflect') &&
            callMethod === 'get' &&
            node.arguments[0] &&
            isEnvShapedObject(node.arguments[0])
          ) {
            const key = node.arguments[1];
            if (key && ts.isStringLiteralLike(key) && NETWORK_ENV_NAME_RE.test(key.text)) {
              networkUrlEnvVars.add(key.text);
            } else {
              networkUrlEnvVars.add('<dynamic>');
            }
          }
        }

        const required = requireModule(node);
        if (required && VM_MODULES.has(required)) {
          dynamicCode.push({ file: rel, kind: 'module ' + required });
        }
        if (
          required &&
          (CHILD_PROCESS_MODULES.has(required) || WORKER_THREAD_MODULES.has(required))
        ) {
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
        } else {
          const acquiredFsWrite = fsWriteTarget(node.expression);
          if (acquiredFsWrite) {
            filesystemWrites.push({ file: rel, callee: acquiredFsWrite });
          } else if (callMethod && FS_WRITE_CALLEES.has(callMethod)) {
            // Conservative name-based backstop: preserve the historical behavior
            // where any dot-style write callee is review-visible, and extend it
            // equally to string element access.
            filesystemWrites.push({ file: rel, callee: callMethod });
          }
        }
      }

      if (ts.isNewExpression(node)) {
        const dynamicTarget = dynamicCodeTarget(node.expression);
        if (dynamicTarget) dynamicCode.push({ file: rel, kind: 'new ' + dynamicTarget });

        const fsConstructor = fsWriteTarget(node.expression);
        if (fsConstructor) filesystemWrites.push({ file: rel, callee: fsConstructor });
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
    nonLiteralModuleAcquisitions: uniq(
      nonLiteralModuleAcquisitions,
      (x) => x.file + ':' + x.kind + ':' + x.expression
    ),
    dynamicCode: uniq(dynamicCode, (x) => x.file + ':' + x.kind),
    filesystemWrites: uniq(filesystemWrites, (x) => x.file + ':' + x.callee),
    staticUrlHosts: [...staticUrlHosts].sort(),
    networkUrlEnvVars: [...networkUrlEnvVars].sort(),
  };
}

function extractImplicitAuthScopeInventoryFromSource(source, path = 'src/server.ts') {
  const sf = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const candidates = new Map();
  const addedScopes = new Map();
  const sinkScopes = new Set();
  const sinkPassthroughs = new Set();

  function unwrap(node) {
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

  function dynamicMarker(node) {
    return `<dynamic:${node?.getText(sf) ?? '<missing>'}>`;
  }

  function emptyInventory(recognized = false) {
    return { scopes: [], passthroughs: [], recognized };
  }

  function mergeInventory(target, sourceInventory) {
    target.scopes.push(...sourceInventory.scopes);
    target.passthroughs.push(...sourceInventory.passthroughs);
    target.recognized ||= sourceInventory.recognized;
    return target;
  }

  function setInventory(node) {
    const expr = unwrap(node);
    if (
      !expr ||
      !ts.isNewExpression(expr) ||
      !ts.isIdentifier(expr.expression) ||
      expr.expression.text !== 'Set'
    ) {
      return emptyInventory(false);
    }

    const inventory = emptyInventory(true);
    const first = expr.arguments?.[0];
    if (!first) return inventory;

    const source = unwrap(first);
    if (!source || !ts.isArrayLiteralExpression(source)) {
      inventory.passthroughs.push(first.getText(sf));
      return inventory;
    }

    for (const element of source.elements) {
      if (ts.isStringLiteralLike(element)) {
        inventory.scopes.push(...element.text.split(/\s+/).filter(Boolean));
      } else if (ts.isSpreadElement(element)) {
        // A spread into the Set is a runtime-provided base scope collection, not
        // an implicit literal. Track its exact source separately so replacing or
        // adding a passthrough still fails closed at policy validation.
        inventory.passthroughs.push(element.expression.getText(sf));
      } else {
        inventory.scopes.push(dynamicMarker(element));
      }
    }
    return inventory;
  }

  function candidateInventory(name) {
    const candidate = candidates.get(name);
    if (!candidate) return undefined;
    const inventory = {
      scopes: [...candidate.scopes, ...(addedScopes.get(name) ?? [])],
      passthroughs: [...candidate.passthroughs],
      recognized: true,
    };
    return inventory;
  }

  function memberName(node) {
    const expr = unwrap(node);
    if (!expr) return undefined;
    if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
    if (
      ts.isElementAccessExpression(expr) &&
      expr.argumentExpression &&
      ts.isStringLiteralLike(expr.argumentExpression)
    ) {
      return expr.argumentExpression.text;
    }
    return undefined;
  }

  function memberOwner(node) {
    const expr = unwrap(node);
    if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
      return unwrap(expr.expression);
    }
    return undefined;
  }

  function serializationInventory(node) {
    const expr = unwrap(node);
    if (!expr) return { scopes: [dynamicMarker(node)], passthroughs: [], recognized: false };

    if (ts.isStringLiteralLike(expr)) {
      return {
        scopes: expr.text.split(/\s+/).filter(Boolean),
        passthroughs: [],
        recognized: true,
      };
    }

    if (ts.isIdentifier(expr)) {
      const candidate = candidateInventory(expr.text);
      if (candidate) return candidate;
      return { scopes: [dynamicMarker(expr)], passthroughs: [], recognized: false };
    }

    const directSet = setInventory(expr);
    if (directSet.recognized) return directSet;

    if (ts.isArrayLiteralExpression(expr)) {
      const inventory = emptyInventory(true);
      for (const element of expr.elements) {
        if (ts.isStringLiteralLike(element)) {
          inventory.scopes.push(...element.text.split(/\s+/).filter(Boolean));
        } else if (ts.isSpreadElement(element)) {
          const spread = unwrap(element.expression);
          if (spread && ts.isIdentifier(spread)) {
            const candidate = candidateInventory(spread.text);
            if (candidate) mergeInventory(inventory, candidate);
            else inventory.passthroughs.push(element.expression.getText(sf));
          } else {
            inventory.scopes.push(dynamicMarker(element.expression));
          }
        } else {
          inventory.scopes.push(dynamicMarker(element));
        }
      }
      return inventory;
    }

    if (ts.isCallExpression(expr)) {
      const calleeName = memberName(expr.expression);
      const owner = memberOwner(expr.expression);

      if (
        calleeName === 'from' &&
        owner &&
        ts.isIdentifier(owner) &&
        owner.text === 'Array' &&
        expr.arguments[0]
      ) {
        const arg = unwrap(expr.arguments[0]);
        if (arg && ts.isIdentifier(arg)) {
          const candidate = candidateInventory(arg.text);
          if (candidate) return candidate;
          return { scopes: [], passthroughs: [arg.getText(sf)], recognized: true };
        }
        const set = setInventory(arg);
        if (set.recognized) return set;
        return { scopes: [dynamicMarker(expr.arguments[0])], passthroughs: [], recognized: false };
      }

      if (calleeName === 'join' && owner) return serializationInventory(owner);

      if (calleeName === 'concat' && owner) {
        const inventory = serializationInventory(owner);
        for (const arg of expr.arguments) {
          const value = unwrap(arg);
          if (value && ts.isStringLiteralLike(value)) {
            inventory.scopes.push(...value.text.split(/\s+/).filter(Boolean));
          } else {
            inventory.scopes.push(dynamicMarker(arg));
          }
        }
        inventory.recognized = true;
        return inventory;
      }
    }

    return { scopes: [dynamicMarker(expr)], passthroughs: [], recognized: false };
  }

  function recordSink(value) {
    const inventory = serializationInventory(value);
    for (const scope of inventory.scopes) sinkScopes.add(scope);
    for (const sourceName of inventory.passthroughs) sinkPassthroughs.add(sourceName);
  }

  function visit(node) {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const inventory = setInventory(node.initializer);
      if (inventory.recognized) candidates.set(node.name.text, inventory);
    }

    if (ts.isCallExpression(node) && memberName(node.expression) === 'add' && node.arguments[0]) {
      const owner = memberOwner(node.expression);
      if (owner && ts.isIdentifier(owner) && candidates.has(owner.text)) {
        const value = ts.isStringLiteralLike(node.arguments[0])
          ? node.arguments[0].text
          : dynamicMarker(node.arguments[0]);
        const values = addedScopes.get(owner.text) ?? [];
        values.push(value);
        addedScopes.set(owner.text, values);
      }
    }

    if (
      ts.isCallExpression(node) &&
      ['set', 'append'].includes(memberName(node.expression)) &&
      node.arguments[0] &&
      ts.isStringLiteralLike(node.arguments[0]) &&
      node.arguments[0].text === 'scope'
    ) {
      if (node.arguments[1]) recordSink(node.arguments[1]);
      else sinkScopes.add('<dynamic:<missing>>');
    }

    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(unwrap(node.expression)) &&
      unwrap(node.expression).text === 'URLSearchParams' &&
      node.arguments?.[0]
    ) {
      const first = unwrap(node.arguments[0]);
      if (first && ts.isObjectLiteralExpression(first)) {
        for (const property of first.properties) {
          if (ts.isPropertyAssignment(property)) {
            const name = property.name.getText(sf).replace(/^['"]|['"]$/g, '');
            if (name === 'scope') recordSink(property.initializer);
          } else if (ts.isShorthandPropertyAssignment(property) && property.name.text === 'scope') {
            recordSink(property.name);
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sf);
  return {
    scopes: [...sinkScopes].sort(),
    passthroughs: [...sinkPassthroughs].sort(),
  };
}

export function extractImplicitAuthScopesFromSource(source, path = 'src/server.ts') {
  return extractImplicitAuthScopeInventoryFromSource(source, path).scopes;
}

export function extractImplicitAuthScopePassthroughsFromSource(source, path = 'src/server.ts') {
  return extractImplicitAuthScopeInventoryFromSource(source, path).passthroughs;
}

function extractImplicitAuthScopeInventory() {
  const path = 'src/server.ts';
  return extractImplicitAuthScopeInventoryFromSource(readFileSync(path, 'utf8'), path);
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
    ...walkFiles(join(ROOT, 'scripts')),
  ];

  const scan = scanCode(codeFiles);
  const implicitAuth = extractImplicitAuthScopeInventory();

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
    implicitAuthScopes: implicitAuth.scopes,
    implicitAuthScopePassthroughs: implicitAuth.passthroughs,
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
    nonLiteralModuleAcquisitions: scan.nonLiteralModuleAcquisitions,
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

  if (
    policy.approvedImplicitAuthScopes.some(
      (scope) => scope === '<dynamic>' || scope.startsWith('<dynamic:')
    )
  ) {
    failures.push('policy must not approve dynamic implicit auth scope markers');
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

  const passthroughDiff = diffSet(
    policy.approvedImplicitAuthScopePassthroughs ?? [],
    snapshot.implicitAuthScopePassthroughs ?? []
  );
  if (passthroughDiff.added.length) {
    failures.push(
      'unapproved implicit auth scope passthroughs: ' + passthroughDiff.added.join(', ')
    );
  }
  if (passthroughDiff.removed.length) {
    failures.push(
      'approved implicit auth scope passthroughs missing from source: ' +
        passthroughDiff.removed.join(', ')
    );
  }

  const hostDiff = diffSet(policy.approvedCloudNetworkHosts, snapshot.cloudNetworkHosts);
  if (hostDiff.added.length) {
    failures.push(`unapproved cloud network hosts: ${hostDiff.added.join(', ')}`);
  }

  if (policy.approvedNetworkUrlEnvVars.includes('<dynamic>')) {
    failures.push('policy must not approve the reserved <dynamic> network-env marker');
  }
  if (
    policy.approvedFilesystemWrites.some(
      (site) => site.callee === '<dynamic>' || site.callee === '*'
    )
  ) {
    failures.push('policy must not approve reserved wildcard/dynamic filesystem-write markers');
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
  if (snapshot.nonLiteralModuleAcquisitions.length) {
    failures.push(
      `non-literal module acquisitions are forbidden: ${JSON.stringify(snapshot.nonLiteralModuleAcquisitions)}`
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
    'implicitAuthScopePassthroughs',
    'writeLikeScopes',
    'writeCapableTools',
    'staticUrlHosts',
    'cloudNetworkHosts',
    'networkUrlEnvVars',
    'processExecution',
    'dynamicImports',
    'nonLiteralDynamicImports',
    'nonLiteralModuleAcquisitions',
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
    `implicit auth scope passthroughs: ${snapshot.implicitAuthScopePassthroughs.join(', ') || 'none'}`,
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
