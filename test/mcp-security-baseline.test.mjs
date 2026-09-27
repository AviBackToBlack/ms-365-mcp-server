import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  buildSnapshot,
  compareSnapshots,
  describeBaselineDelta,
  extractImplicitAuthScopesFromSource,
  scanCode,
  validatePolicy,
} from '../scripts/mcp-security-snapshot.mjs';

const baseline = JSON.parse(readFileSync('downstream/mcp-security-baseline.json', 'utf8'));
const policy = JSON.parse(readFileSync('downstream/mcp-security-policy.json', 'utf8'));

const clone = (value) => structuredClone(value);
const tempDirs = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scanFixture(source, extension = '.ts') {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-security-fixture-'));
  tempDirs.push(dir);
  const path = join(dir, 'fixture' + extension);
  writeFileSync(path, source);
  return scanCode([path]);
}

describe('MCP security baseline', () => {
  it('matches the current reviewed source and policy', () => {
    const snapshot = buildSnapshot();
    expect(compareSnapshots(baseline, snapshot)).toEqual([]);
    expect(validatePolicy(snapshot, policy)).toEqual([]);
  });

  it('rejects a new Graph permission', () => {
    const snapshot = clone(baseline);
    snapshot.graphScopes.push('Mail.SuperDangerous');
    expect(validatePolicy(snapshot, policy).join('\n')).toContain(
      'unapproved Graph scopes: Mail.SuperDangerous'
    );
  });

  it('rejects a new implicit OAuth permission', () => {
    const snapshot = clone(baseline);
    snapshot.implicitAuthScopes.push('Directory.AccessAsUser.All');
    expect(validatePolicy(snapshot, policy).join('\n')).toContain(
      'unapproved implicit auth scopes: Directory.AccessAsUser.All'
    );
  });

  it('rejects a new network destination or URL-bearing network input', () => {
    const hostSnapshot = clone(baseline);
    hostSnapshot.cloudNetworkHosts.push('example.invalid');
    expect(validatePolicy(hostSnapshot, policy).join('\n')).toContain(
      'unapproved cloud network hosts: example.invalid'
    );

    const envSnapshot = clone(baseline);
    envSnapshot.networkUrlEnvVars.push('MS365_MCP_ARBITRARY_URL');
    expect(validatePolicy(envSnapshot, policy).join('\n')).toContain(
      'unapproved URL-bearing network env vars: MS365_MCP_ARBITRARY_URL'
    );
  });

  it('rejects a new process execution capability', () => {
    const snapshot = clone(baseline);
    snapshot.processExecution.push({
      file: 'src/new-runtime.ts',
      module: 'node:child_process',
      callee: 'exec',
    });
    expect(validatePolicy(snapshot, policy).join('\n')).toContain(
      'unapproved process execution site: src/new-runtime.ts|node:child_process|exec'
    );
  });

  it('rejects a new filesystem write capability', () => {
    const snapshot = clone(baseline);
    snapshot.filesystemWrites.push({ file: 'src/new-runtime.ts', callee: 'writeFileSync' });
    expect(validatePolicy(snapshot, policy).join('\n')).toContain(
      'unapproved filesystem write site: src/new-runtime.ts|writeFileSync'
    );
  });

  it('rejects new or non-literal dynamic loading and dynamic code execution', () => {
    const importSnapshot = clone(baseline);
    importSnapshot.dynamicImports.push({
      file: 'src/new-runtime.ts',
      specifier: 'surprise-package',
    });
    expect(validatePolicy(importSnapshot, policy).join('\n')).toContain(
      'unapproved dynamic import: src/new-runtime.ts|surprise-package'
    );

    const nonLiteralSnapshot = clone(baseline);
    nonLiteralSnapshot.nonLiteralDynamicImports.push({
      file: 'src/new-runtime.ts',
      expression: 'userControlledModule',
    });
    expect(validatePolicy(nonLiteralSnapshot, policy).join('\n')).toContain(
      'non-literal dynamic imports are forbidden'
    );

    const evalSnapshot = clone(baseline);
    evalSnapshot.dynamicCode.push({ file: 'src/new-runtime.ts', kind: 'eval' });
    expect(validatePolicy(evalSnapshot, policy).join('\n')).toContain(
      'dynamic code execution is forbidden'
    );
  });

  it('detects URL-bearing env inputs across direct, element and aliased access', () => {
    const scan = scanFixture(
      [
        'const direct = process.env.MS365_MCP_PUBLIC_URL;',
        "const element = process.env['MS365_MCP_ALLOWED_REDIRECT_URIS'];",
        'const alias = process.env;',
        'const host = alias.MS365_MCP_ATTACHMENT_HOST;',
        'function config(env = process.env) {',
        '  return env.MS365_MCP_ATTACHMENT_URL_BASE;',
        '}',
      ].join('\n')
    );

    expect(scan.networkUrlEnvVars).toEqual([
      'MS365_MCP_ALLOWED_REDIRECT_URIS',
      'MS365_MCP_ATTACHMENT_HOST',
      'MS365_MCP_ATTACHMENT_URL_BASE',
      'MS365_MCP_PUBLIC_URL',
    ]);
  });

  it('detects child_process default imports and require/createRequire forms', () => {
    const scan = scanFixture(
      [
        "import cp from 'node:child_process';",
        "import { createRequire } from 'node:module';",
        "cp.execSync('echo safe-fixture');",
        'const req = createRequire(import.meta.url);',
        "const { spawnSync: run } = req('child_process');",
        "run('echo', ['safe-fixture']);",
        "const legacy = require('child_process');",
        "legacy.execFileSync('echo', ['safe-fixture']);",
        "const fs = req('node:fs');",
        "fs.writeFileSync('/tmp/security-fixture', 'x');",
      ].join('\n')
    );

    expect(scan.processExecution.some((site) => site.callee === 'execSync')).toBe(true);
    expect(scan.processExecution.some((site) => site.callee === 'spawnSync')).toBe(true);
    expect(scan.processExecution.some((site) => site.callee === 'execFileSync')).toBe(true);
    expect(scan.filesystemWrites.some((site) => site.callee === 'writeFileSync')).toBe(true);
  });

  it('detects Function/eval direct, globalThis and alias forms', () => {
    const scan = scanFixture(
      [
        "Function('return 1');",
        "globalThis.eval('1');",
        "new globalThis.Function('return 1');",
        'const indirectEval = eval;',
        "const indirectFunction = globalThis['Function'];",
        "(0, eval)('1');",
      ].join('\n')
    );

    const kinds = scan.dynamicCode.map((entry) => entry.kind);
    expect(kinds).toContain('call Function');
    expect(kinds).toContain('call globalThis.eval');
    expect(kinds).toContain('new globalThis.Function');
    expect(kinds).toContain('alias eval');
    expect(kinds).toContain("alias globalThis['Function']");
    expect(kinds.filter((kind) => kind === 'call eval').length).toBeGreaterThanOrEqual(1);
  });

  it('extracts implicit OAuth scopes without depending on the local variable name', () => {
    const scopes = extractImplicitAuthScopesFromSource(
      [
        "const renamedScopes = new Set([...baseScopes, 'User.Read', 'offline_access']);",
        "microsoftAuthUrl.searchParams.set('scope', Array.from(renamedScopes).join(' '));",
      ].join('\n')
    );
    expect(scopes).toEqual(['User.Read', 'offline_access']);
  });

  it('fails if an approved implicit OAuth scope disappears from source', () => {
    const snapshot = clone(baseline);
    snapshot.implicitAuthScopes = ['User.Read'];
    expect(validatePolicy(snapshot, policy).join('\n')).toContain(
      'approved implicit auth scopes missing from source: offline_access'
    );
  });

  it('hashes the reviewed runtime source surface and the verifier itself', () => {
    const snapshot = buildSnapshot();
    for (const path of [
      'scripts/mcp-security-snapshot.mjs',
      'src/audit-log.ts',
      'src/auth-tools.ts',
      'src/obo-client.ts',
      'src/lib/attachment-url-config.ts',
      'src/lib/cache-encryption.ts',
      'src/lib/redirect-uri-validation.ts',
      'src/lib/url-signing.ts',
    ]) {
      expect(snapshot.criticalFileSha256[path]).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('detects casted/imported/destructured/helper env inputs and plural suffixes', () => {
    const scan = scanFixture(
      [
        "import { env as importedEnv } from 'node:process';",
        'const castEnv = process.env as NodeJS.ProcessEnv;',
        'const satisfiesEnv = process.env satisfies NodeJS.ProcessEnv;',
        'const parenEnv = (process.env);',
        'const { env: destructuredEnv } = process;',
        'const a = castEnv.MS365_MCP_PROXY_URLS;',
        'const b = parenEnv.MS365_MCP_PROXY_HOSTS;',
        'const b2 = satisfiesEnv.MS365_MCP_PROXY_ENDPOINTS;',
        'const c = importedEnv.MS365_MCP_API_ENDPOINTS;',
        'const d = destructuredEnv.MS365_MCP_LOGIN_ORIGINS;',
        'function helper(env) { return env.MS365_MCP_HELPER_URL; }',
        'function destructured({ MS365_MCP_HELPER_URIS }) { return MS365_MCP_HELPER_URIS; }',
      ].join('\n')
    );

    expect(scan.networkUrlEnvVars).toEqual([
      'MS365_MCP_API_ENDPOINTS',
      'MS365_MCP_HELPER_URIS',
      'MS365_MCP_HELPER_URL',
      'MS365_MCP_LOGIN_ORIGINS',
      'MS365_MCP_PROXY_ENDPOINTS',
      'MS365_MCP_PROXY_HOSTS',
      'MS365_MCP_PROXY_URLS',
    ]);
  });

  it('detects getBuiltinModule, module.createRequire, casted require and require aliases', () => {
    const scan = scanFixture(
      [
        "import module from 'node:module';",
        'const req = module.createRequire(import.meta.url);',
        'const req2 = req;',
        "const cp = (req2('node:child_process') as any);",
        "cp.execSync('echo safe-fixture');",
        "const { execFileSync } = process.getBuiltinModule('child_process');",
        "execFileSync('echo', ['safe-fixture']);",
        "const { createRequire: makeRequire } = require('module');",
        'const req3 = makeRequire(import.meta.url);',
        "const { spawnSync } = req3('child_process');",
        "spawnSync('echo', ['safe-fixture']);",
        "process.getBuiltinModule('node:child_process').exec('echo safe-fixture');",
      ].join('\n')
    );

    for (const callee of ['execSync', 'execFileSync', 'spawnSync', 'exec']) {
      expect(scan.processExecution.some((site) => site.callee === callee)).toBe(true);
    }
  });

  it('detects fs element-access writes and local rebindings', () => {
    const fixtures = [
      {
        source: ["import * as fs from 'node:fs';", "fs['writeFileSync']('/tmp/a', 'x');"].join(
          '\n'
        ),
        callee: 'writeFileSync',
      },
      {
        source: ["import fsDefault from 'fs';", "fsDefault['appendFileSync']('/tmp/a', 'x');"].join(
          '\n'
        ),
        callee: 'appendFileSync',
      },
      {
        source: "require('fs')['writeFileSync']('/tmp/a', 'x');",
        callee: 'writeFileSync',
      },
      {
        source: "process.getBuiltinModule('node:fs')['appendFileSync']('/tmp/a', 'x');",
        callee: 'appendFileSync',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          'const { writeFileSync: write1 } = fs;',
          "write1('/tmp/a', 'x');",
        ].join('\n'),
        callee: 'writeFileSync',
      },
      {
        source: [
          "import { writeFileSync } from 'node:fs';",
          'const write2 = writeFileSync;',
          "write2('/tmp/a', 'x');",
        ].join('\n'),
        callee: 'writeFileSync',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          "const write3 = fs['writeFileSync'];",
          "write3('/tmp/a', 'x');",
        ].join('\n'),
        callee: 'writeFileSync',
      },
    ];

    for (const { source, callee } of fixtures) {
      const scan = scanFixture(source);
      expect(scan.filesystemWrites.some((site) => site.callee === callee)).toBe(true);
    }
  });

  it('detects TypeScript import-equals and child_process re-exports', () => {
    const importEquals = scanFixture(
      ["import cp = require('child_process');", "cp.execSync('echo safe-fixture');"].join('\n'),
      '.cts'
    );
    expect(importEquals.processExecution.some((site) => site.callee === '*')).toBe(true);
    expect(importEquals.processExecution.some((site) => site.callee === 'execSync')).toBe(true);

    const reexport = scanFixture("export { execSync as run } from 'child_process';");
    expect(reexport.processExecution.some((site) => site.callee === 'execSync')).toBe(true);

    const exportAll = scanFixture("export * from 'node:child_process';");
    expect(exportAll.processExecution.some((site) => site.callee === '*')).toBe(true);

    const typeOnly = scanFixture("export { type execSync } from 'child_process';");
    expect(typeOnly.processExecution).toEqual([]);

    const fsReexport = scanFixture("export { writeFileSync } from 'node:fs';");
    expect(fsReexport.filesystemWrites).toContainEqual({
      file: fsReexport.filesystemWrites[0].file,
      callee: 'writeFileSync',
    });

    const namespaceProcess = scanFixture("export * as cp from 'child_process';");
    expect(namespaceProcess.processExecution.some((site) => site.callee === '*')).toBe(true);

    const namespaceFs = scanFixture("export * as files from 'node:fs';");
    expect(namespaceFs.filesystemWrites.some((site) => site.callee === '*')).toBe(true);
  });

  it('ignores type-only builtin imports', () => {
    const scan = scanFixture(
      ["import type cp from 'child_process';", "import type * as fs from 'node:fs';"].join('\n')
    );
    expect(scan.processExecution).toEqual([]);
    expect(scan.filesystemWrites).toEqual([]);
  });

  it('detects dynamic-code call/apply/bind and Reflect.apply forms', () => {
    const scan = scanFixture(
      [
        "eval.call(null, '1');",
        "eval.apply(null, ['1']);",
        "Function.bind(null, 'return 1');",
        "Reflect.apply(eval, null, ['1']);",
      ].join('\n')
    );
    const kinds = scan.dynamicCode.map((entry) => entry.kind);
    expect(kinds).toContain('call eval');
    expect(kinds).toContain('apply eval');
    expect(kinds).toContain('bind Function');
    expect(kinds).toContain('Reflect.apply eval');
  });

  it('extracts literal Set.add scopes and fails closed on dynamic implicit scopes', () => {
    const literalScopes = extractImplicitAuthScopesFromSource(
      [
        "const granted = new Set([...baseScopes, 'User.Read']);",
        "granted.add('offline_access');",
        "microsoftAuthUrl.searchParams.set('scope', Array.from(granted).join(' '));",
      ].join('\n')
    );
    expect(literalScopes).toEqual(['User.Read', 'offline_access']);

    const dynamicScopes = extractImplicitAuthScopesFromSource(
      [
        "const granted = new Set([...baseScopes, 'User.Read', 'offline_access']);",
        'granted.add(extraScope);',
        "microsoftAuthUrl.searchParams.set('scope', Array.from(granted).join(' '));",
      ].join('\n')
    );
    expect(dynamicScopes).toContain('<dynamic:extraScope>');

    const snapshot = clone(baseline);
    snapshot.implicitAuthScopes = dynamicScopes;
    expect(validatePolicy(snapshot, policy).join('\n')).toContain(
      'unapproved implicit auth scopes: <dynamic:extraScope>'
    );
  });

  it('hashes tracked generated runtime files and build/security scripts', () => {
    const snapshot = buildSnapshot();
    for (const path of [
      'src/generated/client-beta.ts',
      'src/generated/endpoint-types.ts',
      'src/generated/hack.ts',
      'bin/modules/generate-mcp-tools.mjs',
      'scripts/mcp-security-snapshot.mjs',
      'scripts/verify-npm-audit.mjs',
      'scripts/verify-supply-chain.mjs',
    ]) {
      expect(snapshot.criticalFileSha256[path]).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(snapshot.criticalFileSha256['src/generated/client.ts']).toBeUndefined();
  });

  it('fails closed on node:vm and worker_threads execution modules', () => {
    const scan = scanFixture(
      [
        "import vm from 'node:vm';",
        "import { Worker } from 'node:worker_threads';",
        "vm.runInNewContext('1');",
        "new Worker('1', { eval: true });",
        "const vm2 = process.getBuiltinModule('vm');",
        "vm2.compileFunction('return 1', []);",
      ].join('\n')
    );

    expect(scan.dynamicCode.some((entry) => entry.kind === 'module node:vm')).toBe(true);
    expect(scan.dynamicCode.some((entry) => entry.kind === 'module vm')).toBe(true);
    expect(
      scan.processExecution.some(
        (entry) => entry.module === 'node:worker_threads' && entry.callee === 'Worker'
      )
    ).toBe(true);
  });

  it('fails closed on computed or wholesale environment access', () => {
    const scan = scanFixture(
      [
        'const env = process.env;',
        'const key = getName();',
        'const a = env[key];',
        'const b = { ...process.env };',
        'const c = Object.entries(env);',
        'const d = JSON.stringify(process.env);',
        'const e = Object.getOwnPropertyDescriptors(process.env);',
        "const f = Reflect.get(process.env, 'MS365_MCP_KEYVAULT_URL');",
        'const g = Reflect.get(env, key);',
        "const h = Object.getOwnPropertyDescriptor(env, 'MS365_MCP_PUBLIC_URL');",
        'const i = Reflect.getOwnPropertyDescriptor(env, key);',
        'for (const k in env) { void k; }',
        'const { [key]: value } = env;',
        'const { ...rest } = process.env;',
      ].join('\n')
    );

    expect(scan.networkUrlEnvVars).toContain('<dynamic>');
    expect(scan.networkUrlEnvVars).toContain('MS365_MCP_KEYVAULT_URL');

    const snapshot = clone(baseline);
    snapshot.networkUrlEnvVars = [...new Set([...baseline.networkUrlEnvVars, '<dynamic>'])].sort();
    expect(validatePolicy(snapshot, policy).join('\n')).toContain(
      'unapproved URL-bearing network env vars: <dynamic>'
    );
  });

  it('detects process/getBuiltinModule aliases and Reflect.construct dynamic code', () => {
    const scan = scanFixture(
      [
        "import proc from 'node:process';",
        'const p = proc;',
        'const { getBuiltinModule: destructuredGetBuiltin } = p;',
        'const getBuiltin = p.getBuiltinModule;',
        'const getBuiltin2 = getBuiltin;',
        "const { execSync } = getBuiltin2('child_process');",
        "destructuredGetBuiltin('node:worker_threads');",
        "execSync('echo safe-fixture');",
        'const { process: globalProcess } = globalThis;',
        "globalProcess.getBuiltinModule('node:worker_threads');",
        "globalThis.process.getBuiltinModule('node:worker_threads');",
        "global.eval('1');",
        "global['Function']('return 1');",
        "Reflect['apply'](eval, null, ['1']);",
        "Reflect.construct(Function, ['return 1']);",
        'const F = Function.prototype.constructor;',
        "const requiredEnv = require('node:process').env;",
        'const dynamicKey = getName();',
        'void requiredEnv[dynamicKey];',
      ].join('\n')
    );

    expect(scan.processExecution.some((entry) => entry.callee === 'execSync')).toBe(true);
    expect(scan.processExecution.some((entry) => entry.module === 'node:worker_threads')).toBe(
      true
    );
    expect(scan.networkUrlEnvVars).toContain('<dynamic>');
    const kinds = scan.dynamicCode.map((entry) => entry.kind);
    expect(kinds).toContain('call globalThis.eval');
    expect(kinds).toContain("call globalThis['Function']");
    expect(kinds).toContain('Reflect.apply eval');
    expect(kinds).toContain('Reflect.construct Function');
    expect(kinds).toContain('alias Function.prototype.constructor');
  });

  it('does not classify unrelated computed parameter destructuring as dynamic env access', () => {
    const scan = scanFixture('function pick({ [key]: value }) { return value; }');
    expect(scan.networkUrlEnvVars).not.toContain('<dynamic>');
  });

  it('intentionally inventories env-style names even on non-env owners', () => {
    const scan = scanFixture(
      [
        'const a = config.SOME_SERVICE_URL;',
        "const b = row['REDIRECT_URIS'];",
        'const c = config.INTERNAL_HOSTNAME;',
        'const d = config.SERVICE_DOMAIN;',
      ].join('\n')
    );
    expect(scan.networkUrlEnvVars).toEqual([
      'INTERNAL_HOSTNAME',
      'REDIRECT_URIS',
      'SERVICE_DOMAIN',
      'SOME_SERVICE_URL',
    ]);
  });

  it('includes the verifier in its own capability boundary', () => {
    const snapshot = buildSnapshot();
    expect(snapshot.filesystemWrites).toContainEqual({
      file: 'scripts/mcp-security-snapshot.mjs',
      callee: 'writeFileSync',
    });
  });

  it('locks the first-production runtime profile', () => {
    const changed = clone(policy);
    changed.productionProfile.readOnly = false;
    expect(validatePolicy(baseline, changed)).toContain(
      'productionProfile differs from the approved first-production contract'
    );
  });

  it('reports changed tool metadata as an explicit review delta', () => {
    const changed = clone(baseline);
    const tool = Object.keys(changed.toolFingerprints)[0];
    changed.toolFingerprints[tool] = '0'.repeat(64);
    const delta = describeBaselineDelta(baseline, changed).join('\n');
    expect(delta).toContain('tool metadata changed:');
    expect(delta).toContain(tool);
  });
});
