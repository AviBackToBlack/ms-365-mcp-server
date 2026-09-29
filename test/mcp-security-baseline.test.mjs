import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  buildSnapshot,
  compareSnapshots,
  describeBaselineDelta,
  extractImplicitAuthScopesFromSource,
  extractImplicitAuthScopePassthroughsFromSource,
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

  it('covers the reviewed node:fs mutation vocabulary', () => {
    const scan = scanFixture(
      [
        "import * as fs from 'node:fs';",
        "fs.linkSync('/tmp/a', '/tmp/b');",
        "fs.symlinkSync('/tmp/a', '/tmp/c');",
        "fs.truncateSync('/tmp/a', 0);",
        "fs.cpSync('/tmp/a', '/tmp/d');",
        "fs.mkdtempSync('/tmp/prefix-');",
        "fs.rmdirSync('/tmp/d');",
        "fs.writeSync(1, 'x');",
        "fs.writevSync(1, [Buffer.from('x')]);",
        "fs.chownSync('/tmp/a', 0, 0);",
        "fs.utimesSync('/tmp/a', new Date(), new Date());",
        'fs.fchmodSync(1, 0o600);',
        "new fs.WriteStream('/tmp/e');",
      ].join('\n')
    );

    for (const callee of [
      'linkSync',
      'symlinkSync',
      'truncateSync',
      'cpSync',
      'mkdtempSync',
      'rmdirSync',
      'writeSync',
      'writevSync',
      'chownSync',
      'utimesSync',
      'fchmodSync',
      'WriteStream',
    ]) {
      expect(scan.filesystemWrites.some((site) => site.callee === callee)).toBe(true);
    }
  });

  it('fails closed on structuredClone of an env-shaped object', () => {
    const scan = scanFixture(
      ['const env = process.env;', 'const copy = structuredClone(env);', 'void copy;'].join('\n')
    );
    expect(scan.networkUrlEnvVars).toContain('<dynamic>');
  });

  it('does not let a runtime file hide under __tests__', () => {
    const dir = join(process.cwd(), 'src', '__tests__');
    const path = join(dir, '__sm4_runtime_probe.ts');
    writeFileSync(
      path,
      [
        "import { writeFileSync } from 'node:fs';",
        "writeFileSync('/tmp/sm4-runtime-probe', 'x');",
      ].join('\n')
    );

    try {
      const snapshot = buildSnapshot();
      expect(snapshot.criticalFileSha256['src/__tests__/__sm4_runtime_probe.ts']).toMatch(
        /^[0-9a-f]{64}$/
      );
      expect(snapshot.filesystemWrites).toContainEqual({
        file: 'src/__tests__/__sm4_runtime_probe.ts',
        callee: 'writeFileSync',
      });
    } finally {
      rmSync(path, { force: true });
    }
  });

  it('forbids non-literal require-like module acquisitions', () => {
    const fixtures = [
      {
        source: "const name = 'v' + 'm'; require(name);",
        kind: 'require',
      },
      {
        source: [
          "import { createRequire } from 'node:module';",
          'const req = createRequire(import.meta.url);',
          "const name = 'v' + 'm';",
          'req(name);',
        ].join('\n'),
        kind: 'require',
      },
      {
        source: [
          "import * as moduleNs from 'node:module';",
          'const req = moduleNs.createRequire(import.meta.url);',
          "const name = 'v' + 'm';",
          'req(name);',
        ].join('\n'),
        kind: 'require',
      },
      {
        source: [
          "import { createRequire } from 'node:module';",
          "const name = 'v' + 'm';",
          'createRequire(import.meta.url)(name);',
        ].join('\n'),
        kind: 'createRequire',
      },
      {
        source: [
          "import * as moduleNs from 'node:module';",
          "const name = 'v' + 'm';",
          'moduleNs.createRequire(import.meta.url)(name);',
        ].join('\n'),
        kind: 'createRequire',
      },
      {
        source: ["const name = 'child' + '_process';", 'process.getBuiltinModule(name);'].join(
          '\n'
        ),
        kind: 'getBuiltinModule',
      },
      {
        source: [
          'const getBuiltin = process.getBuiltinModule;',
          "const name = 'v' + 'm';",
          'getBuiltin(name);',
        ].join('\n'),
        kind: 'getBuiltinModule',
      },
    ];

    for (const { source, kind } of fixtures) {
      const scan = scanFixture(source);
      expect(scan.nonLiteralModuleAcquisitions).toHaveLength(1);
      expect(scan.nonLiteralModuleAcquisitions[0].kind).toBe(kind);
    }

    const scan = scanFixture("const name = 'v' + 'm'; process.getBuiltinModule(name);");
    const snapshot = clone(baseline);
    snapshot.nonLiteralModuleAcquisitions = scan.nonLiteralModuleAcquisitions;
    expect(validatePolicy(snapshot, policy).join('\n')).toContain(
      'non-literal module acquisitions are forbidden'
    );
  });

  it('binds require-acquired process modules and preserves the vm ban', () => {
    const fixtures = [
      "require('node:process').getBuiltinModule('vm');",
      "const p = require('node:process'); p.getBuiltinModule('vm');",
      "const { getBuiltinModule } = require('node:process'); getBuiltinModule('vm');",
    ];

    for (const source of fixtures) {
      const scan = scanFixture(source);
      expect(scan.dynamicCode.some((site) => site.kind === 'module vm')).toBe(true);
    }
  });

  it('normalizes require-family indirect calls and node:module createRequire receivers', () => {
    const vmFixtures = [
      "require.call(null, 'vm');",
      "require.apply(null, ['vm']);",
      "Reflect.apply(require, null, ['vm']);",
      "(0, require)('vm');",
    ];

    for (const source of vmFixtures) {
      const scan = scanFixture(source);
      expect(scan.dynamicCode.some((site) => site.kind === 'module vm')).toBe(true);
    }

    const dynamicFixtures = [
      [
        "const r = require('node:module').createRequire(import.meta.url);",
        "const name = 'v' + 'm';",
        'r(name);',
      ].join('\n'),
      [
        "const name = 'v' + 'm';",
        "require('node:module').createRequire(import.meta.url)(name);",
      ].join('\n'),
      "const name = 'v' + 'm'; import x = require(name);",
    ];

    for (const source of dynamicFixtures) {
      const scan = scanFixture(source);
      expect(scan.nonLiteralModuleAcquisitions.length).toBeGreaterThan(0);
    }
  });

  it('closes require-family one-hop alias and bind escapes', () => {
    const fixtures = [
      "import proc from 'node:process'; const g = proc['getBuiltinModule']; g('vm');",
      "import * as m from 'node:module'; const m2 = m; m2.createRequire(import.meta.url)('vm');",
      "import * as m from 'node:module'; const { createRequire } = m; createRequire(import.meta.url)('vm');",
      "import { createRequire } from 'node:module'; const cr = createRequire; cr(import.meta.url)('vm');",
      "import * as m from 'node:module'; m['createRequire'](import.meta.url)('vm');",
      "require.bind(null)('vm');",
      "Reflect['apply'](require, null, ['vm']);",
      "import proc from 'node:process'; proc.getBuiltinModule.bind(proc)('vm');",
      "const { ...rest } = require('node:process'); rest.getBuiltinModule('vm');",
    ];

    for (const source of fixtures) {
      const scan = scanFixture(source);
      expect(scan.dynamicCode.some((site) => site.kind === 'module vm')).toBe(true);
    }
  });

  it('preserves bound require-family arguments and bound createRequire factories', () => {
    const fixtures = [
      "require.bind(null, 'vm')('ignored');",
      "const r = require.bind(null, 'vm'); r('ignored');",
      "import proc from 'node:process'; proc.getBuiltinModule.bind(proc, 'vm')('ignored');",
      "import { createRequire } from 'node:module'; createRequire(import.meta.url).bind(null, 'vm')('ignored');",
      "import { createRequire } from 'node:module'; createRequire.bind(null)(import.meta.url)('vm');",
      "import * as m from 'node:module'; m.createRequire.bind(m)(import.meta.url)('vm');",
      "import { createRequire } from 'node:module'; const f = createRequire.bind(null); f(import.meta.url)('vm');",
    ];

    for (const source of fixtures) {
      const scan = scanFixture(source);
      expect(scan.dynamicCode.some((site) => site.kind === 'module vm')).toBe(true);
    }

    const dynamicBound = scanFixture("const name = getName(); require.bind(null, name)('x');");
    expect(dynamicBound.nonLiteralModuleAcquisitions.length).toBeGreaterThan(0);
  });

  it('normalizes global Reflect dynamic-code calls and single-hop constructors', () => {
    const scan = scanFixture(
      [
        "globalThis.Reflect.apply(eval, null, ['1']);",
        "const g = globalThis; g['Reflect'].construct(Function, ['return 1']);",
        "const f = () => {}; f.constructor('return 1');",
        "(async () => {})['constructor']('return 1');",
      ].join('\n')
    );
    const kinds = scan.dynamicCode.map((entry) => entry.kind);
    expect(kinds).toContain('Reflect.apply eval');
    expect(kinds).toContain('Reflect.construct Function');
    expect(kinds).toContain('call constructor');
  });

  it('fails closed on computed process/module namespace member acquisition', () => {
    const fixtures = [
      "const k = getMethod(); process[k]('vm');",
      "const k = getMethod(); const g = process[k]; g('vm');",
      "import * as m from 'node:module'; const k = getMethod(); m[k](import.meta.url);",
    ];

    for (const source of fixtures) {
      const scan = scanFixture(source);
      expect(scan.nonLiteralModuleAcquisitions.length).toBeGreaterThan(0);
    }
  });

  it('propagates fs, child-process and global-object aliases conservatively', () => {
    const fsBound = scanFixture(
      "import * as fs from 'node:fs'; const w = fs.writeFileSync.bind(fs); w('/tmp/a', 'x');"
    );
    expect(fsBound.filesystemWrites.some((site) => site.callee === 'writeFileSync')).toBe(true);

    const fsAlias = scanFixture(
      "import * as fs from 'node:fs'; const fs2 = fs; const k = getMethod(); fs2[k]('/tmp/a', 'x');"
    );
    expect(fsAlias.filesystemWrites.some((site) => site.callee === '<dynamic>')).toBe(true);

    const childAlias = scanFixture(
      "import * as cp from 'node:child_process'; const cp2 = cp; cp2.execSync('x');"
    );
    expect(childAlias.processExecution.some((site) => site.callee === 'execSync')).toBe(true);

    const globalAlias = scanFixture(
      "const g = globalThis; g.eval('1'); g.Object.keys(process.env); g.process.env[getKey()];"
    );
    expect(globalAlias.dynamicCode.some((site) => site.kind === 'call globalThis.eval')).toBe(true);
    expect(globalAlias.networkUrlEnvVars).toContain('<dynamic>');
  });

  it('normalizes named-default module, fs, and execution namespaces', () => {
    const moduleScan = scanFixture(
      "import { default as m } from 'node:module'; m.createRequire(import.meta.url)('vm');"
    );
    expect(moduleScan.dynamicCode.some((entry) => entry.kind === 'module vm')).toBe(true);

    const fsScan = scanFixture(
      "import { default as f } from 'node:fs'; const k = getMethod(); f[k]('/tmp/a', 'x');"
    );
    expect(fsScan.filesystemWrites.some((entry) => entry.callee === '<dynamic>')).toBe(true);

    const childScan = scanFixture(
      "import { default as cp } from 'node:child_process'; cp.execSync('x');"
    );
    expect(
      childScan.processExecution.some(
        (entry) => entry.module === 'node:child_process' && entry.callee === 'execSync'
      )
    ).toBe(true);
  });

  it('preserves createRequire factory results through call/apply/Reflect.apply', () => {
    const fixtures = [
      "import { createRequire } from 'node:module'; const r = createRequire.call(null, import.meta.url); r('vm');",
      "import { createRequire } from 'node:module'; const r = createRequire.apply(null, [import.meta.url]); r('vm');",
      "import * as m from 'node:module'; const r = m.createRequire.call(m, import.meta.url); r('vm');",
      "import { createRequire } from 'node:module'; const r = Reflect.apply(createRequire, null, [import.meta.url]); r('vm');",
      "import { createRequire } from 'node:module'; createRequire.call(null, import.meta.url)('vm');",
    ];

    for (const source of fixtures) {
      const scan = scanFixture(source);
      expect(scan.dynamicCode.some((entry) => entry.kind === 'module vm')).toBe(true);
    }
  });

  it('normalizes computed literal binding keys and fails closed on dynamic binding keys', () => {
    const literal = scanFixture(
      [
        "const { ['getBuiltinModule']: g } = process; g('node:vm');",
        "import * as m from 'node:module'; const { ['createRequire']: c } = m; c(import.meta.url)('vm');",
        "const { ['eval']: e } = globalThis; void e;",
        "const { ['apply']: a } = Reflect; a(eval, null, ['1']);",
        "const { ['env']: e2 } = process; e2['SERVICE_URL'];",
        "import * as fs from 'node:fs'; const { ['writeFileSync']: w } = fs; w('/tmp/a', 'x');",
      ].join('\n')
    );
    expect(literal.dynamicCode.some((entry) => entry.kind === 'module node:vm')).toBe(true);
    expect(literal.dynamicCode.some((entry) => entry.kind === 'module vm')).toBe(true);
    expect(literal.dynamicCode.some((entry) => entry.kind === 'alias globalThis.eval')).toBe(true);
    expect(literal.dynamicCode.some((entry) => entry.kind === 'Reflect.apply eval')).toBe(true);
    expect(literal.networkUrlEnvVars).toContain('SERVICE_URL');
    expect(literal.filesystemWrites.some((entry) => entry.callee === 'writeFileSync')).toBe(true);

    const dynamic = scanFixture(
      [
        'const k = getKey();',
        'const { [k]: p } = process;',
        "import * as m from 'node:module'; const { [k]: c } = m;",
        "import * as fs from 'node:fs'; const { [k]: w } = fs;",
        'const { [k]: x } = globalThis;',
      ].join('\n')
    );
    expect(dynamic.nonLiteralModuleAcquisitions.length).toBeGreaterThan(0);
    expect(dynamic.filesystemWrites.some((entry) => entry.callee === '<dynamic>')).toBe(true);
    expect(dynamic.dynamicCode.length).toBeGreaterThan(0);
  });

  it('marks computed process/module members regardless of AST nesting position', () => {
    const fixtures = [
      'const k = getMethod(); const r = process[k].bind(process);',
      'const k = getMethod(); f(process[k]);',
      'const k = getMethod(); const g = a ?? process[k];',
      'const k = getMethod(); function x() { return process[k]; }',
      'const k = getMethod(); x = process[k];',
    ];

    for (const source of fixtures) {
      const scan = scanFixture(source);
      expect(
        scan.nonLiteralModuleAcquisitions.some((entry) => entry.kind === 'computed-member')
      ).toBe(true);
    }
  });

  it('preserves member precision for child namespace destructuring and nested env bindings', () => {
    const child = scanFixture(
      "import * as cp from 'node:child_process'; const { execSync } = cp; execSync('x');"
    );
    expect(
      child.processExecution.some(
        (entry) => entry.module === 'node:child_process' && entry.callee === 'execSync'
      )
    ).toBe(true);

    const env = scanFixture('const { env: { SERVICE_URL } } = process; void SERVICE_URL;');
    expect(env.networkUrlEnvVars).toContain('SERVICE_URL');
  });

  it('normalizes builtin aliases, global destructuring, and env writes', () => {
    const scan = scanFixture(
      [
        "const R = Reflect; R.apply(eval, null, ['1']);",
        "const { apply } = Reflect; apply(eval, null, ['1']);",
        'const { keys } = Object; keys(process.env);',
        'const sc = structuredClone; sc(process.env);',
        'const g = globalThis; const { eval: e } = g; void e;',
        "Reflect.set(process.env, getKey(), 'x');",
        'Reflect.deleteProperty(process.env, getKey());',
        "Object.defineProperty(process.env, 'X_URL', { value: 'x' });",
      ].join('\n')
    );

    const kinds = scan.dynamicCode.map((entry) => entry.kind);
    expect(kinds).toContain('Reflect.apply eval');
    expect(kinds).toContain('alias globalThis.eval');
    expect(scan.networkUrlEnvVars).toContain('<dynamic>');
  });

  it('tracks named-default process imports and side-effect execution-module imports', () => {
    const processScan = scanFixture(
      "import { default as p } from 'node:process'; p.getBuiltinModule('vm');"
    );
    expect(processScan.dynamicCode.some((entry) => entry.kind === 'module vm')).toBe(true);

    const vmScan = scanFixture("import 'node:vm';");
    expect(vmScan.dynamicCode.some((entry) => entry.kind === 'module node:vm')).toBe(true);

    const dynamicVmScan = scanFixture("void import('node:vm');");
    expect(dynamicVmScan.dynamicCode.some((entry) => entry.kind === 'module node:vm')).toBe(true);

    const childScan = scanFixture("import 'node:child_process';");
    expect(
      childScan.processExecution.some(
        (entry) => entry.module === 'node:child_process' && entry.callee === '*'
      )
    ).toBe(true);
  });

  it('forbids constructor-chain dynamic code and process.dlopen', () => {
    const scan = scanFixture(
      [
        "globalThis.Function.prototype.constructor('return 1');",
        "({}).constructor.constructor('return 1');",
        "globalThis['Function']['prototype']['constructor']('return 1');",
        "({})['constructor']['constructor']('return 1');",
        "process.dlopen(module, '/tmp/native.node');",
      ].join('\n')
    );
    const kinds = scan.dynamicCode.map((entry) => entry.kind);
    expect(kinds).toContain('call Function.prototype.constructor');
    expect(kinds).toContain('call constructor.constructor');
    expect(kinds).toContain('process.dlopen');
  });

  it('tracks bare WriteStream construction and fs.promises/rebound calls', () => {
    const fixtures = [
      {
        source: ["import { WriteStream } from 'node:fs';", "new WriteStream('/tmp/a');"].join('\n'),
        callee: 'WriteStream',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          'const { WriteStream: WS } = fs;',
          "new WS('/tmp/a');",
        ].join('\n'),
        callee: 'WriteStream',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          'const { writeFile } = fs.promises;',
          "writeFile('/tmp/a', 'x');",
        ].join('\n'),
        callee: 'writeFile',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          "fs.writeFileSync.call(fs, '/tmp/a', 'x');",
        ].join('\n'),
        callee: 'writeFileSync',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          "fs.writeFileSync.bind(fs)('/tmp/a', 'x');",
        ].join('\n'),
        callee: 'writeFileSync',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          "fs.writeFileSync.apply(fs, ['/tmp/a', 'x']);",
        ].join('\n'),
        callee: 'writeFileSync',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          "Reflect.apply(fs.writeFileSync, fs, ['/tmp/a', 'x']);",
        ].join('\n'),
        callee: 'writeFileSync',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          "Reflect.construct(fs.WriteStream, ['/tmp/a']);",
        ].join('\n'),
        callee: 'WriteStream',
      },
      {
        source: [
          "import { writeFileSync } from 'node:fs';",
          "writeFileSync.call(null, '/tmp/a', 'x');",
        ].join('\n'),
        callee: 'writeFileSync',
      },
      {
        source: [
          "import * as fs from 'node:fs';",
          "const { writeFile } = fs['promises'];",
          "writeFile('/tmp/a', 'x');",
        ].join('\n'),
        callee: 'writeFile',
      },
    ];

    for (const { source, callee } of fixtures) {
      const scan = scanFixture(source);
      expect(scan.filesystemWrites.some((site) => site.callee === callee)).toBe(true);
    }

    const dynamicFs = scanFixture(
      [
        "import * as fs from 'node:fs';",
        'const key = getMethod();',
        "fs[key]('/tmp/a', 'x');",
      ].join('\n')
    );
    expect(dynamicFs.filesystemWrites).toContainEqual({
      file: dynamicFs.filesystemWrites[0].file,
      callee: '<dynamic>',
    });

    const dynamicPromiseFs = scanFixture(
      [
        "import * as fs from 'node:fs';",
        'const key = getMethod();',
        "fs['promises'][key]('/tmp/a', 'x');",
      ].join('\n')
    );
    expect(dynamicPromiseFs.filesystemWrites.some((site) => site.callee === '<dynamic>')).toBe(
      true
    );
  });

  it('hashes test-named source files without capability-scanning them', () => {
    const dir = join(process.cwd(), 'src', '__tests__');
    const path = join(dir, '__sm4_hash_probe.test.ts');
    writeFileSync(
      path,
      [
        "import { writeFileSync } from 'node:fs';",
        "writeFileSync('/tmp/sm4-hash-probe', 'x');",
      ].join('\n')
    );

    try {
      const snapshot = buildSnapshot();
      expect(snapshot.criticalFileSha256['src/__tests__/__sm4_hash_probe.test.ts']).toMatch(
        /^[0-9a-f]{64}$/
      );
      expect(snapshot.filesystemWrites).not.toContainEqual({
        file: 'src/__tests__/__sm4_hash_probe.test.ts',
        callee: 'writeFileSync',
      });
    } finally {
      rmSync(path, { force: true });
    }
  });

  it('does not allow policy to approve reserved dynamic or wildcard markers', () => {
    const envPolicy = clone(policy);
    envPolicy.approvedNetworkUrlEnvVars.push('<dynamic>');
    expect(validatePolicy(baseline, envPolicy).join('\n')).toContain(
      'policy must not approve the reserved <dynamic> network-env marker'
    );

    const fsPolicy = clone(policy);
    fsPolicy.approvedFilesystemWrites.push({
      file: 'src/example.ts',
      callee: '*',
    });
    expect(validatePolicy(baseline, fsPolicy).join('\n')).toContain(
      'policy must not approve reserved wildcard/dynamic filesystem-write markers'
    );
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

  it('fails closed on alternate OAuth scope serialization and passthrough drift', () => {
    const concatScopes = extractImplicitAuthScopesFromSource(
      [
        "const scopeSet = new Set([...baseScopes, 'User.Read', 'offline_access']);",
        "params.set('scope', Array.from(scopeSet).concat('Sites.ReadWrite.All').join(' '));",
      ].join('\n')
    );
    expect(concatScopes).toContain('Sites.ReadWrite.All');

    const spreadScopes = extractImplicitAuthScopesFromSource(
      [
        "const scopeSet = new Set([...baseScopes, 'User.Read', 'offline_access']);",
        "params.set('scope', [...scopeSet].join(' '));",
      ].join('\n')
    );
    expect(spreadScopes).toEqual(['User.Read', 'offline_access']);

    expect(
      extractImplicitAuthScopesFromSource("params.set('scope', 'User.Read offline_access X');")
    ).toEqual(['User.Read', 'X', 'offline_access']);
    expect(extractImplicitAuthScopesFromSource("searchParams.append('scope', v);")).toContain(
      '<dynamic:v>'
    );
    expect(extractImplicitAuthScopesFromSource('new URLSearchParams({ scope: v });')).toContain(
      '<dynamic:v>'
    );

    const source = [
      "const scopeSet = new Set([...injected, 'User.Read', 'offline_access']);",
      "params.set('scope', Array.from(scopeSet).join(' '));",
    ].join('\n');
    expect(extractImplicitAuthScopePassthroughsFromSource(source)).toEqual(['injected']);

    const snapshot = clone(baseline);
    snapshot.implicitAuthScopePassthroughs = ['injected'];
    expect(validatePolicy(snapshot, policy).join('\n')).toContain(
      'unapproved implicit auth scope passthroughs: injected'
    );
  });

  it('covers additional URLSearchParams and search-assignment scope sink forms', () => {
    expect(
      extractImplicitAuthScopesFromSource(
        "new URLSearchParams('scope=User.Read%20offline_access');"
      )
    ).toEqual(['User.Read', 'offline_access']);

    expect(
      extractImplicitAuthScopesFromSource(
        "new URLSearchParams([['scope', 'User.Read offline_access']]);"
      )
    ).toEqual(['User.Read', 'offline_access']);

    expect(
      extractImplicitAuthScopesFromSource(
        "const v = getScopes(); new URLSearchParams({ ['scope']: v });"
      )
    ).toContain('<dynamic:v>');

    expect(
      extractImplicitAuthScopesFromSource("url.search = 'scope=User.Read%20offline_access';")
    ).toEqual(['User.Read', 'offline_access']);

    const arrayBacked = [
      "const arr = ['User.Read', 'offline_access', 'Sites.Read.All'];",
      'const scopeSet = new Set(arr);',
      "params.set('scope', Array.from(scopeSet).join(' '));",
    ].join('\n');
    expect(extractImplicitAuthScopesFromSource(arrayBacked)).toEqual([
      'Sites.Read.All',
      'User.Read',
      'offline_access',
    ]);

    expect(
      extractImplicitAuthScopesFromSource(
        'const k = getKey(); const v = getScopes(); new URLSearchParams({ [k]: v });'
      ).some((scope) => scope.startsWith('<dynamic:'))
    ).toBe(true);

    expect(
      extractImplicitAuthScopesFromSource(
        'const x = getObject(); new URLSearchParams({ ...x });'
      ).some((scope) => scope.startsWith('<dynamic:'))
    ).toBe(true);

    expect(
      extractImplicitAuthScopesFromSource(
        "const k = getKey(); new URLSearchParams([[k, 'User.Read']]);"
      ).some((scope) => scope.startsWith('<dynamic:'))
    ).toBe(true);

    expect(extractImplicitAuthScopesFromSource("url.search += '&scope=Sites.Read.All';")).toContain(
      'Sites.Read.All'
    );

    expect(
      extractImplicitAuthScopesFromSource('url.searchParams = getParams();').some((scope) =>
        scope.startsWith('<dynamic:')
      )
    ).toBe(true);

    expect(
      extractImplicitAuthScopesFromSource(
        "Object.assign(url, { search: '?scope=Chat.Read%20Mail.Read' });"
      )
    ).toEqual(['Chat.Read', 'Mail.Read']);

    expect(
      extractImplicitAuthScopesFromSource(
        'Object.assign(url, { searchParams: getParams() });'
      ).some((scope) => scope.startsWith('<dynamic:'))
    ).toBe(true);
  });

  it('does not allow policy to approve dynamic implicit-scope markers', () => {
    const snapshot = clone(baseline);
    snapshot.implicitAuthScopes = ['User.Read', 'offline_access', '<dynamic:extraScope>'];
    const weakened = clone(policy);
    weakened.approvedImplicitAuthScopes.push('<dynamic:extraScope>');
    expect(validatePolicy(snapshot, weakened).join('\n')).toContain(
      'policy must not approve dynamic implicit auth scope markers'
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

  it('detects wholesale env access through globalThis builtins', () => {
    const fixtures = [
      'globalThis.structuredClone(process.env);',
      'globalThis.Object.keys(process.env);',
      'globalThis.Reflect.get(process.env, getKey());',
    ];

    for (const source of fixtures) {
      const scan = scanFixture(source);
      expect(scan.networkUrlEnvVars).toContain('<dynamic>');
    }
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

  it('reports detailed deltas for dynamic and implicit-scope surfaces', () => {
    const changed = clone(baseline);
    changed.implicitAuthScopePassthroughs = [
      ...(changed.implicitAuthScopePassthroughs ?? []),
      'otherScopes',
    ];
    changed.writeLikeScopes = [...changed.writeLikeScopes, 'Files.ReadWrite.All'];
    changed.staticUrlHosts = [...changed.staticUrlHosts, 'example.invalid'];
    const changedTool = Object.keys(changed.toolFingerprints)[0];
    changed.toolFingerprints[changedTool] = '0'.repeat(64);
    changed.dynamicCode = [...changed.dynamicCode, { file: 'src/x.ts', kind: 'call eval' }];
    changed.nonLiteralModuleAcquisitions = [
      ...changed.nonLiteralModuleAcquisitions,
      { file: 'src/x.ts', kind: 'computed-member', expression: 'process[k]' },
    ];
    changed.nonLiteralDynamicImports = [
      ...changed.nonLiteralDynamicImports,
      { file: 'src/x.ts', expression: 'name' },
    ];

    const delta = describeBaselineDelta(baseline, changed).join('\n');
    expect(delta).toContain('implicitAuthScopePassthroughs added: otherScopes');
    expect(delta).toContain('writeLikeScopes added: Files.ReadWrite.All');
    expect(delta).toContain('staticUrlHosts added: example.invalid');
    expect(delta).toContain(`toolFingerprints changed: ${changedTool}`);
    expect(delta).toContain('dynamicCode added: src/x.ts|call eval');
    expect(delta).toContain(
      'nonLiteralModuleAcquisitions added: src/x.ts|computed-member|process[k]'
    );
    expect(delta).toContain('nonLiteralDynamicImports added: src/x.ts|name');
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
