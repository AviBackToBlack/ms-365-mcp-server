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

function scanFixture(source) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-security-fixture-'));
  tempDirs.push(dir);
  const path = join(dir, 'fixture.ts');
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

  it('hashes the full non-generated runtime source surface and the verifier itself', () => {
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
