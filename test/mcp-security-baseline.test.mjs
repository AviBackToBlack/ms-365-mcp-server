import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  buildSnapshot,
  compareSnapshots,
  describeBaselineDelta,
  validatePolicy,
} from '../scripts/mcp-security-snapshot.mjs';

const baseline = JSON.parse(readFileSync('downstream/mcp-security-baseline.json', 'utf8'));
const policy = JSON.parse(readFileSync('downstream/mcp-security-policy.json', 'utf8'));

const clone = (value) => structuredClone(value);

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
