import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const verifySupplyChain = join(repoRoot, 'scripts', 'verify-supply-chain.mjs');
const verifyNpmAudit = join(repoRoot, 'scripts', 'verify-npm-audit.mjs');

const tempDirs: string[] = [];

function makeTempRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'ms365-supply-chain-'));
  tempDirs.push(dir);
  mkdirSync(join(dir, 'downstream'), { recursive: true });
  return dir;
}

function readPolicy() {
  return JSON.parse(
    readFileSync(join(repoRoot, 'downstream', 'supply-chain-policy.json'), 'utf8')
  );
}

function readLock() {
  return JSON.parse(readFileSync(join(repoRoot, 'package-lock.json'), 'utf8'));
}

function writeSupplyFixture(dir: string, policy: object, lock: object | string) {
  writeFileSync(
    join(dir, 'downstream', 'supply-chain-policy.json'),
    JSON.stringify(policy)
  );
  writeFileSync(
    join(dir, 'package-lock.json'),
    typeof lock === 'string' ? lock : JSON.stringify(lock)
  );
}

function runSupplyVerifier(dir: string) {
  return spawnSync(process.execPath, [verifySupplyChain], {
    cwd: dir,
    encoding: 'utf8',
  });
}

function runAuditVerifier(dir: string, report: object | string) {
  writeFileSync(
    join(dir, 'downstream', 'supply-chain-policy.json'),
    JSON.stringify(readPolicy())
  );
  writeFileSync(
    join(dir, 'audit.json'),
    typeof report === 'string' ? report : JSON.stringify(report)
  );
  return spawnSync(process.execPath, [verifyNpmAudit, 'audit.json'], {
    cwd: dir,
    encoding: 'utf8',
  });
}

function expectFailure(result: ReturnType<typeof spawnSync>, message: string) {
  expect(result.status).toBe(1);
  expect(result.stderr).toContain(message);
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('supply-chain verifier fail-closed behavior', () => {
  it('rejects a tampered lockfile hash', () => {
    const dir = makeTempRepo();
    const lockText = readFileSync(join(repoRoot, 'package-lock.json'), 'utf8');
    writeSupplyFixture(dir, readPolicy(), `${lockText}\n`);

    expectFailure(runSupplyVerifier(dir), 'package-lock SHA-256');
  });

  it('rejects a Node version that does not match policy', () => {
    const dir = makeTempRepo();
    const policy = readPolicy();
    policy.verificationToolchain.nodeVersion = '0.0.0';
    writeSupplyFixture(dir, policy, readLock());

    expectFailure(runSupplyVerifier(dir), 'Node version');
  });

  it('rejects lockfileVersion drift', () => {
    const dir = makeTempRepo();
    const policy = readPolicy();
    policy.lockfile.lockfileVersion += 1;
    writeSupplyFixture(dir, policy, readLock());

    expectFailure(runSupplyVerifier(dir), 'lockfileVersion');
  });

  it('rejects package-count drift', () => {
    const dir = makeTempRepo();
    const policy = readPolicy();
    policy.lockfile.packageCount += 1;
    writeSupplyFixture(dir, policy, readLock());

    expectFailure(runSupplyVerifier(dir), 'package count');
  });

  it('rejects a non-registry package resolution', () => {
    const dir = makeTempRepo();
    const lock = readLock();
    const entry = Object.values(lock.packages).find(
      (value: any) => value?.resolved && !value?.link
    ) as any;
    entry.resolved = 'https://example.invalid/package.tgz';
    writeSupplyFixture(dir, readPolicy(), lock);

    expectFailure(runSupplyVerifier(dir), 'resolves outside approved registry');
  });

  it('rejects missing SHA-512 integrity metadata', () => {
    const dir = makeTempRepo();
    const lock = readLock();
    const entry = Object.values(lock.packages).find(
      (value: any) => value?.resolved && value?.integrity && !value?.link
    ) as any;
    delete entry.integrity;
    writeSupplyFixture(dir, readPolicy(), lock);

    expectFailure(runSupplyVerifier(dir), 'does not have sha512 integrity');
  });

  it('rejects install-script surface drift', () => {
    const dir = makeTempRepo();
    const lock = readLock();
    const entry = Object.values(lock.packages).find(
      (value: any) => value?.resolved && !value?.hasInstallScript && !value?.link
    ) as any;
    entry.hasInstallScript = true;
    writeSupplyFixture(dir, readPolicy(), lock);

    expectFailure(runSupplyVerifier(dir), 'install-script package surface changed');
  });

  it('rejects verification npm version drift', () => {
    const dir = makeTempRepo();
    const policy = readPolicy();
    policy.verificationToolchain.npmVersion = '0.0.0';
    writeSupplyFixture(dir, policy, readLock());

    expectFailure(runSupplyVerifier(dir), 'verification npm version');
  });

  it('rejects a package with neither registry resolution nor inBundle', () => {
    const dir = makeTempRepo();
    const lock = readLock();
    const path = Object.keys(lock.packages).find(
      (key) => key && lock.packages[key]?.resolved && !lock.packages[key]?.link
    ) as string;
    delete lock.packages[path].resolved;
    delete lock.packages[path].integrity;
    writeSupplyFixture(dir, readPolicy(), lock);

    expectFailure(runSupplyVerifier(dir), 'has neither a registry resolution nor inBundle=true');
  });
});

describe('npm audit policy fail-closed behavior', () => {
  it('rejects an unapproved npm advisory', () => {
    const dir = makeTempRepo();
    const result = runAuditVerifier(dir, {
      vulnerabilities: {
        'unexpected-package': {
          severity: 'low',
          via: [
            {
              source: 123456,
              name: 'unexpected-package',
              severity: 'low',
              url: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
            },
          ],
        },
      },
    });

    expectFailure(result, 'unapproved vulnerable package: unexpected-package');
  });

  it('rejects severity drift for an accepted advisory', () => {
    const dir = makeTempRepo();
    const result = runAuditVerifier(dir, {
      vulnerabilities: {
        esbuild: {
          severity: 'moderate',
          via: [
            {
              source: 1120680,
              name: 'esbuild',
              severity: 'moderate',
              url: 'https://github.com/advisories/GHSA-g7r4-m6w7-qqqr',
            },
          ],
        },
      },
    });

    expectFailure(result, 'severity changed from low to moderate');
  });

  it('rejects a stale accepted-vulnerability entry', () => {
    const dir = makeTempRepo();
    const result = runAuditVerifier(dir, { vulnerabilities: {} });

    expectFailure(result, 'accepted vulnerability is stale or missing from audit output');
  });

  it('rejects an npm audit error payload', () => {
    const dir = makeTempRepo();
    const result = runAuditVerifier(dir, {
      error: {
        code: 'EAUDIT',
        summary: 'synthetic audit failure',
      },
    });

    expectFailure(result, 'npm audit returned an error payload');
  });

  it('rejects a string-only transitive advisory chain', () => {
    const dir = makeTempRepo();
    const result = runAuditVerifier(dir, {
      vulnerabilities: {
        esbuild: {
          severity: 'low',
          via: ['some-parent-package'],
        },
      },
    });

    expectFailure(result, 'has no directly attributable advisory');
  });
});
