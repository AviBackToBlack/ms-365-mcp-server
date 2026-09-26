import { execFileSync, spawnSync } from 'node:child_process';
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

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('supply-chain verifier fail-closed behavior', () => {
  it('rejects a tampered lockfile hash', () => {
    const dir = makeTempRepo();
    const policy = readFileSync(join(repoRoot, 'downstream', 'supply-chain-policy.json'), 'utf8');
    const lock = readFileSync(join(repoRoot, 'package-lock.json'), 'utf8');

    writeFileSync(join(dir, 'downstream', 'supply-chain-policy.json'), policy);
    writeFileSync(join(dir, 'package-lock.json'), `${lock}\n`);

    const result = spawnSync(process.execPath, [verifySupplyChain], {
      cwd: dir,
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('package-lock SHA-256');
  });

  it('rejects an unapproved npm advisory', () => {
    const dir = makeTempRepo();
    const policy = readFileSync(join(repoRoot, 'downstream', 'supply-chain-policy.json'), 'utf8');

    writeFileSync(join(dir, 'downstream', 'supply-chain-policy.json'), policy);
    writeFileSync(
      join(dir, 'audit.json'),
      JSON.stringify({
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
      })
    );

    const result = spawnSync(process.execPath, [verifyNpmAudit, 'audit.json'], {
      cwd: dir,
      encoding: 'utf8',
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('unapproved vulnerable package: unexpected-package');
  });

  it('accepts the repository baseline on the pinned Node version', () => {
    const output = execFileSync(process.execPath, [verifySupplyChain], {
      cwd: repoRoot,
      encoding: 'utf8',
    });

    expect(output).toContain('Supply-chain baseline verification PASS');
  });
});
