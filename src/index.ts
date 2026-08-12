import * as core from '@actions/core';
import { sign, type SignOptions } from '@veilmesh/veil-guard';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { createHash } from 'crypto';
import { exec } from '@actions/exec';

async function run() {
  try {
    const dist = core.getInput('dist', { required: true });
    const trustRoot = core.getInput('trust-root', { required: true });
    const keysRaw = core.getInput('keys', { required: true });
    const headersOut = core.getInput('headers-out') || undefined;
    const excludeRaw = core.getInput('exclude') || '';
    const auditUrl = core.getInput('audit-url') || undefined;
    const failOn = core.getInput('fail-on') || 'warning';
    const kmsKeyId = core.getInput('kms-key-id') || undefined;
    const kmsProvider = core.getInput('kms-provider') || undefined;
    const binPath = core.getInput('bin-path') || undefined;

    const keys = keysRaw.split('\n').map(s => s.trim()).filter(Boolean);
    const excludes = excludeRaw.split('\n').map(s => s.trim()).filter(Boolean);

    const signOpts: SignOptions = {
      dist,
      trustRoot,
      keys,
      excludes: excludes.length > 0 ? excludes : undefined,
      headersOut,
      kms: kmsKeyId ? { keyId: kmsKeyId, provider: kmsProvider as any } : undefined,
      binPath,
    };

    core.info(`Signing asset manifest in "${dist}"...`);
    const stdout = await sign(signOpts);
    core.info(`✅ ${stdout.trim()}`);

    // Compute manifest SHA-256
    const manifestPath = join(dist, 'veil-guard-manifest.json');
    const manifestBytes = await readFile(manifestPath);
    const sha256 = createHash('sha256').update(manifestBytes).digest('hex');
    core.setOutput('manifest-sha256', sha256);
    core.info(`manifest SHA-256: ${sha256}`);

    // Run audit if requested
    if (auditUrl) {
      core.info(`Running audit against "${auditUrl}"...`);
      const bin = binPath || 'veil-guard';
      const auditArgs = [
        'audit',
        '--url', auditUrl,
        '--trust-root', trustRoot,
        '--label', 'ci',
        '--fail-on', failOn,
      ];
      await exec(bin, auditArgs);
    }
  } catch (err: any) {
    core.setFailed(err instanceof Error ? err.message : String(err));
  }
}

run();
