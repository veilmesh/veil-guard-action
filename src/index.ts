import * as core from '@actions/core';
import { exec } from '@actions/exec';
import { sign, runtime, verify, type SignOptions } from '@veilmesh/veil-guard';
import { readFile } from 'fs/promises';
import { join, dirname } from 'path';
import { createHash } from 'crypto';
import { installCli } from './install.js';

/** Newline-separated input, trimmed, blanks dropped. */
function lines(name: string): string[] {
  return core
    .getInput(name)
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
}

function flag(name: string, fallback = false): boolean {
  const raw = core.getInput(name);
  return raw === '' ? fallback : core.getBooleanInput(name);
}

async function run(): Promise<void> {
  try {
    const dist = core.getInput('dist', { required: true });
    const trustRoot = core.getInput('trust-root', { required: true });
    const keys = lines('keys');
    if (keys.length === 0) {
      throw new Error('`keys` is required: one key file path per line');
    }

    const kmsKeyId = core.getInput('kms-key-id') || undefined;
    const kmsProvider = core.getInput('kms-provider') || undefined;

    // An explicit binary wins; otherwise fetch the release build that matches this
    // runner — and the KMS flavour if the inputs ask for KMS, since the base
    // archives are compiled without it and would fail halfway through signing.
    let binPath = core.getInput('bin-path') || undefined;
    if (!binPath) {
      binPath = await installCli(
        core.getInput('version') || '0.1.1',
        kmsKeyId !== undefined,
        core.getInput('token', { required: true }),
      );
      core.addPath(dirname(binPath));
    }
    core.info(`veil-guard: ${binPath}`);

    // Without this the deployment has a signed manifest and no worker to enforce
    // it — the signature exists and nothing reads it.
    if (flag('emit-runtime', true)) {
      await runtime({ out: dist, trustRoot, binPath });
      core.info('emitted the Service Worker and loader');
    }

    const signOpts: SignOptions = {
      dist,
      trustRoot,
      keys,
      excludes: lines('exclude'),
      cspSources: lines('csp-source'),
      navigationHtmlFallback: flag('navigation-html-fallback'),
      headersOut: core.getInput('headers-out') || undefined,
      enforceHeaders: flag('enforce-headers'),
      noSri: flag('no-sri'),
      sourceCommit: core.getInput('source-commit') || process.env.GITHUB_SHA,
      notAfterDays: core.getInput('not-after-days')
        ? Number(core.getInput('not-after-days'))
        : undefined,
      kms: kmsKeyId
        ? { keyId: kmsKeyId, provider: kmsProvider as 'aws' | 'gcp' | undefined }
        : undefined,
      binPath,
    };

    core.info(`signing ${dist}`);
    core.info((await sign(signOpts)).trim());

    // Catches a later step writing into the output directory after the signature
    // was taken — otherwise invisible until a browser refuses the page.
    if (flag('verify', true)) {
      await verify({ dist, trustRoot, binPath });
      core.info('verified');
    }

    const manifest = await readFile(join(dist, 'veil-guard-manifest.json'));
    const sha256 = createHash('sha256').update(manifest).digest('hex');
    core.setOutput('manifest-sha256', sha256);
    core.info(`manifest sha256: ${sha256}`);

    const auditUrl = core.getInput('audit-url');
    if (auditUrl) {
      core.info(`auditing ${auditUrl}`);
      await exec(binPath, [
        'audit',
        '--url',
        auditUrl,
        '--trust-root',
        trustRoot,
        '--label',
        core.getInput('audit-label') || 'ci',
        '--fail-on',
        core.getInput('fail-on') || 'warning',
      ]);
    }
  } catch (err) {
    core.setFailed(err instanceof Error ? err.message : String(err));
  }
}

run();
