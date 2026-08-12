import { test } from 'node:test';
import assert from 'node:assert';
import { join, dirname } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';
import { randomBytes } from 'crypto';
import { mkdir, mkdtemp, rm, writeFile, readFile } from 'fs/promises';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { targetSlug, expectedDigest } from '../install.js';

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dirname, '../../..');
const CLI = join(REPO, 'veil-guard/target/debug/veil-guard');
const BUNDLE = join(REPO, 'veil-guard-action/dist/index.js');

test('targetSlug picks the right archive per runner', () => {
  assert.deepStrictEqual(targetSlug('linux', 'x64', false), {
    slug: 'x86_64-unknown-linux-musl',
    exe: 'veil-guard',
  });
  assert.deepStrictEqual(targetSlug('win32', 'x64', false), {
    slug: 'x86_64-pc-windows-msvc',
    exe: 'veil-guard.exe',
  });
  assert.strictEqual(targetSlug('darwin', 'arm64', false).slug, 'aarch64-apple-darwin');

  // KMS archives are native and glibc; only two platforms have one.
  assert.strictEqual(targetSlug('linux', 'x64', true).slug, 'x86_64-unknown-linux-gnu-kms');
  assert.strictEqual(targetSlug('darwin', 'arm64', true).slug, 'aarch64-apple-darwin-kms');
});

test('asking for KMS where no KMS build exists fails with a reason', () => {
  // Silently handing back the base archive would surface as "KMS support is
  // disabled" partway through a signing run, long after the useful context is gone.
  assert.throws(() => targetSlug('linux', 'arm64', true), /no KMS-capable release build/);
  assert.throws(() => targetSlug('win32', 'x64', true), /no KMS-capable release build/);
  assert.throws(() => targetSlug('freebsd', 'x64', false), /no veil-guard release build/);
});

test('expectedDigest reads both sha256sum and shasum output', () => {
  const sums = [
    'aa'.repeat(32) + '  veil-guard-0.1.1-x86_64-apple-darwin.tar.gz',
    'bb'.repeat(32) + '  veil-guard-0.1.1-x86_64-unknown-linux-musl.tar.gz',
  ].join('\n');
  assert.strictEqual(
    expectedDigest(sums, 'veil-guard-0.1.1-x86_64-unknown-linux-musl.tar.gz'),
    'bb'.repeat(32),
  );
  assert.throws(() => expectedDigest(sums, 'nope.tar.gz'), /no entry for/);
});

test('the built bundle signs a build and reports the manifest digest', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vg-action-'));
  try {
    const dist = join(dir, 'dist');
    await mkdir(dist, { recursive: true });
    await writeFile(join(dist, 'app.js'), 'export const x = 1;\n');
    await writeFile(
      join(dist, 'index.html'),
      '<!doctype html><html><head><script src="/veil-guard-loader.js"></script>' +
        '</head><body><script type="module" src="/app.js"></script></body></html>',
    );

    const keys = join(dir, 'keys');
    await execFileAsync(CLI, ['keygen', '--out-dir', keys, '--name', 'a']);
    const trustRoot = join(dir, 'trust-root.json');
    await execFileAsync(CLI, [
      'trust-root',
      '--key',
      join(keys, 'a.pub.json'),
      '--threshold',
      '1',
      '--out',
      trustRoot,
    ]);

    const outputFile = join(dir, 'gh-output');
    await writeFile(outputFile, '');

    const { stdout } = await execFileAsync('node', [BUNDLE], {
      env: {
        ...process.env,
        // How the runner hands inputs to an action. `bin-path` short-circuits the
        // release download, which is the only part that needs the network.
        INPUT_DIST: dist,
        'INPUT_TRUST-ROOT': trustRoot,
        INPUT_KEYS: join(keys, 'a.key.json'),
        'INPUT_BIN-PATH': CLI,
        INPUT_EXCLUDE: '/api/',
        'INPUT_CSP-SOURCE': 'https://www.googletagmanager.com',
        'INPUT_HEADERS-OUT': join(dir, 'headers'),
        GITHUB_OUTPUT: outputFile,
        GITHUB_SHA: 'cafebabe',
      },
    });

    const manifest = JSON.parse(await readFile(join(dist, 'veil-guard-manifest.json'), 'utf8'));
    const paths: string[] = manifest.assets.map((a: { path: string }) => a.path);

    assert.ok(paths.includes('/veil-guard-sw.js'), 'emit-runtime defaults on, so the worker ships');
    assert.ok(paths.includes('/veil-guard-loader.js'));
    assert.deepStrictEqual(manifest.scope.exclude, ['/api/'], 'exclude must reach the CLI');
    assert.strictEqual(manifest.source.commit, 'cafebabe', 'GITHUB_SHA becomes source.commit');

    const headers = await readFile(join(dir, 'headers/_headers'), 'utf8');
    assert.ok(headers.includes('googletagmanager'), 'csp-source must reach the policy');

    assert.match(stdout, /verified/, 'verify defaults on');

    // The output the workflow downstream reads has to be the digest of the file
    // that was actually written.
    const written = await readFile(join(dist, 'veil-guard-manifest.json'));
    const { createHash } = await import('crypto');
    const digest = createHash('sha256').update(written).digest('hex');
    assert.ok(
      (await readFile(outputFile, 'utf8')).includes(digest),
      'manifest-sha256 must be set to the real digest',
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a missing required input fails the step instead of throwing raw', async () => {
  // setFailed exits non-zero, which is the point — the assertion is on how it
  // reports, not on whether it survives.
  const result: { code?: number; stdout?: string } = await execFileAsync('node', [BUNDLE], {
    env: {
      ...process.env,
      INPUT_DIST: join(tmpdir(), `vg-none-${randomBytes(4).toString('hex')}`),
      'INPUT_TRUST-ROOT': '/nonexistent/trust-root.json',
      INPUT_KEYS: '',
      'INPUT_BIN-PATH': CLI,
    },
  }).catch((e: { code?: number; stdout?: string }) => e);

  assert.strictEqual(result.code, 1, 'the step must fail');
  const stdout = result.stdout ?? '';
  assert.match(stdout, /::error::/, 'reported through the Actions error protocol');
  assert.match(stdout, /keys/, 'and naming the missing input');
});
