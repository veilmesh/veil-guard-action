import * as core from '@actions/core';
import * as tc from '@actions/tool-cache';
import { createHash } from 'crypto';
import { readFile } from 'fs/promises';
import { join } from 'path';

const REPO = 'veilmesh/veil-guard';

/**
 * Which release archive this runner needs.
 *
 * The `-kms` archives are native, glibc, and exist for two platforms only —
 * `aws-lc-sys` does not cross-compile to musl. Asking for KMS anywhere else is a
 * hard error rather than a silent fall back to a binary that would answer
 * "KMS support is disabled" halfway through a signing run.
 */
export function targetSlug(
  platform: string,
  arch: string,
  needsKms: boolean,
): { slug: string; exe: string } {
  const exe = platform === 'win32' ? 'veil-guard.exe' : 'veil-guard';
  const key = `${platform}-${arch}`;

  if (needsKms) {
    const kms: Record<string, string> = {
      'linux-x64': 'x86_64-unknown-linux-gnu-kms',
      'darwin-arm64': 'aarch64-apple-darwin-kms',
    };
    const slug = kms[key];
    if (!slug) {
      throw new Error(
        `no KMS-capable release build for ${key}. KMS archives are published for ` +
          `linux-x64 and darwin-arm64 only, because aws-lc-sys does not cross-compile ` +
          `to musl. Run this step on one of those, or build the CLI from source with ` +
          `--features audit,kms and point bin-path at it.`,
      );
    }
    return { slug, exe };
  }

  const base: Record<string, string> = {
    'linux-x64': 'x86_64-unknown-linux-musl',
    'linux-arm64': 'aarch64-unknown-linux-musl',
    'darwin-x64': 'x86_64-apple-darwin',
    'darwin-arm64': 'aarch64-apple-darwin',
    'win32-x64': 'x86_64-pc-windows-msvc',
  };
  const slug = base[key];
  if (!slug) {
    throw new Error(`no veil-guard release build for ${key}`);
  }
  return { slug, exe };
}

/** The SHA-256 recorded for `name` in a SHA256SUMS file. */
export function expectedDigest(sums: string, name: string): string {
  for (const line of sums.split('\n')) {
    // "<hex>  <name>", two spaces, as both sha256sum and shasum emit.
    const match = line.trim().match(/^([0-9a-f]{64})\s+\*?(.+)$/);
    if (match && match[2] === name) return match[1];
  }
  throw new Error(`SHA256SUMS has no entry for ${name}`);
}

interface Asset {
  name: string;
  url: string;
}

async function releaseAssets(tag: string, token: string): Promise<Asset[]> {
  const res = await fetch(`https://api.github.com/repos/${REPO}/releases/tags/${tag}`, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'x-github-api-version': '2022-11-28',
    },
  });
  if (!res.ok) {
    // The common case by far, and the error the API gives for it is a bare 404.
    const hint =
      res.status === 404
        ? `\n\n${REPO} is private, so the default GITHUB_TOKEN of another repository ` +
          `cannot read its releases. Pass a token with read access to it:\n` +
          `    token: \${{ secrets.VEIL_GUARD_READ_TOKEN }}`
        : '';
    throw new Error(`cannot read release ${tag} of ${REPO}: HTTP ${res.status}${hint}`);
  }
  const body = (await res.json()) as { assets?: Asset[] };
  return body.assets ?? [];
}

async function download(asset: Asset, token: string): Promise<string> {
  return tc.downloadTool(asset.url, undefined, `Bearer ${token}`, {
    accept: 'application/octet-stream',
  });
}

/**
 * Put a `veil-guard` binary on this runner and return its path.
 *
 * The archive is checked against the release's own SHA256SUMS before it is
 * unpacked. A tool whose entire purpose is refusing code that does not match a
 * published hash has no business installing itself without doing the same.
 */
export async function installCli(
  version: string,
  needsKms: boolean,
  token: string,
): Promise<string> {
  const { slug, exe } = targetSlug(process.platform, process.arch, needsKms);
  const tag = version.startsWith('v') ? version : `v${version}`;
  const bare = tag.slice(1);

  const cached = tc.find('veil-guard', bare, slug);
  if (cached) {
    core.info(`veil-guard ${bare} (${slug}) found in the tool cache`);
    return join(cached, exe);
  }

  const archiveName = `veil-guard-${bare}-${slug}.tar.gz`;
  core.info(`downloading ${archiveName} from ${REPO} ${tag}`);

  const assets = await releaseAssets(tag, token);
  const archive = assets.find((a) => a.name === archiveName);
  if (!archive) {
    throw new Error(
      `release ${tag} has no asset ${archiveName}. Available: ` +
        (assets.map((a) => a.name).join(', ') || '(none)'),
    );
  }
  const sums = assets.find((a) => a.name === 'SHA256SUMS');
  if (!sums) {
    throw new Error(`release ${tag} publishes no SHA256SUMS; refusing to install unverified`);
  }

  const [archivePath, sumsPath] = await Promise.all([
    download(archive, token),
    download(sums, token),
  ]);

  const want = expectedDigest(await readFile(sumsPath, 'utf8'), archiveName);
  const got = createHash('sha256')
    .update(await readFile(archivePath))
    .digest('hex');
  if (got !== want) {
    throw new Error(
      `checksum mismatch for ${archiveName}\n  expected ${want}\n  got      ${got}`,
    );
  }
  core.info(`sha256 ok: ${got}`);

  const extracted = await tc.extractTar(archivePath);
  // Archives unpack into a directory named after the archive itself.
  const dir = join(extracted, `veil-guard-${bare}-${slug}`);
  const cachedDir = await tc.cacheDir(dir, 'veil-guard', bare, slug);
  return join(cachedDir, exe);
}
