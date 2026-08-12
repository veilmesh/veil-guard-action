# veil-guard-action

Sign a web build with [`veil-guard`](https://github.com/veilmesh/veil-guard) in GitHub
Actions: install the CLI, emit the Tier 1 Service Worker, hash every asset into a
threshold-signed manifest, splice `integrity` attributes into the HTML, verify the
result, and optionally audit a live deployment.

```yaml
- uses: veilmesh/veil-guard-action@v1
  with:
    dist: dist
    trust-root: trust-root.json
    keys: |
      .keys/build-1.key.json
      .keys/build-2.key.json
    exclude: |
      /api/
```

## Installing the CLI

The action downloads the release archive matching the runner and **checks it against
the release's own `SHA256SUMS` before unpacking**. A tool whose purpose is refusing
code that does not match a published hash should not install itself any other way. The
result is kept in the runner tool cache, so repeat runs skip the download.

`bin-path` skips all of this and uses a binary you provide.

### Private repository

While `veilmesh/veil-guard` is private, the default `GITHUB_TOKEN` of a *different*
repository cannot read its releases and the API answers 404. Supply a token that can:

```yaml
  with:
    token: ${{ secrets.VEIL_GUARD_READ_TOKEN }}
```

A fine-grained token with `Contents: Read-only` on that one repository is enough.

### KMS

Setting `kms-key-id` selects a KMS-capable build. Those are published for
`linux-x64` and `darwin-arm64` only — `aws-lc-sys` does not cross-compile to musl —
and the action fails with that explanation rather than installing a base build that
would report `KMS support is disabled` partway through signing.

## Inputs

| Input | Default | |
|---|---|---|
| `dist` | `dist` | Build output directory. |
| `trust-root` | — | Required. Must come from the repository, never from the deployment being signed. |
| `keys` | — | Required. One key file path per line, enough to meet the threshold. |
| `version` | `0.1.1` | CLI release to install. |
| `token` | `${{ github.token }}` | Used only to download the release. |
| `bin-path` | — | Use an existing binary; skips the download. |
| `exclude` | — | Prefixes the worker leaves alone, one per line. Scope is an allowlist, so dynamic endpoints must be carved out. |
| `csp-source` | — | Extra `script-src` sources, one per line. |
| `navigation-html-fallback` | `false` | Resolve `/faq` against a signed `faq.html`. Only for hosts that map clean URLs onto files. |
| `headers-out` | — | Directory for the generated header snippets. |
| `enforce-headers` | `false` | Enforcing `Integrity-Policy` instead of report-only. |
| `no-sri` | `false` | Leave the built HTML untouched. |
| `not-after-days` | `180` | Expiry is a soft warning, never a tamper alert. |
| `source-commit` | `GITHUB_SHA` | A claim by the signer, not a proof. |
| `emit-runtime` | `true` | Write the worker and loader into the output before signing. |
| `verify` | `true` | Re-check after signing. |
| `kms-key-id` / `kms-provider` | — | For signers whose P-256 half is remote. |
| `audit-url`, `audit-label`, `fail-on` | — / `ci` / `warning` | Audit a live deployment after signing. |

## Outputs

| Output | |
|---|---|
| `manifest-sha256` | SHA-256 of the signed `veil-guard-manifest.json`. |

## Where the keys should not be

The signing keys have to reach the runner somehow, and a runner that can read a
threshold of them can sign anything. `veil-guard` supports keeping each signer's
P-256 half in a cloud KMS so that only the Ed25519 half is on disk — see SPEC §4.6
for what that does and does not achieve, because it is half a measure and the
project says so.

## Licence

MIT or Apache-2.0.
