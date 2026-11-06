# dsh-profile-lock-proof

**Maintainer / Author：贺去病 (He Fangsheng / Dosen) · [hequbing.com](https://www.hequbing.com)**

[![CI](https://github.com/dongsheng123132/dsh-profile-lock-proof/actions/workflows/ci.yml/badge.svg)](https://github.com/dongsheng123132/dsh-profile-lock-proof/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/github/license/dongsheng123132/dsh-profile-lock-proof)](LICENSE)
[![Node.js 22+](https://img.shields.io/badge/Node.js-%E2%89%A522-339933?logo=nodedotjs&logoColor=white)](package.json)
[![Awesome DSH Plugins](https://img.shields.io/badge/Awesome_DSH-verified_lab-0969da)](https://github.com/dongsheng123132/awesome-dsh-plugins#2origin-plugin-lab)

`dsh-profile-lock-proof` produces a content-addressed, machine-readable proof that a DeepSeek Harness profile's dependency declaration, pnpm lock importer, installed package manifests, and each package's declared `dsh.bundle.patch` agree.

It is deliberately narrower than an SBOM, CVE scanner, signature verifier, or installer. It does not execute packages, contact the network, mutate a profile, or return manifest, lockfile, patch, script-command, or secret contents.

Version 0.2.0 removes the bundled DSH tool runtime and the default export that stock Cordis Loader misclassified. The bundle now exposes host-neutral tool definitions through its namespace export; local-path and fixed-commit installs are exercised against the real stock Web profile.

## Proof boundary

- Input paths are workspace-relative regular files; traversal and symlinks are rejected.
- Profile and lockfile bytes must match the SHA-256 values in an explicit proof manifest.
- Dependency specifiers must be exact semver or `github:owner/repo#<40-hex-commit>`.
- The pnpm importer specifier, installed name/version/package hash, bundle patch path/hash, and absence of lifecycle hooks must all agree.
- Missing, stale, invalid, mutable, mismatched, or lifecycle-script-bearing evidence fails closed.
- Output contains identities, classifications, hashes, status, and disclosure only. Reports are written atomically under an explicit `artifactDir` and read back.

## CLI

```bash
dsh-profile-lock-proof inspect --workspace . --manifest proof.json
dsh-profile-lock-proof verify --workspace . --manifest proof.json --artifactDir artifacts
```

Exit `0` means a verified proof, `2` means verification or input failure.

## DSH / MCP tools

- `dsh_profile_lock_inspect`
- `dsh_profile_lock_verify`
- MCP aliases: `profile_lock_inspect`, `profile_lock_verify`

The MCP surface is deliberately lower privilege: it accepts bounded inline evidence only, never reads or writes files, and shares the validation core. DSH/CLI may write only to an explicit workspace-relative `artifactDir`, atomically and with read-back verification.

Install into an isolated profile:

```bash
dsh plugin --profile profile-lock add github:dongsheng123132/dsh-profile-lock-proof#<commit>
```

## Development

```bash
npm ci
npm test
npm run check
npm run smoke:plugin
npm run smoke:mcp
npm run smoke:web-loader # requires DSH_CHECKOUT and isolated DSH_HOME
```

MIT licensed. See [SECURITY.md](SECURITY.md) for the threat boundary.
