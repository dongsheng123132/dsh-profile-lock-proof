# dsh-profile-lock-proof

`dsh-profile-lock-proof` produces a content-addressed, machine-readable proof that a DeepSeek Harness profile's dependency declaration, pnpm lock importer, installed package manifests, and each package's declared `dsh.bundle.patch` agree.

It is deliberately narrower than an SBOM, CVE scanner, signature verifier, or installer. It does not execute packages, contact the network, mutate a profile, or return manifest, lockfile, patch, script-command, or secret contents.

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
```

MIT licensed. See [SECURITY.md](SECURITY.md) for the threat boundary.
