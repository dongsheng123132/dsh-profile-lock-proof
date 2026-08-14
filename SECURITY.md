# Security policy

Report vulnerabilities privately through GitHub Security Advisories.

The verifier is offline and read-only except for its explicit workspace-relative `artifactDir`. It rejects path traversal, symlinks, oversized files, secret-shaped manifest fields, mutable dependency references, and lifecycle scripts. It never executes inspected packages or their scripts and never returns input file bodies.

A passing proof establishes consistency only among the explicitly pinned profile, pnpm importer, installed package manifests, and bundle patch bytes. It does not establish author trust, malware absence, vulnerability status, signature validity, or runtime behavior.
