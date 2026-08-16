# Threat model

The engine treats all input SBOM/lockfile data as untrusted data, never executes it, and only parses bounded local JSON files explicitly supplied by the caller. It does not fetch certificate URLs, run package scripts, execute builds, or contact registries. Output paths are caller-controlled directories; the CLI creates files only inside that directory.

Confidence is evidence confidence, not cryptographic trust. A malicious or compromised evidence source can assert false edges; signed attestations and source trust policies are planned research extensions. The engine therefore preserves provenance instead of erasing disagreement.
