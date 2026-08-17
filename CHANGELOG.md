# Changelog

All notable changes will be documented here. This project follows Semantic Versioning and the Keep a Changelog structure.

## 0.2.0 - Unreleased

- Replace unsafe whole-PURL lowercasing with ECMA-427/type-aware parsing and
  canonical serialization through the official Python implementation.
- Retain original identity aliases and reject ambiguous opaque component-key
  collisions.
- Add adversarial case, qualifier, percent-encoding, ecosystem, and version
  parity tests.
- Prefer Maven dependency-tree JSON and harden the text fallback so classifier,
  type, scope, optionality, and depth survive as relationship evidence.
- Add compile/runtime/test-aware reachability for Maven graphs.
