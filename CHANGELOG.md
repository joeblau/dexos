# Changelog

All notable changes are recorded here. This project follows Keep a Changelog and
uses Semantic Versioning after the first stable release. During `0.x`, minor
versions may contain breaking changes and every such change must be called out.

## [Unreleased]

### Security

- Pin CI actions to immutable commits and minimize workflow permissions.
- Exclude developer tooling and mock chain adapters from default `marketd` builds.

### Added

- `dexos` command-line RPC client (`bin/dexos`): 18 read-only queries and 10
  ed25519-signed control methods over the binary TCP RPC, one subcommand per
  method. Documented in [docs/CLI.md](docs/CLI.md). Targets a plaintext listener
  for now; TLS client and `marketd run` endpoint binding remain planned.
- Operational runbooks, contribution guidance, dependency automation, and
  reproducible profiling tooling.

## [0.0.1]

- Initial research implementation. Not production-ready.
