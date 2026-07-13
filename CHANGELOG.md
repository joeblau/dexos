# Changelog

All notable changes are recorded here. This project follows Keep a Changelog and
uses Semantic Versioning after the first stable release. During `0.x`, minor
versions may contain breaking changes and every such change must be called out.

## [Unreleased]

### Changed

- **Breaking consensus hard fork:** replaced the legacy engine with Minimmit.
  Committees now require `n ≥ 5f+1` (minimum 6 for `f=1`) and explicit unit
  weights; `M=2f+1` advances views while `L=n-f` finalizes. Six wire messages
  (`Propose`, `Notarize`, `Nullify`, `Notarization`, `Nullification`, and
  `ExecAttest`) use `u16` validator indices. The engine-mode toggle is retired,
  and an execution L-certificate remains mandatory after ordering finality.
  This wire/threshold change requires a coordinated restart; see
  [the migration runbook](docs/runbooks/MINIMMIT_HARD_FORK.md).

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
