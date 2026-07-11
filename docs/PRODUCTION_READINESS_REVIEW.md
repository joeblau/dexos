# DexOS production-readiness review

> Review date: 2026-07-11  
> Reviewed commit: `b92ffd7` (`main`)  
> Verdict: **RELEASE BLOCKED — not suitable for real funds or public trading**  
> Canonical backlog: [GitHub epic #320](https://github.com/joeblau/dexos/issues/320)

## Executive summary

DexOS contains a promising deterministic Rust component library, but it is not presently a functioning exchange node. The repository shows unusually good foundational discipline—strict dependency direction, fixed-point arithmetic in the deterministic core, unsafe/no-float gates, typed error surfaces, deterministic simulations, and a broad passing unit test suite. Those strengths are real and worth preserving.

They do not yet compose into production software. `marketd run` starts placeholder role queues that only count envelopes; it does not bind the advertised RPC/network endpoints, journal commands to durable storage, connect sequencing to execution, finalize real checkpoints, or recover state. Independently implemented subsystems also contain release-blocking authentication, consensus, custody, economic-conservation, exactly-once, state-commitment, networking, and market-resolution failures.

The production-readiness backlog now contains **99 deduplicated implementation tasks**: **36 P0**, **36 P1**, **19 P2**, and **8 P3**. Every task has code evidence, a concrete failure mode, a remediation direction, and testable acceptance criteria.

## Scope and method

The review covered approximately 53,000 lines across all workspace crates and binaries:

- architecture and subsystem composition;
- RPC, networking, replay protection, priority scheduling, wire formats, byte packing, allocation and backpressure;
- consensus, signatures, validator sets, light-client trust, discovery, oracle and custody boundaries;
- execution atomicity, orderbook semantics, fixed-point arithmetic, risk, margin, liquidation, ledger conservation and idempotency;
- perpetual, prediction, scalar and decision market lifecycle, resolution, payout and sponsor economics;
- WAL/snapshot/replay durability and corruption handling;
- benchmarks, load generation, SIMD, state roots, observability, CI, supply chain, release engineering, documentation and operator experience.

Four independent passes were consolidated and checked against the existing GitHub backlog before publication. The security-review skill has no Rust-specific reference pack, so the Rust security pass used repository invariants, standard Rust/system security practice, and direct source/runtime evidence.

## Validation performed

| Check | Result | Notes |
|---|---|---|
| `cargo test --workspace --all-targets` | Pass | TCP tests initially hit the sandbox socket restriction; they passed when local binds were permitted. |
| `cargo build --release --workspace` | Pass | Current checkout builds in release mode. |
| `cargo fmt --all -- --check` | Pass | No formatting drift. |
| Rust 1.92 `cargo clippy --workspace --all-targets -- -D warnings` | Pass | The repository-pinned toolchain passes. Homebrew Rust 1.96 introduces additional lint failures, so toolchain invocation must be reproducible. |
| `check-no-float.sh` | Pass | Deterministic core only. |
| `check-core-deps.sh` | Pass | Core remains isolated from async/network/storage. |
| `check-unsafe.sh` | Pass | Core gate passes. |
| `cargo deny check advisories bans licenses sources` | Pass with warnings | Only unmatched/unused license allow-list entries. |

### Direct runtime evidence

- `marketd replay`, `verify`, `inspect`, and `snapshot` accept nonexistent inputs, print Phase 0 stub messages, and exit successfully.
- `marketd benchmark --suite definitely-not-a-suite` runs all 22 suites, reports the invalid name, and still emits `Spec target gate: PASS`.
- The checkpoint-finality gate measures checkpoint construction rather than distributed finality; the reported p95 in the audit run was tens of microseconds.
- `market-loadgen --target 203.0.113.1:9` reports successful synthetic orders and latencies without contacting the unreachable target.
- `marketd keygen --output ...` created a private seed file with mode `0644` under the default umask; the temporary audit key was deleted immediately.

## What is already strong

- Clear workspace layering and core dependency isolation.
- Fixed-point integer types and explicit checked/saturating APIs.
- No unsafe code in the deterministic core under the current gate.
- Broad deterministic/unit/property-style coverage and good typed-error hygiene.
- Useful in-memory simulation, benchmark, observability, codec, risk and market building blocks.
- A small, auditable dependency set with a passing cargo-deny policy.

These are foundations, not evidence of production readiness until the composed system and adversarial invariants are exercised end to end.

## Principal release blockers

| ID | Area | Impact | Primary evidence | Tasks |
|---|---|---|---|---|
| PR-001 | Composition | `marketd` can appear healthy while providing no exchange service. | `crates/node/src/lib.rs:57-65,157-194,216-238` | [#312](https://github.com/joeblau/dexos/issues/312), [#348](https://github.com/joeblau/dexos/issues/348) |
| PR-002 | Authentication | Public RPC control commands and sessions do not prove key possession for all mutations. | `crates/rpc/src/command.rs:12-24`, `stub.rs:260-300`, `session.rs:19-88` | [#267](https://github.com/joeblau/dexos/issues/267), [#268](https://github.com/joeblau/dexos/issues/268), [#277](https://github.com/joeblau/dexos/issues/277) |
| PR-003 | Exactly-once / atomicity | Retries can reapply fills; multiple handlers mutate before later failure. | `orderbook/src/book.rs:94-106`, `execution/src/engine.rs:158-175,212-347` | [#322](https://github.com/joeblau/dexos/issues/322), [#324](https://github.com/joeblau/dexos/issues/324) |
| PR-004 | Consensus | Current BFT permits unsafe proposal replacement/finalization and invalid committee construction. | `consensus/src/bft.rs:247-349`, `crypto/src/quorum.rs:48-68` | [#272](https://github.com/joeblau/dexos/issues/272), [#337](https://github.com/joeblau/dexos/issues/337), [#338](https://github.com/joeblau/dexos/issues/338) |
| PR-005 | Custody / chain | Withdrawal QCs do not bind the exact request; bindings/adapters/HSM paths are not production authorization. | `custody/src/withdrawal.rs:192-215`, `binding.rs:145-172,269-339`, `chain-adapter-*/src/lib.rs` | [#271](https://github.com/joeblau/dexos/issues/271), [#273](https://github.com/joeblau/dexos/issues/273), [#332](https://github.com/joeblau/dexos/issues/332), [#333](https://github.com/joeblau/dexos/issues/333) |
| PR-006 | State / collateral | Published roots omit future-behavior state; risk and ledger balances diverge after trades. | `execution/src/engine.rs:60-149`, `ledger.rs:174-182`, `risk/src/engine.rs:521-535` | [#276](https://github.com/joeblau/dexos/issues/276), [#323](https://github.com/joeblau/dexos/issues/323) |
| PR-007 | Market economics | Non-perp fills are booked as perps; payouts, sponsor escrow, fees/funding and liquidation are incomplete or unsafe. | `execution/src/engine.rs:307-419`, `markets/src/registry.rs:147-432`, `markets/src/payout.rs` | [#321](https://github.com/joeblau/dexos/issues/321), [#323](https://github.com/joeblau/dexos/issues/323), [#325](https://github.com/joeblau/dexos/issues/325), [#345](https://github.com/joeblau/dexos/issues/345) |
| PR-008 | Resolution / oracle | Caller-selected or unauthenticated authorities can influence oracle and resolution outcomes. | `oracle/src/aggregate.rs:101-194`, `markets/src/registry.rs:462-483`, prediction/decision committee paths | [#327](https://github.com/joeblau/dexos/issues/327)–[#331](https://github.com/joeblau/dexos/issues/331) |
| PR-009 | Networking | Reliable data can be silently dropped; sequencing conflicts with priority reorder; queues permit hundreds of GiB; one TCP stream has severe HOL. | `network/src/tcp.rs:136-184`, `connection.rs:34-180`, `scheduler.rs:21-99` | [#269](https://github.com/joeblau/dexos/issues/269), [#334](https://github.com/joeblau/dexos/issues/334)–[#340](https://github.com/joeblau/dexos/issues/340) |
| PR-010 | Durability | Storage is in-memory; snapshots/logs are not authoritative recovery anchored to finalized state. | `storage/src/log.rs`, `snapshot.rs`, `replay.rs` | [#291](https://github.com/joeblau/dexos/issues/291), [#359](https://github.com/joeblau/dexos/issues/359) |
| PR-011 | Performance evidence | Gates measure proxies and fixed simulations, not the composed path. | `benchmarks/src/suites.rs`, `loadgen/src/engine.rs:24-34`, `marketd/src/main.rs:162-173` | [#353](https://github.com/joeblau/dexos/issues/353), [#360](https://github.com/joeblau/dexos/issues/360) |

## Production sequencing recommendation

1. Fail closed and compose the real node: #312, #296, #322, #291, #348.
2. Authenticate every control/value path: #267, #268, #277, #324, #333, #271, #332.
3. Restore economic and state integrity: #276, #321, #323, #325-#331, #345.
4. Complete consensus, custody, oracle and light-client trust: #272-#274, #288-#290, #328, #337-#338.
5. Make networking safe under overload: #266, #269-#270, #334-#340, #354-#356.
6. Add durable operations, observability and release artifacts: #291, #293-#294, #348, #350-#352, #359.
7. Optimize only against trustworthy production-path measurements: #341-#344, #353, #357-#363.

Do not treat P2/P3 optimization work as permission to defer any P0. Real-funds testing should remain disabled until every release gate in epic #320 is satisfied.

## P0 — release blockers

- [#266](https://github.com/joeblau/dexos/issues/266) — Encrypt peer traffic after handshake (Noise/AEAD or mTLS)
- [#267](https://github.com/joeblau/dexos/issues/267) — Require signed RPC control commands; reject unsigned trade/withdraw
- [#268](https://github.com/joeblau/dexos/issues/268) — Fix session privilege escalation (admin ops must not use trading sessions)
- [#269](https://github.com/joeblau/dexos/issues/269) — Never silently drop reliable frames under inbound backpressure
- [#270](https://github.com/joeblau/dexos/issues/270) — Cap RPC concurrent connections, per-IP limits, and I/O timeouts
- [#271](https://github.com/joeblau/dexos/issues/271) — Bind custody withdrawal QC to full withdrawal authorization digest
- [#272](https://github.com/joeblau/dexos/issues/272) — Complete HotStuff/PBFT-safe consensus (chained QCs, locks, view-change)
- [#273](https://github.com/joeblau/dexos/issues/273) — Replace mock HSM/soft custody keys with real HSM/KMS backends
- [#274](https://github.com/joeblau/dexos/issues/274) — Production chain adapters must verify EVM/SVM finality (not mock self-assertions)
- [#275](https://github.com/joeblau/dexos/issues/275) — Make order matching transactional under capacity failures
- [#276](https://github.com/joeblau/dexos/issues/276) — Unify ledger/risk/positions into committed state roots
- [#277](https://github.com/joeblau/dexos/issues/277) — Enforce session keys on all trading and withdraw commands
- [#278](https://github.com/joeblau/dexos/issues/278) — Implement real liquidation pipeline (cancel, close, insurance, socialization)
- [#279](https://github.com/joeblau/dexos/issues/279) — Include multi-outcome/payout positions in margin and liquidation
- [#280](https://github.com/joeblau/dexos/issues/280) — Harden marketd keygen entropy and never discard private seeds
- [#312](https://github.com/joeblau/dexos/issues/312) — Bootstrap marketd into a real production node
- [#321](https://github.com/joeblau/dexos/issues/321) — Enforce value-conserving payout vectors and canonical scalar outcome ordering
- [#322](https://github.com/joeblau/dexos/issues/322) — Make every execution command atomic across ledger, risk, book, and state tree
- [#323](https://github.com/joeblau/dexos/issues/323) — Back sponsor stake, bootstrap liquidity, and complete sets with ledger escrow
- [#324](https://github.com/joeblau/dexos/issues/324) — Make command idempotency receipt-based, durable, and payload-bound
- [#325](https://github.com/joeblau/dexos/issues/325) — Route fills by instrument type and settle claims, premiums, and perps correctly
- [#326](https://github.com/joeblau/dexos/issues/326) — Risk market orders from executable depth, never an ignored price field
- [#327](https://github.com/joeblau/dexos/issues/327) — Bind market resolution to committed rules, rounds, and challenge state
- [#328](https://github.com/joeblau/dexos/issues/328) — Authorize oracle producers and derive real source diversity
- [#329](https://github.com/joeblau/dexos/issues/329) — Verify objective sponsor-slashing evidence before moving escrow
- [#330](https://github.com/joeblau/dexos/issues/330) — Authenticate prediction resolver votes and bind the complete resolution digest
- [#331](https://github.com/joeblau/dexos/issues/331) — Authenticate decision authorities and enforce committed guards and time windows
- [#332](https://github.com/joeblau/dexos/issues/332) — Verify chain-adapter withdrawal authorization and reserve nonces atomically
- [#333](https://github.com/joeblau/dexos/issues/333) — Require current account-owner approval for every wallet binding
- [#334](https://github.com/joeblau/dexos/issues/334) — Bound transport memory by bytes per peer, class, and process
- [#335](https://github.com/joeblau/dexos/issues/335) — Separate reliable sequence spaces from priority reordering
- [#336](https://github.com/joeblau/dexos/issues/336) — Implement independent QUIC streams and real datagrams to eliminate cross-class HOL
- [#337](https://github.com/joeblau/dexos/issues/337) — Make validator-set construction canonical and overflow-safe
- [#341](https://github.com/joeblau/dexos/issues/341) — Replace full-book rehashing with incremental authenticated market roots
- [#342](https://github.com/joeblau/dexos/issues/342) — Reject sparse external IDs before dense vector allocation
- [#353](https://github.com/joeblau/dexos/issues/353) — Gate performance claims on the fully composed production path

## P1 — required production hardening

- [#281](https://github.com/joeblau/dexos/issues/281) — Network handshake: CSPRNG nonces, timeouts, membership on accept
- [#282](https://github.com/joeblau/dexos/issues/282) — TCP keepalive, idle timeout, and reconnect backoff with jitter
- [#283](https://github.com/joeblau/dexos/issues/283) — Wire PeerDedup + reliable gap detection with connection epochs
- [#284](https://github.com/joeblau/dexos/issues/284) — Harden discovery against Sybil, unbounded strings, and bad reputation incentives
- [#285](https://github.com/joeblau/dexos/issues/285) — RPC session install, bounded idempotency store, and authenticated streams
- [#286](https://github.com/joeblau/dexos/issues/286) — TLS 1.3 on public RPC + lower payload/structural decode caps
- [#287](https://github.com/joeblau/dexos/issues/287) — Crypto: enforce secp256k1 low-S; implement real EIP-712 and EIP-1271
- [#288](https://github.com/joeblau/dexos/issues/288) — Light-client validator-set transitions must be quorum-proven
- [#289](https://github.com/joeblau/dexos/issues/289) — Custody settle + wallet authorization must be mandatory and verified
- [#290](https://github.com/joeblau/dexos/issues/290) — Enforce equivocation/fork evidence (halt, slash hook, evidence broadcast)
- [#291](https://github.com/joeblau/dexos/issues/291) — Durable on-disk WAL with fsync policy + crypto integrity (not CRC-only RAM log)
- [#292](https://github.com/joeblau/dexos/issues/292) — Gate trading on market lifecycle + oracle health; reserve IM for resting orders
- [#293](https://github.com/joeblau/dexos/issues/293) — Wire observability metrics + livez/readyz into marketd
- [#294](https://github.com/joeblau/dexos/issues/294) — Production shutdown: SIGTERM, drain deadline, subsystem flush
- [#295](https://github.com/joeblau/dexos/issues/295) — Implement real thread pinning; fail loud when pin_threads=true unsupported
- [#296](https://github.com/joeblau/dexos/issues/296) — Release profile panic=abort + operator stubs fail closed
- [#297](https://github.com/joeblau/dexos/issues/297) — Config validation: addresses, storage bounds, validators.toml, unused flags
- [#298](https://github.com/joeblau/dexos/issues/298) — CI production gates: --locked, fuzz, coverage, docs, perf, state-root script
- [#338](https://github.com/joeblau/dexos/issues/338) — Bound consensus input windows and prune finalized state
- [#339](https://github.com/joeblau/dexos/issues/339) — Authorize traffic classes and use starvation-safe byte scheduling
- [#340](https://github.com/joeblau/dexos/issues/340) — Preserve unsent datagram batches and integrate MTU-aware batching
- [#343](https://github.com/joeblau/dexos/issues/343) — Make risk updates proportional to affected accounts and positions
- [#344](https://github.com/joeblau/dexos/issues/344) — Make conditional orders durable, owner-bound, and atomic through execution
- [#345](https://github.com/joeblau/dexos/issues/345) — Implement sequenced perpetual funding and fee settlement
- [#346](https://github.com/joeblau/dexos/issues/346) — Enforce economic prerequisites on halt, resume, and archive
- [#347](https://github.com/joeblau/dexos/issues/347) — Reject duplicate node roles before spawning handlers
- [#348](https://github.com/joeblau/dexos/issues/348) — Supervise critical subsystem tasks and fail readiness on unexpected exit
- [#349](https://github.com/joeblau/dexos/issues/349) — Negotiate wire versions, network identity, and rolling-upgrade capabilities
- [#350](https://github.com/joeblau/dexos/issues/350) — Publish reproducible signed production artifacts with SBOM and rollback metadata
- [#352](https://github.com/joeblau/dexos/issues/352) — Prove deterministic compatibility across supported CPU architectures
- [#354](https://github.com/joeblau/dexos/issues/354) — Isolate synchronous RPC dispatch and bound in-flight work by bytes
- [#355](https://github.com/joeblau/dexos/issues/355) — Make RPC stream fanout byte-bounded, sharded, and copy-light
- [#356](https://github.com/joeblau/dexos/issues/356) — Consolidate bounded canonical wire primitives and pack quorum certificates
- [#357](https://github.com/joeblau/dexos/issues/357) — Build canonical Merkle and oracle roots in O(N) or incrementally
- [#358](https://github.com/joeblau/dexos/issues/358) — Avoid repeated scalar signature verification during QC formation
- [#359](https://github.com/joeblau/dexos/issues/359) — Bound storage decoding and index recovery by segment and offset

## P2 — important optimization, DX, and verification

- [#299](https://github.com/joeblau/dexos/issues/299) — Network write coalescing + frame buffer pooling (drop per-frame flush)
- [#300](https://github.com/joeblau/dexos/issues/300) — Unify PeerId vs NodeId identity; classify disconnect reasons + metrics
- [#301](https://github.com/joeblau/dexos/issues/301) — Orderbook hot-path: cancel-all/liq queue complexity + fill buffer allocs
- [#302](https://github.com/joeblau/dexos/issues/302) — Durable client-id idempotency + TWAP driven by sequenced time
- [#303](https://github.com/joeblau/dexos/issues/303) — Fixed-point IM/fees round away from zero; document dust policy
- [#304](https://github.com/joeblau/dexos/issues/304) — Consensus epoch pipeline freeze + vote epoch/phase binding
- [#305](https://github.com/joeblau/dexos/issues/305) — Unify withdrawal certificate domain tags across custody and chain-adapter
- [#306](https://github.com/joeblau/dexos/issues/306) — Structured JSON logging + real Prometheus exposition
- [#307](https://github.com/joeblau/dexos/issues/307) — Feature flags: strip loadgen/mocks from prod marketd; mock-chains gate
- [#308](https://github.com/joeblau/dexos/issues/308) — Loadgen: wire --market; network driver or rename to offline simulator
- [#309](https://github.com/joeblau/dexos/issues/309) — Docs/ops: runbooks, CHANGELOG, LICENSE, SECURITY honesty, CONTRIBUTING
- [#310](https://github.com/joeblau/dexos/issues/310) — Dependabot + scheduled cargo-deny/audit; ban list for unwanted crates
- [#311](https://github.com/joeblau/dexos/issues/311) — Flamegraph/perf tooling + release-with-debug profile
- [#351](https://github.com/joeblau/dexos/issues/351) — Make observability counters concurrency-correct and metric names type-safe
- [#360](https://github.com/joeblau/dexos/issues/360) — Fix benchmark timing methodology and record complete provenance
- [#361](https://github.com/joeblau/dexos/issues/361) — Implement measurable SIMD kernels or remove no-op production controls
- [#362](https://github.com/joeblau/dexos/issues/362) — Plan FOK/deep matches once and byte-bound fill receipts
- [#363](https://github.com/joeblau/dexos/issues/363) — Make oracle aggregation linear-bounded with reusable scratch
- [#364](https://github.com/joeblau/dexos/issues/364) — Pin GitHub Actions to immutable SHAs and declare least privilege

## P3 — follow-up hardening

- [#313](https://github.com/joeblau/dexos/issues/313) — RPC DX: MessageTooLarge error class; codec error detail; stream topic caps
- [#314](https://github.com/joeblau/dexos/issues/314) — Make Connection replay mutex poison-safe
- [#315](https://github.com/joeblau/dexos/issues/315) — Crypto hygiene: length-prefix hash_node; real or renamed batch_verify; document n=64
- [#316](https://github.com/joeblau/dexos/issues/316) — SIMD kernels never feed wrapping sums into solvency decisions
- [#317](https://github.com/joeblau/dexos/issues/317) — CI DX: rust-cache, harden safety scripts, expand .gitignore
- [#318](https://github.com/joeblau/dexos/issues/318) — MSRV policy + optional multi-OS CI matrix
- [#319](https://github.com/joeblau/dexos/issues/319) — Custody session error taxonomy (revoke vs expiry vs replay)
- [#365](https://github.com/joeblau/dexos/issues/365) — Make replay-window advancement O(1) and bound loopback admission

## Limitations and follow-up assurance

This was a source-grounded engineering review, not a formal proof, independent cryptographic audit, external penetration test, chain-specific mainnet verification, or benchmark on production hardware. Before real funds, complete those independent reviews after the P0/P1 architecture is implemented; auditing mocks or disconnected components cannot establish end-to-end safety.

