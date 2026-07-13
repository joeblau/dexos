# DexOS Minimmit Consensus — Protocol Design & Migration Spec

**Status:** interim ground truth. This document pins the Minimmit protocol and the
HotStuff→Minimmit migration contract for every issue in the migration epic (#509).
Downstream issues cite section numbers here (`§N`) instead of restating the protocol.
It remains authoritative until the formal quint model lands or its deferral is
documented (#544). Protocol-correctness review by a second engineer is required
before Phase 2 rule work (R1–R7) begins.

Minimmit reference: arXiv 2508.10862. Terminology below is **locked** for all DexOS
artifacts; where upstream sources disagree, this document wins.

---

## §1 Terminology (LOCKED)

| Concept | arXiv | commonware blog | **DexOS (canonical)** | Value |
|---|---|---|---|---|
| Small quorum → form cert → **advance view** | M | Q | **M** | `2f+1` (weighted `2B+1`) |
| Large quorum → **finalize** | L | L | **L** | `n−f` (weighted `W−B`) |

Never say "quorum certificate threshold" unqualified — always **M-cert** (advance)
or **L-cert** (finalize). Substance is identical across sources: *small quorum
advances the view, large quorum finalizes.*

## §2 Fault, network, and sizing model

- Partial synchrony: unknown GST, **known Δ** (post-GST message delay bound).
  Δ lives in node config (`delta_ms`, §13.4) and is consumed **only** by the
  node/network driver — never by the consensus state machine (§7).
- `n` replicas, at most `f` Byzantine, **`n ≥ 5f+1`**; unit-weight derivation
  `f = floor((n−1)/5)`.
- Two thresholds:
  - **M = 2f+1** — assembling a `Notarization` or `Nullification` certificate
    advances the view.
  - **L = n−f** (`= 4f+1` at the tight `n = 5f+1`) — finalizes a block and its
    ancestors.
- **Honest-intersection lemma:** `L + M − n = (n−f) + (2f+1) − n = f+1 ≥ 1`. Any
  M-quorum and L-quorum share at least one honest replica; that replica, bound by
  vote-once (§8), is the root of safety.

### §2.1 Why 5f+1 (do not weaken)

- Safety needs `M ≥ 2f+1` (any M-quorum holds ≥ f+1 honest, so two conflicting
  M-certs would share an honest double-voter — impossible under vote-once).
- A *meaningful separation* `M < L` needs only `n ≥ 3f+2`, but Minimmit mandates
  `n ≥ 5f+1` to obtain the **2f gap** (`L − M = 2f` at the tight bound) that the
  safety+liveness argument (mutual exclusion + contradiction progress, §2.2, §8 R6)
  relies on. Do **not** "optimize" to `3f+1`: at `n = 3f+1`, `L = 2f+1 = M` and the
  design collapses to a single-threshold protocol.

### §2.2 Mutual-exclusion algebra (assert these in tests)

With `n = 5f+1`, `M = 2f+1`, `L = 4f+1`:

- **Finalize ⇒ no nullification (same view).** If block `c` reaches L notarize
  weight in view `v`, then ≥ `L − f = 3f+1` honest replicas notarized `c`. Honest
  non-notarizers number ≤ `(n−f) − (3f+1) = f`; with `f` Byzantine, at most `2f < M`
  weight can nullify ⇒ no `Nullification(v)` can form.
- **Nullification ⇒ no finalize (same view).** If nullify reaches `M = 2f+1` in
  `v`, at most `n − M = 3f` weight remains to notarize any single block ⇒
  `3f < L = 4f+1` ⇒ nothing finalizes in `v`.

**Use `n − M = 3f` in this algebra everywhere** (an earlier distilled note carried a
`4f` typo; `3f` is correct and is also the R6 justification, §8).

### §2.3 Weighted generalization (DexOS validators are weighted)

`Validator { public_key: [u8;32], weight: u64 }`; `ValidatorSet` sums weight. Map:

- `W = ValidatorSet::total_weight()`, `B` = configured Byzantine **weight** bound.
- Requirement **`W ≥ 5B+1`**; **`M = 2B+1`**, **`L = W−B`** (#511).
- Committees violating the bound are rejected at construction with
  `QuorumError::InsufficientSizing` (#512).
- Equal-unit-weight committees recover `B = f`, `W = n`, `M = 2f+1`, `L = n−f`.

### §2.4 Sizing envelope: MAX_VALIDATORS = 16 (DECIDED, #546)

**Decision:** the validator cap drops **64 → 16** and `QuorumCertificate.signer_bitmap`
shrinks **u64 → u16** (#546). The product needs ≤ 16 validators; the old 64 cap was
dictated purely by the u64 bitmap. The alternative (retain the 64 cap, `f_max = 12`)
was considered in the initial migration analysis and rejected.

| Quantity | Value at the 16 cap |
|---|---|
| `MAX_VALIDATORS` (crypto + consensus, lockstep-asserted) | **16** |
| `signer_bitmap` | **u16** (packed QC bitmap header 8 → 2 bytes LE; `QC_WIRE_VERSION` bumped) |
| Minimum committee (`f = 1`) | **`n = 6`** (M = 3, L = 5) — was ≥ 4 under HotStuff |
| `f_max` at `n = 16` | **3** (`5·3+1 = 16`), giving **M = 7**, **L = 13** |
| Byzantine tolerance at cap | 3/16 ≈ **19%** vs HotStuff 3f+1's 5/16 ≈ 31% |
| L-cert size at `n=16, f=3` | 32 + 2 + 13·64 ≈ **866 B**; M-cert ≈ 482 B |

Surface the fault-tolerance-for-latency trade (~20% vs ~33%) loudly in
`docs/SECURITY.md` and the cutover PR (#543). All `validator_index` /
`proposer_index` wire fields are **u16** (§4.3), applied uniformly (#517).

`CrashTolerant` mode has no Minimmit analog: **`ConsensusMode` is retired** (§13.1).

## §3 Module map (fixed layout)

The completed implementation is laid out as follows:

- `crates/crypto/src/quorum.rs` — `minimmit_thresholds` (#511), sizing guard
  (#512), dual-threshold test helper (#514), u16 bitmap + `MAX_VALIDATORS = 16`
  (#546).
- `crates/consensus/src/minimmit/mod.rs` — module root. The first
  consensus-touching issue creates it and adds `pub mod minimmit;` to
  `crates/consensus/src/lib.rs` **unconditionally** — the `minimmit` cargo feature
  (#530) lives in `simulation`/`benchmarks` and gates engine *selection*, never
  this module's compilation.
- `crates/consensus/src/minimmit/committee.rs` (#513), `digest.rs` (#515),
  `block.rs` (#516), `wire.rs` (#517, #518, #519, #520), `replica.rs`
  (#521–#526, #528, #529), `tests.rs` (#527). Extend these files rather than
  adding parallel ones.

## §4 Wire messages

All wire types: `serde` + `codec` (postcard) encode/decode; 64-byte signatures via
the existing `sig64` adapter; every digest is domain-separated through
`crypto::hash_domain` with **little-endian** integer encoding, so results are
bit-identical across architectures. Postcard is non-self-describing, so decoding
branches on the `msg_type` tag (§4.3).

### §4.1 Domains & digests

New domain constants (they *replace* `DOMAIN_VOTE/PROPOSAL/TIMEOUT` at Phase 5;
until then they coexist):

```text
DOMAIN_PROPOSE   = b"dexos:consensus:minimmit:propose:v1"
DOMAIN_NOTARIZE  = b"dexos:consensus:minimmit:notarize:v1"
DOMAIN_NULLIFY   = b"dexos:consensus:minimmit:nullify:v1"
DOMAIN_EXEC_COMMIT = b"dexos:consensus:exec-commit:v1"   // RETAINED, unchanged
```

Digest preimages (`‖` = concat, all integers `to_le_bytes()`):

```text
notarize_digest = hash_domain(DOMAIN_NOTARIZE, epoch_le ‖ view_le ‖ block_hash[32])
nullify_digest  = hash_domain(DOMAIN_NULLIFY,  epoch_le ‖ view_le)
propose_auth    = hash_domain(DOMAIN_PROPOSE,  epoch_le ‖ view_le ‖ block_hash[32]
                                               ‖ parent_hash[32] ‖ parent_view_le)
execution_commitment_digest = hash_domain(DOMAIN_EXEC_COMMIT,
                                epoch_le ‖ view_le ‖ height_le ‖ block_hash[32]
                                ‖ execution_root[32])     // RETAINED (bft.rs:133)
```

There is **no separate certificate domain**: a certificate's
`QuorumCertificate.message` *is* the notarize/nullify/exec digest it aggregates.
`block_hash` commits to the block header **including its `height`** (#516), so
`notarize_digest` safely drops the height/phase fields the old `vote_digest`
carried. `epoch` is bound into every digest so no vote or certificate can cross an
epoch / validator-set boundary (§11).

### §4.2 `ParentRef` and the ⊥ sentinel

```text
ParentRef { parent_hash: Hash, parent_view: u64 }
```

- Genesis parent = `{ parent_hash: genesis_hash, parent_view: ⊥ }` where
  **`⊥` is encoded as `u64::MAX`** — a reserved sentinel. It must be rejected
  anywhere a *real* view is expected, and it orders **below** every real view for
  the interval logic in `valid_parent` (§6.4).

### §4.3 Message set: five consensus messages + the execution attestation

`msg_type: u16` tags ride the existing `codec::Frame` on `TrafficClass::Consensus`
(P0 lane) — **no structural network/codec change** (§13.6). Tag constants live in
one place (#518).

| Message | msg_type | Fields |
|---|---|---|
| `Propose` | `0x0001` | `{ epoch: u64, view: u64, block: BlockHeader, block_hash: Hash, parent: ParentRef, proposer_index: u16, notarize_sig: [u8;64], propose_sig: [u8;64] }` |
| `Notarize` | `0x0002` | `{ epoch: u64, view: u64, block_hash: Hash, validator_index: u16, signature: [u8;64] }` |
| `Nullify` | `0x0003` | `{ epoch: u64, view: u64, validator_index: u16, signature: [u8;64] }` |
| `Notarization` | `0x0004` | `{ epoch: u64, view: u64, block_hash: Hash, cert: Certificate }` — `cert.message == notarize_digest` |
| `Nullification` | `0x0005` | `{ epoch: u64, view: u64, cert: Certificate }` — `cert.message == nullify_digest` |
| `ExecAttest` | `0x0006` | `{ epoch: u64, view: u64, height: u64, block_hash: Hash, execution_root: Hash, validator_index: u16, signature: [u8;64] }` — signs `execution_commitment_digest` (#520) |

Notes:

- **The propose IS the leader's implicit notarize.** `notarize_sig` signs
  `notarize_digest(epoch, view, block_hash)` — the identical preimage a follower's
  `Notarize` signs — so the leader's vote counts in the same tally. `propose_sig`
  signs `propose_auth` and authenticates the parent binding (equivocation / fork
  evidence uses it). A follower verifies **both**.
- `ExecAttest` is the retained per-validator execution vote (§10). It is
  **mandatory**, not optional: without an exec L-cert a height never reaches
  `Finalized`.
- An in-crate `ConsensusMessage` enum gives the node a single
  `encode → (u16, Vec<u8>)` / `decode(u16, &[u8])` entry point (#518); decode is
  total (never panics on arbitrary bytes).

### §4.4 `Proof`

```text
Proof = Notarization | Nullification
```

The union used for `proofs[view]` storage, re-dissemination (R7), and the
`select_parent` / `valid_parent` predicates. It is **not** a standalone wire type.

### §4.5 Certificates: one type, two thresholds

Both cert kinds reuse `crypto::QuorumCertificate`
(`message: Hash, signer_bitmap: u16, signatures: Vec<[u8;64]>` after #546; packed
wire form `message[32] ‖ signer_bitmap_le[2] ‖ sig[64]×popcount`).
`ValidatorSet::try_with_threshold(validators, threshold)` (quorum.rs:136) already
verifies a QC at an *arbitrary* threshold — **an M-cert and an L-cert are the same
type at two thresholds; zero new crypto primitives are required** (§13.2).

`Certificate` is a **type alias** (`= QuorumCertificate` today) held behind
`MinimmitCommittee::{assemble, verify}` — the BLS deferral seam (#513, #545, §13.2).
Certificate verification (#519) asserts `cert.message ==` the recomputed digest,
then verifies against the appropriate set:

- `Notarization` / `Nullification` accepted at **M** (`advance_set`); a
  notarization additionally meeting **L** (`finalize_set`) triggers finalization
  (§8 R4).
- Exec cert verified at **L** (`finalize_set`) only (§10).

## §5 Replica state

Pure synchronous struct in `crates/consensus/src/minimmit/replica.rs` (#521). No
clock, no I/O, no async, no float. All maps are `BTreeMap` (deterministic
iteration).

```text
MinimmitReplica {
  epoch: u64,                               // validator-set generation
  committee: MinimmitCommittee,             // §5.1
  view: u64,                                // starts 0
  notarized: Option<Hash>,                  // block notarized THIS view (⊥ = None)
  nullified: bool,                          // nullified THIS view
  proofs: BTreeMap<u64, Proof>,             // view -> the single chosen proof
  notarize_votes: BTreeMap<u64, Tally>,     // view -> per-block notarize tallies
  nullify_votes:  BTreeMap<u64, Tally>,     // view -> nullify tally (STRICTLY separate, §12)
  exec_votes: BTreeMap<u64 /*height*/, Tally>, // exec attestations toward the L exec-cert (§10)
  finality: BTreeMap<u64 /*height*/, FinalityStage>, // consensus-final -> exec-pending -> finalized (§10)
  finalized_tip: (u64 /*view*/, Hash),
  chain: BTreeMap<u64 /*height*/, Hash>,    // finalized blocks by height
}
```

The 2Δ timer is **not** stored here — it is driven from outside (§7). Tallies
carry the existing DoS defenses from `vote.rs` (`CollectorWindow` windowed
admission, `DEFAULT_VOTE_QUOTA`, equivocation detection → `SlashEvidence`,
offender-halt), retagged to `(validator_index, epoch, view)` (#523).

### §5.1 `MinimmitCommittee` (#513)

One member `Vec<Validator>` validated **once**, wrapped into:

- `advance_set = try_with_threshold(members, M)`
- `finalize_set = try_with_threshold(members, L)`
- cached `CachedEd25519Key` per validator for hot-path `verify_cached`.

Constructor takes explicit Byzantine **weight** `B` (unit convenience derives `f`),
rejects `W < 5B+1` / `n < 5f+1` / `n > 16` (#512, #546). `assemble(votes) →
Certificate` and `verify(cert, threshold) → bool` live behind the committee — the
core's R4/R5 never touch certificate internals (§13.2).

**Canonical-set rule (LOCKED):** `ValidatorSet::commitment()` binds the threshold,
so `advance_set` and `finalize_set` hash **differently**. The **`finalize_set` (L)
is the single canonical set** feeding every commitment: checkpoints, epoch
transitions (`validator_set_transition_digest`), and light-client verification
(#538, #539). Feeding the M-set anywhere silently breaks light clients.

## §6 Helper functions & locking predicates

### §6.1 `leader(view) → validator_index` — epoch-mixed (RECONCILED)

The Minimmit paper says `v mod n`; DexOS code says
**`(epoch + view) mod n`** (`Committee::leader`, vote.rs:512, `wrapping_add`).
**Decision: keep epoch-mixing; the spec text is corrected, not the code.**
Epoch-mixing rotates the starting proposer each epoch, changes nothing about the
protocol's guarantees (any deterministic, commonly-computable rotation works), and
preserves existing DexOS semantics. All tests and the quint model (#544) must use
the epoch-mixed expectation.

### §6.2 `enter_view(next)`

If `next > view`: `view = next; notarized = None; nullified = false;` and emit
`Effect::ArmTimer { view: next }` (§7). If additionally `leader(next) == self` and
`select_parent(next)` is `Some(parent)`, emit `Effect::NeedProposal { parent }`
(§7, R1). Idempotent no-op for `next ≤ view`.

### §6.3 `select_parent(v) → Option<ParentRef>`

Walk views `v−1, v−2, …, 0`:

- first view `i` where `proofs[i]` is `Notarization(c', i)` ⇒
  `Some({ parent_hash: c', parent_view: i })`;
- skip views whose proof is a `Nullification`;
- if the walk exhausts every view down to 0 with only nullifications ⇒
  `Some({ genesis_hash, ⊥ })`;
- if any view in the walk has **no proof at all** ⇒ `None` — cannot propose yet;
  wait for re-dissemination (R7) to fill the gap.

### §6.4 `valid_parent(v, parent) → bool`

True iff **both**:

1. every view `j ∈ (parent.parent_view, v)` (exclusive both ends; for
   `parent_view = ⊥` this means every `j ∈ [0, v)`) has a `Nullification(j)` in
   `proofs`, **and**
2. `proofs[parent.parent_view]` is a `Notarization(parent.parent_hash,
   parent.parent_view)` — or `parent.parent_view == ⊥` with
   `parent.parent_hash == genesis_hash`.

This is Minimmit's locking rule. It **replaces** HotStuff's high-QC/locking:
a proposal may only skip views that provably went nowhere.

### §6.5 Genesis & view-0 bootstrap

The genesis block (height 0, well-known `genesis_hash`) is injected at replica
construction; it is finalized by definition (`chain[0] = genesis_hash`,
`finalized_tip = (⊥, genesis_hash)` conceptually — no proof object exists for it).
The replica starts at `epoch = e₀, view = 0`; construction behaves like
`enter_view(0)`: it emits `ArmTimer { view: 0 }` (and `NeedProposal` if
`leader(0) == self`). The first proposal's parent is `{ genesis_hash, ⊥ }`.
`⊥ = u64::MAX` is rejected as a real view everywhere else (§4.2).

### §6.6 `prune(view)`

Drop `notarize_votes`, `nullify_votes`, and `proofs` entries for keys below the
horizon (reuse `DEFAULT_VIEW_HORIZON`-style bounding). Called after finalization
(R4). Exec tallies prune when their height finalizes (§10).

## §7 The clock-free reactor contract (LOCKED)

**The core is clock-free and event-driven; the node owns all wall-clock time.**
The state machine never reads a clock, never sleeps, never does I/O, and never
invokes callbacks — this preserves bit-identical replay. The 2Δ timer, message
delivery, block **build**, and block **verify** are all driven from the
node/network layer; verification results enter as **data**, never as an in-core
call.

```text
fn step(&mut self, input: Input) -> Vec<Effect>

Input ∈ {
  Message(ConsensusMessage),                       // delivered by the network
  TimerFired { view: u64 },                        // the node's 2Δ timer expired
  Tick,                                            // periodic driver pulse (R7)
  ProposalVerified { view: u64, block_hash: Hash, valid: bool },  // §7.1
}

Effect ∈ {
  Broadcast(ConsensusMessage),
  ArmTimer { view: u64 },                          // node sets an OS timer for 2Δ
  CancelTimer { view: u64 },
  NeedProposal { parent: ParentRef },              // node builds + signs + re-injects (§7.2)
  ConsensusFinal { block: Hash, height: u64 },     // L-notarization reached (§10)
  Finalized { block: Hash, height: u64 },          // exec L-cert also landed (§10)
  Slash(SlashEvidence),
}
```

(#521 owns the final field lists; the shapes above are the contract.)

Contract rules:

- `enter_view(next)` emits `ArmTimer { view: next }`. The **node** translates that
  into an OS timer firing after `2Δ` (`delta_ms` config knob, §13.4) and, on
  expiry, calls `step(Input::TimerFired { view })`. R3 decides purely whether to
  nullify; a stale `TimerFired` for a superseded view is a guard no-op.
- Forming or ingesting a certificate emits `CancelTimer { view }`; the node
  cancels the OS timer (a late fire is harmless — R3's guard rejects it — but
  cancelling keeps traffic clean).
- R7 re-dissemination is driven by a periodic node **`Tick`** (e.g. every Δ). The
  cadence is a node concern: different cadences change *when* messages go out,
  never the finalized state.
- **Determinism guarantee:** given the same ordered `Input` sequence, the core
  produces the same `Effect` sequence and the same finalized chain on every
  node/arch — because 2Δ, delivery, and cadence are inputs, not core decisions.
  The simulator injects `TimerFired`/`Tick` from its deterministic scheduler
  (#531, #532).

### §7.1 The verify-injection seam

Block validity (execution/state checks) requires state the core does not own.
On a `Propose` passing the stateless guards (§8 R2), the core **buffers** the
pending proposal and waits. The node runs `verify(block, parent_hash)` outside the
core and injects `Input::ProposalVerified { view, block_hash, valid }`. R2
completes on that input. `verify` is **never** called inside `step()`.

### §7.2 The propose-build seam

Leaders don't build blocks in-core. `enter_view` emits
`NeedProposal { parent }` when `leader == self`; the node builds the
`BlockHeader` deterministically, signs `notarize_sig` + `propose_sig` via a pure
constructor helper exported by the crate, and re-injects the result as
`Input::Message(Propose)`. The leader's own propose thus flows through the same
admission/tally path as everyone else's (R1), keeping the core I/O-free and the
leader's implicit notarize in the same tally.

### §7.3 Node wall-clock driver — a named Phase-4 deliverable (#540)

The node-side loop (`ArmTimer → OS timer → TimerFired`, periodic `Tick`,
`Broadcast → network`, `NeedProposal → build/sign → Message`,
`ProposalVerified` injection, `ConsensusFinal`/`Finalized` consumption) is its own
deliverable in `crates/node` (#540). Until then, `simulation` is the only driver.
The old external view-change surface (`on_timeout` / `advance_view`) does **not**
carry over — any node code driving views externally would double-advance (§12).

## §8 Rules R1–R7

All rules are pure transitions `(state, input) → (state', Vec<Effect>)`.

**R1 — Propose** (leader of view `v`, on entering `v`):

1. `parent = select_parent(v)`; if `None` ⇒ do nothing (wait for R7 to fill
   proofs). Otherwise `enter_view` emitted `NeedProposal { parent }` (§7.2).
2. Node builds `block`, signs both sigs, re-injects `Propose`. On admitting its
   own `Propose`, the core sets `notarized = Some(block_hash)`, emits
   `Broadcast(Propose)`, and feeds the leader's implicit notarize into the R4
   tally.

**R2 — Notarize** (on the first valid `Propose` from `leader(v)` for current view
`v`, completed by `ProposalVerified`):

Stateless guards, all required, checked on `Message(Propose)`:
`propose.proposer_index == leader(v)` ∧ both signatures verify (`notarize_sig`
over `notarize_digest`, `propose_sig` over `propose_auth`) ∧
`valid_parent(v, propose.parent)` ∧ `notarized == None` ∧ `!nullified`. If they
pass, buffer the proposal (§7.1). On `ProposalVerified { view: v, block_hash,
valid: true }` with the guards **still** holding (the timer may have nullified
meanwhile): `notarized = Some(block_hash)`; emit
`Broadcast(Notarize { epoch, v, block_hash, self, sig })`. `valid: false` ⇒ drop
the pending proposal; never notarize that hash.

A second, conflicting `Propose` from the same leader ⇒ record equivocation, emit
`Slash(SlashEvidence)` (proposal fork, provable via the two `propose_sig`s), and
do **not** notarize the second.

**R3 — Nullify by timeout** (on `TimerFired { view: v }` where `v == view`):

Guard `notarized == None ∧ !nullified` ⇒ `nullified = true`; emit
`Broadcast(Nullify { epoch, v, self, sig })`. Guard fails or stale view ⇒ no-op.

**R4 — Notarization: form + INGEST + finalize.** Two symmetric entry points
(#525) — the ingest path is **mandatory**, not an optimization (§12):

- *Form:* on each admitted `Notarize(c, v)` (including the leader's implicit
  one), add to `notarize_votes[v][c]` (dedup by `validator_index`; a second
  distinct block from the same validator ⇒ equivocation/slash, drop). When
  `weight(notarize_votes[v][c]) ≥ M` and `proofs[v]` is unset: assemble
  `Notarization(c, v)` (a `Certificate` over `notarize_digest`), store it in
  `proofs[v]`, emit `Broadcast(Notarization)`, emit `CancelTimer { v }`, then
  `enter_view(v+1)`.
- *Ingest:* on an inbound `Notarization(c, v)` message whose cert verifies (§4.5)
  and `proofs[v]` is unset: store it in `proofs[v]`, emit `CancelTimer { v }`,
  `enter_view(v+1)`. (Re-broadcast is R7's job.)
- *Finalize:* when notarize weight for `c` in `v` reaches **L** (via the tally, or
  an ingested cert whose signer weight meets `finalize_set`'s bar), finalize `c`
  and every not-yet-final ancestor: set `finalized_tip = (v, c)`; per newly-final
  height emit `ConsensusFinal { block, height }` and mark the height
  *exec-pending* (§10); then `prune(v)`. `L ≥ M`, so the view has already
  advanced; finalization is monotone and idempotent. `Finalized` is **not**
  emitted here (§10).

**R5 — Nullification: form + ingest** (symmetric with R4):

On `≥ M` distinct admitted `Nullify(v)` votes, or one inbound `Nullification(v)`
with a valid cert, and `proofs[v]` unset ⇒ assemble/store `Nullification(v)` in
`proofs[v]`, emit `Broadcast(Nullification)` (form path only), `CancelTimer { v }`,
`enter_view(v+1)`.

**R6 — Nullify by contradiction** (only after this replica broadcast
`Notarize(c, v)`):

If `notarized == Some(c)` in view `v` and the replica observes `≥ M` distinct
view-`v` messages, each of which is `Nullify(v)` **or** `Notarize(c' ≠ c, v)` ⇒
set `nullified = true`; emit `Broadcast(Nullify { epoch, v, self, sig })`.

*Safety justification (assert in tests):* `≥ M` contradicting ⇒ at most
`n − M = 3f` weight remains able to notarize `c`; `3f < L = 4f+1` ⇒ `c` can never
finalize, so nullifying after notarizing is safe. This is the **only** case a
replica emits both a `Notarize` and a `Nullify` in one view, and it is
**non-slashable** — the split notarize/nullify tallies (§5, #523) exist precisely
so R6 is never mis-flagged as double-signing (§12).

**R7 — Re-dissemination** (on `Input::Tick`):

Emit `Broadcast` for every `Notarization`/`Nullification` in `proofs` not yet
re-disseminated by this replica, bounded by `DEFAULT_VIEW_HORIZON`. This is
Minimmit's liveness pump — it lets a lagging replica assemble the proofs that
`select_parent`/`valid_parent` require, replacing HotStuff's implicit QC gossip.

**Vote-once invariants (by construction):** at most one `Notarize` and one
`Nullify` per replica per view (R6 the single provably-safe exception); no
`Notarize` after `Nullify` (R2 guard); at most one block finalizes per view; a
view with a `Nullification` finalizes nothing (§2.2).

## §9 Safety & liveness invariants (test oracles, #527/#534)

Safety:

- **S1 Agreement:** no two honest replicas finalize conflicting blocks at the same
  height (honest-intersection lemma + vote-once).
- **S2 View mutual exclusion:** no view has both an L-finalized block and a
  `Nullification` (§2.2).
- **S3 Cross-view lock:** a `Notarization(c, v)` accepted into a valid parent
  chain cannot skip a finalized view — a finalized view has no `Nullification`
  (S2) and `valid_parent` requires one for every skipped view.
- **S4 No conflicting M-cert:** an L-notarized block in `v` ⇒ no
  `Notarization(c' ≠ c, v)` and no `Nullification(v)`.

Liveness (post-GST, timer = 2Δ, actual delay δ ≤ Δ):

- **L1** honest-leader view finalizes in ~3δ (propose + notarize + L-notarize).
- **L2** crashed leader: view advances in ~2Δ (timeout → Nullify → Nullification).
- **L3** equivocating leader: view advances in ~4Δ via the contradiction round
  (R6) then nullification.
- **L4** R7 guarantees a lagging honest replica eventually holds every proof
  needed to propose/vote.

Plus the **determinism replay oracle**: the same ordered `Input` sequence yields
identical `Effect` sequences and finalized chains (#527).

## §10 Execution-certified finalization (RETAINED and MANDATORY)

**Decision: keep DexOS's execution certification, layered as a distinct gate
AFTER L-notarization — never fused, never optional.** The two certificates prove
different things:

- Minimmit **L-notarization proves ordering-agreement** (a `Certificate` over
  `notarize_digest` at threshold L). It drives `enter_view`, `prune`,
  `finalized_tip`, and emits `ConsensusFinal`.
- DexOS **execution certification proves state-agreement** — an L-threshold
  `Certificate` over `execution_commitment_digest(epoch, view, height,
  block_hash, execution_root)` assembled from `ExecAttest` votes (§4.3, #520,
  #528). Light clients verify checkpoints (which bind `execution_root`) and never
  re-execute; dropping the exec cert would break that trust chain.

**Two certificates at the same threshold L over different digests.** Both verify
against `finalize_set` (§5.1).

Monotone per-height ladder (the explicit marker is mandatory — see §12 risk 2):

```text
consensus-final  --(exec L-cert lands)-->  finalized
   (emit ConsensusFinal{block,height};        (emit Finalized{block,height};
    height is exec-pending)                    seal checkpoint with the exec L-cert)
```

- `ConsensusFinal` fires exactly once per height, at L-notarization (R4).
- `Finalized` fires exactly once per height, only after the exec L-cert. The
  HotStuff `MissingExecutionCertificate` finalize gate (bft.rs:772) moves verbatim
  onto the Minimmit finalize: no exec cert, no `Finalized` — in **all** modes
  (the old `is_bft()` gating disappears with `ConsensusMode`).
- L-notarization may precede or follow the exec cert's assembly; the ladder is
  monotone either way (an exec cert arriving first parks until `ConsensusFinal`).

`CommandStatus` ladder mapping (`sequencer.rs`, unchanged structurally):
`ACCEPTED`/`EXECUTED` unchanged; `CERTIFIED` = the exec L-cert exists;
`FINALIZED` = L-notarization **and** the exec L-cert. Checkpoint sealing
(`seal_checkpoint`, checkpoint.rs) carries the **exec/L QC**, so `checkpoint.rs`,
`light-client`, and `proto`'s RPC `Checkpoint` survive structurally untouched
(#538).

## §11 Epoch / validator-set transition (#529)

Semantics mirror the existing `schedule_update`/`activate_epoch` contract
(bft.rs:879/896), adapted to the reactor:

- A `ValidatorSetUpdate` (retained type) is scheduled with an `activation_epoch`.
- **Activation gate:** the boundary activates only once every pre-boundary
  consensus-final height has its exec L-cert (**drain-before-swap**). Every digest
  binds `epoch` (§4.1), so a late `ExecAttest` for a pre-boundary height would
  need the *old* epoch's `finalize_set`; draining first means the replica never
  holds two committees. (#529 may relax this to a bounded two-committee window
  only with an explicit design note.)
- On activation: `epoch = new_epoch`; build the new `MinimmitCommittee`
  (membership + recomputed M/L) rejecting undersized/oversized sets (§2.3–§2.4);
  **reset `view = 0`**; clear `notarize_votes`, `nullify_votes`, `exec_votes`,
  and `proofs` so pre-boundary evidence (with old validator indices) can never be
  counted against the new set; retain the finalized `chain`, `finalized_tip`, and
  fork/equivocation evidence; then `enter_view(0)` semantics apply (emit
  `ArmTimer { view: 0 }`, and `NeedProposal` if `leader(0) == self` — leader
  rotation restarts epoch-mixed, §6.1).
- Because digests bind `epoch`, any message from another epoch fails digest
  recomputation and is dropped at admission — votes and certs cannot cross the
  boundary.
- The light-client transition digest (`validator_set_transition_digest`,
  light-client sync.rs) and every set commitment bind the **L `finalize_set`**
  (§5.1, #539).

## §12 Migration decisions — the four riskiest, plus secondary traps

1. **Sizing: `n ≥ 5f+1` with `MAX_VALIDATORS = 16` (u16 bitmap) — DECIDED
   (#546, §2.4).** Consequences: minimum committee **4 → 6**, `f_max = 3` at the
   16 cap, Byzantine tolerance ~19% at cap (vs ~31% for 3f+1 at 16) — the
   deliberate fault-tolerance-for-latency trade. Blast radius is *data*:
   `config/validators.toml` now ships **6** validators; the load-time guard
   (#536) rejects smaller production descriptors. The packed QC wire format breaks
   (8-byte → 2-byte bitmap header) — hard-fork note in #543. Do not "optimize" to
   3f+1 (§2.1).
2. **Execution-certified finalize — DECIDED: KEEP, mandatory, layered after
   L-notarization (§10).** The subtle trap is **ordering**: L-notarization can
   precede the exec cert, so a naive port of the finalize gate either withholds
   `Finalized` forever or emits it twice. The explicit
   `consensus-final → exec-pending → finalized` marker (#528) is mandatory.
   Load-bearing for the light-client trust chain.
3. **ed25519 + bitmap now; BLS deferred — DECIDED (§4.5, #545).**
   `try_with_threshold` already verifies a QC at any threshold ⇒ M-certs and
   L-certs are one type at two thresholds — zero new crypto. The silent-collapse
   trap: if cert formation keeps a single hardcoded `committee.threshold()`, the
   two-threshold protocol degenerates to single-threshold — a safety-critical,
   invisible regression. Cert formation must be **threshold-parameterized**
   (#523). Cost accepted: linear cert size (≈482 B M / ≈866 B L at the 16 cap) on
   the P0 lane. The `Certificate` alias behind `MinimmitCommittee::{assemble,
   verify}` is the seam; BLS later is a crypto+committee change, not a
   consensus-logic change.
4. **Clock-free core; the node owns all wall-clock — DECIDED (§7).**
   `step(Input) → Vec<Effect>`; `ArmTimer`/`CancelTimer`/`TimerFired`/`Tick`;
   build and verify injected as data (`NeedProposal`, `ProposalVerified`).
   Risk: the `BftEngine` method-per-action API inverts into one reactor — every
   caller changes, and the leader must self-feed its own propose. The old
   external view-change (`on_timeout`/`advance_view`) is gone; node code still
   driving views externally would double-advance. The node driver is a named
   Phase-4 deliverable (#540).

**Secondary traps (each can silently corrupt correctness):**

- **u16 indices** — `validator_index`/`proposer_index` are u16 on every wire type,
  applied uniformly (#517, #546); a stray u32 splits the codec.
- **Canonical L-set** — `finalize_set` feeds every commitment/checkpoint/epoch
  digest; the M-set hashes differently and silently breaks light clients
  (§5.1, #538, #539).
- **Serde-defaulted `delta_ms`** — `ConsensusSection` has
  `#[serde(deny_unknown_fields)]` (config.rs:139); a non-defaulted new field
  breaks every `config/*.toml` and inline test TOML at once (#536).
- **Split tallies** — notarize and nullify tallies must be strictly separate so
  R6's legitimate notarize+nullify is never slashed as double-signing (#523, §8).
- **R4 ingestion** — R4 must both FORM and INGEST inbound `Notarization` certs,
  symmetric with R5; a form-only R4 leaves a partitioned replica unable to
  advance even after receiving the cert via R7 — a liveness hole (§8, #525).
- **Epoch swap** — clear all tallies/proofs at the boundary (stale indices remap
  onto the new membership) but retain the finalized chain and slash evidence;
  gate activation on exec-cert drain (§11, #529).
- **Leader reconciliation** — keep `(epoch + view) mod n`; fix spec text, not
  code (§6.1).
- **Crate-scoped renames** — `Committee → MinimmitCommittee` is scoped to
  `consensus`; a global rename would corrupt the unrelated
  `prediction-markets::Committee`.

## §13 Migration contract

### §13.1 Retired

`ConsensusMode` (both variants) is retired at Phase 5; Minimmit is single-mode
BFT. `CrashTolerant` has no analog at `5f+1`; a demo needing a crash-only cluster
runs a degenerate `f = 0` committee (`M = 1`, `L = n`) explicitly labeled
demo-only. Also replaced at Phase 5: `BftEngine`, `Proposal`/`ProposalOutcome`,
`Vote`/`VotePhase`, `TimeoutVote`/`TimeoutCertificate`/`TimeoutCollector`,
`Committee`, `proposal_digest`/`vote_digest`/`timeout_digest`,
`DOMAIN_VOTE/PROPOSAL/TIMEOUT`, and the HotStuff tests (#541).

### §13.2 Retained as-is

`checkpoint.rs`, `sequencer.rs` (incl. `CommandStatus`), `Fork`,
`ValidatorSetUpdate`, `Equivocation`/`SlashEvidence`/`SlashKind`/`SlashHook`,
`crypto::{ValidatorSet, QuorumCertificate, KeyPair, CachedEd25519Key}`, the DoS
bounded view/quota machinery, `sig64`, `execution_commitment_digest`/
`DOMAIN_EXEC_COMMIT`/`certify_execution` semantics (§10), and the simulation
substrate (transport/scheduler/rng/oracle). `bft_threshold` stays for its
non-consensus callers (oracle/chain-adapter/decision-markets); Minimmit never
calls it — it uses explicit M and L (#511).

### §13.3 Completed rollout

1. **Phases 0–2** (#546, #511–#529): Minimmit lands as new symbols beside
   HotStuff. Nothing is deleted; `main` stays green; the existing `consensus`
   tests keep compiling. The one invasive early change is #546's shared-QC bitmap
   shrink — its HotStuff call sites are updated in place.
2. **Phase 3** (#530–#534): a feature-gated simulation driver proved the
   fault matrix (S1–S4 + L1–L4) before the flag was retired. The matrix is
   the correctness gate — no consumer cuts over before it is green.
3. **Phase 4** (#535–#540): benchmarks, node config (`delta_ms`, sizing
   validation, ≥ 6 validators), the checkpoint/light-client L-set contract, and
   the node wall-clock driver.
4. **Phase 5** (#541–#543): deleted HotStuff, retired the flag, and rewrote
   `ARCHITECTURE.md`/`SECURITY.md`/`README.md`, CHANGELOG breaking-change +
   hard-fork note.
5. **Phase 6** (#544, #545): quint conformance (or its documented deferral, with
   the S1–S4 property tests as interim oracle) and the BLS seam design note.

Phase 6 selected the documented deferral. See
[`MINIMMIT_CONFORMANCE.md`](MINIMMIT_CONFORMANCE.md) for the interim oracle and
revisit triggers, and
[`ADR_MINIMMIT_BLS_CERTIFICATES.md`](ADR_MINIMMIT_BLS_CERTIFICATES.md) for the
certificate-backend and validator-cap decision.

### §13.4 Config

`[consensus] delta_ms` (serde-defaulted, §12) feeds the node's 2Δ timer;
`checkpoint_interval_ms`, `epoch_length`, `validator_set_path` survive.
`config/validators.toml` grows from 3 to ≥ 6 entries (#537).

### §13.5 Docs (Phase 5, #543 — not this document's scope)

`ARCHITECTURE.md` §Consensus (two modes, chained QCs, "≥ 4 validators", 3f+1 →
Minimmit, M/L, "≥ 6 validators"), `SECURITY.md` (R6 non-slashable double-vote;
5f+1 / f≤3-at-16 trade), `PRODUCTION_READINESS_REVIEW.md`, `README.md`, crate
rustdoc headers.

### §13.6 Network

No structural change: messages ride `codec::Frame { class, msg_type, sequence,
payload }` on `TrafficClass::Consensus` (P0). The scheduler, per-class streams,
and `ConsensusPermits` auth are untouched; the network routes opaque bytes.

## §14 Ground-truth anchors (verified in-repo at authoring time)

| Anchor | Location |
|---|---|
| `crypto::MAX_VALIDATORS = 64` (→ 16 in #546) | `crates/crypto/src/quorum.rs:18` |
| `ValidatorSet::try_with_threshold` (arbitrary-threshold QC verify) | `crates/crypto/src/quorum.rs:136` |
| `bft_threshold` (legacy `2W/3+1`; not used by Minimmit) | `crates/crypto/src/quorum.rs:248` |
| Packed QC form `message[32] ‖ bitmap_le ‖ sigs` | `crates/crypto/src/quorum.rs:295` |
| `Committee::leader` = `(epoch + view) mod n` | `crates/consensus/src/vote.rs:512` |
| `DOMAIN_EXEC_COMMIT` / `execution_commitment_digest` | `crates/consensus/src/bft.rs:46,133` |
| `certify_execution` (consumes a pre-assembled QC) | `crates/consensus/src/bft.rs:598` |
| `MissingExecutionCertificate` finalize gate | `crates/consensus/src/bft.rs:772` |
| `schedule_update` / `activate_epoch` (view reset, collector clear) | `crates/consensus/src/bft.rs:879,896` |
| `DEFAULT_VIEW_HORIZON` / `DEFAULT_VOTE_QUOTA` / `CollectorWindow` | `crates/consensus/src/vote.rs:53,64,350` |
| `#[serde(deny_unknown_fields)]` on `ConsensusSection` | `crates/node/src/config.rs:139` |
| `validator_set_transition_digest` | `crates/light-client/src/sync.rs:43` |
| `pipeline/minimmit/quint/` **does not exist** (interim: this doc + #527 oracles) | — (#544) |
