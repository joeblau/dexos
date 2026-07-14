# Bare-metal marketd runbook

## Supported outcome and release block

These artifacts reproducibly install and supervise the current `marketd`
binary on a Linux/systemd host. They support only a **pre-production process
smoke deployment**.

`Node::run_until` currently starts placeholder role handlers and the optional
metrics HTTP server. It does not bind the configured peer or RPC listeners,
open the configured storage directory, load a node identity seed, compose
execution/consensus, or provide authoritative snapshots and recovery.
Consequently:

- `/livez` proves that the observability runtime responds;
- `/readyz` proves only that placeholder handlers bootstrapped and no handler
  has exited;
- neither endpoint proves exchange, consensus, data-plane, durability, or
  recovery readiness;
- real assets and public trading traffic are prohibited.

The systemd preflight requires `DEXOS_ACKNOWLEDGE_SKELETON=1` so this limitation
cannot be missed. `bare-metal-verify --production-gate` intentionally exits 2.

## Host and artifact prerequisites

- Dedicated x86_64 or aarch64 Linux host with systemd, GNU coreutils, `curl`,
  `awk`, `sed`, `runuser`, `findmnt`, and synchronized time.
- A binary built for the host's exact target and glibc baseline. A macOS binary
  or differently targeted Linux binary will not install.
- An expected SHA-256 obtained through a trusted channel. SHA-256 verifies
  identity after trust is established; it is not artifact signing.
- No other service using `127.0.0.1:9100`.

Build on a reviewed commit:

```sh
TARGET=x86_64-unknown-linux-gnu OUT_DIR=dist \
  ./scripts/build-release-artifacts.sh
sha256sum -c dist/SHA256SUMS-x86_64-unknown-linux-gnu
```

The release builder passes `--target` to Cargo and packages only
`target/$TARGET/release/marketd`, preventing a host binary from being mislabeled
as a cross-target artifact.

## Install and configure

Review the safe observer template in `deploy/bare-metal/marketd.toml.example`.
It uses `/var/lib/dexos/data`, JSON journald logs, read-only/loopback addresses,
and loopback metrics. The configured RPC and peer addresses are validated but
not bound by the current runtime.

```sh
SHA256=$(awk '{print $1}' dist/SHA256SUMS-x86_64-unknown-linux-gnu)
sudo ./deploy/bare-metal/install.sh \
  --binary dist/marketd-x86_64-unknown-linux-gnu \
  --sha256 "$SHA256"

sudoedit /etc/dexos/marketd.toml
sudoedit /etc/dexos/marketd.env
sudo /usr/libexec/dexos/bare-metal-preflight --skip-skeleton-ack
```

Installation creates:

- immutable `/opt/dexos/releases/<sha256>/marketd` and a relative `current`
  symlink;
- root-owned `/etc/dexos` configuration (`0640`, group `dexos`), including
  the required, non-symlinked `marketd.env`;
- service-owned `/var/lib/dexos/data` (`0750`);
- an unprivileged `dexos` account;
- a hardened `marketd.service` with write access limited to `/var/lib/dexos`.

For a consensus-bearing role, install a reviewed validator descriptor and pass
it to the installer with `--validators`. The current schema validates a
unit-weight Minimmit committee, but `marketd run` still does not load or use a
node private identity key. `marketd keygen` output is not consumed by `run`.
Do not mistake a generated seed for an active node identity.

TLS paths are validated if configured, but the unbound RPC listener means TLS
is not active in `marketd run`. Certificates, client CAs, and private keys must
be real non-symlinked files, root-owned, readable by `dexos`, and never
group/world-writable. Private keys additionally require group `dexos` and must
not be world-readable. Validator descriptors and the configured data directory
must likewise be real paths rather than symlinks.

## Start and smoke-verify

Set the explicit acknowledgement in `/etc/dexos/marketd.env`:

```ini
DEXOS_ACKNOWLEDGE_SKELETON=1
```

Then:

```sh
sudo systemctl enable --now marketd.service
sudo /usr/libexec/dexos/bare-metal-verify
curl --fail http://127.0.0.1:9100/livez
curl --fail http://127.0.0.1:9100/readyz
sudo journalctl -u marketd.service -f
```

Alternatively, the installer can perform that start and use a non-default
metrics listener for its smoke probes:

```sh
sudo ./deploy/bare-metal/install.sh \
  --binary dist/marketd-x86_64-unknown-linux-gnu \
  --sha256 "$SHA256" \
  --acknowledge-skeleton \
  --start \
  --health-url http://127.0.0.1:19100
```

The URL must match `[observability].metrics_listen`; it does not change the
listener configuration.

Expected today: port 9100 is owned by `marketd`; configured peer/RPC ports are
not. Treat that as a release blocker, not as firewall success. Keep 9100 on
loopback; it has no authentication. Do not open 8080/9000 based on this runbook
until the composition root actually owns and authenticates those listeners.

For an explicit non-production assertion:

```sh
sudo /usr/libexec/dexos/bare-metal-verify --production-gate
# exits 2 and lists the missing composed capabilities
```

SIGTERM triggers the implemented in-memory queue drain. `TimeoutStopSec=620s`
covers the configuration schema's maximum 600-second drain deadline (the
template uses 30 seconds) with headroom for post-drain hooks. Current flush
hooks for RPC, network, and journal are placeholders, so a clean stop is not
durable-state evidence.

## Upgrade and rollback

There is no authoritative online snapshot/restore path. Before any change,
fence the host from traffic, preserve `/etc/dexos`, `/var/lib/dexos`, the exact
old release digest, and independently review configuration/wire/state
compatibility. The scripts require explicit confirmation because they cannot
prove that review.

```sh
sudo /usr/libexec/dexos/bare-metal-upgrade \
  --binary /staging/marketd \
  --sha256 <trusted-64-hex-digest> \
  --backup-confirmed
```

The upgrade stages an immutable release, copies configuration into a root-only
receipt under `/var/lib/dexos/admin/upgrades`, stops and drains the old process,
atomically switches `current`, and runs the smoke verifier. A smoke failure
automatically restores and starts the prior binary. It does not back up or
validate canonical state.

Upgrade and rollback also accept a unit whose settled `ActiveState` is
`inactive` or `failed`, so an operator can recover a node that cannot stay up.
In that recovery mode there is no live process to drain: the script validates
the root-owned release trust anchors and target release, switches the relative
`current` link, clears systemd's failed/start-limit state, starts the target,
and smoke-verifies it. Invoking either script therefore attempts to start the
unit even if it began inactive. Units that are not loaded or are still
activating/deactivating are refused; wait for a settled state first. A failed
cutover restores the starting link and attempts to start the starting binary.

Every selected or rollback release must be a real root-owned `0755` directory
named by one full lowercase SHA-256. Its `marketd` must be a root-owned `0755`
regular file and `SHA256` a root-owned `0644` regular file containing exactly
`<digest>  marketd`. `/opt/dexos/current` must be a root-owned relative link of
the exact form `releases/<digest>`. Preflight refuses looser prefixes,
uppercase/short digests, writable metadata, and symlinked artifacts.

Rollback is digest-explicit and binary-only:

```sh
sudo /usr/libexec/dexos/bare-metal-rollback \
  --release <previous-full-sha256> \
  --compatibility-confirmed
```

Keep the node fenced after rollback: bootstrap readiness cannot establish WAL,
snapshot, or state-root compatibility. `marketd snapshot` currently fails
closed, so no procedure here can claim recovery readiness.

## Uninstall

```sh
# Remove service and binaries, preserve configuration/state/account.
sudo /usr/libexec/dexos/bare-metal-uninstall

# Destructive purge; mounted/symlinked state is refused.
sudo /usr/libexec/dexos/bare-metal-uninstall \
  --purge-data CONFIRM_REMOVE_DEXOS_DATA
```

For a purge, both `/etc/dexos` and `/var/lib/dexos` are checked for a top-level
symlink and for any mount at or below either path before the service is disabled
or any installed file is removed. This prevents `rm -rf` from crossing into a
nested state/configuration mount. A refused purge leaves the installation
untouched for inspection.

## Production exit criteria

Bare-metal production remains blocked until current evidence proves all of the
following through `marketd run`: authenticated peer and RPC listeners; loaded
node identity; durable WAL with correct shutdown flush ordering; real execution
and consensus wiring; authoritative snapshot/replay recovery; end-to-end client
queries and writes; state-root agreement; upgrade compatibility; and readiness
that depends on those critical subsystems. Load testing is separate and does
not waive any of these functional gates.
