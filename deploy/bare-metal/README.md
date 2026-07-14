# Bare-metal deployment bundle

This bundle installs a checksummed `marketd` binary as an immutable release,
runs it as an unprivileged systemd service, and provides lifecycle scripts for
smoke verification, upgrade, rollback, and uninstall.

The current node is a **pre-production composition skeleton**. `/readyz` means
only that placeholder role handlers and the metrics listener started; it is not
exchange, consensus, RPC, networking, durability, or recovery readiness. The
service therefore requires `DEXOS_ACKNOWLEDGE_SKELETON=1` before it will start.

Upgrade and rollback accept settled `active`, `inactive`, or `failed` service
states. Inactive/failed invocation is an explicit recovery operation: it starts
and smoke-verifies the selected release while preserving automatic link
restoration on a failed cutover.

Run `deploy/bare-metal/tests/staging.sh` for the rootless packaging and
fail-closed invariant checks. Run
`deploy/bare-metal/tests/preflight-policy.sh` to exercise validator/TLS
ownership, permission, readability, and symlink refusal in Ubuntu. Run
`deploy/bare-metal/tests/purge-nested-mount.sh` when Docker is available to
exercise recursive mount refusal inside an isolated privileged Ubuntu
container.

Use the complete procedure and current release-blocker list in
[`docs/runbooks/BARE_METAL.md`](../../docs/runbooks/BARE_METAL.md).
