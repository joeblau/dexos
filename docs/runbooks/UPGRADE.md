# Upgrade runbook

1. Review changelog, schema/wire compatibility, feature flags, and rollback plan.
2. Build from a reviewed commit with `--no-default-features`; record binary hash.
3. Back up configuration, logs, snapshots, and keys. Verify a restore in staging.
4. Drain and fence one non-writer node, upgrade it, verify health/state root, then
   canary it under read traffic. Upgrade quorum members one at a time.
5. Upgrade the writer only after compatible quorum capacity is healthy.
6. Abort on root divergence, replay failure, or unexpected protocol versions;
   fence the new binary and restore the prior binary/config/snapshot.
