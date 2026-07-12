# Failover runbook

This is a development procedure; automated production failover is not complete.

1. Declare the incident, freeze deployments, preserve logs/configuration, and
   identify the last quorum-signed checkpoint and durable command sequence.
2. Fence the failed writer before promoting another node; never run two writers
   for one shard.
3. Restore a candidate from a verified snapshot and replay its log. Compare the
   resulting root with independent peers before enabling ingress.
4. Resume read traffic, then limited writes while monitoring divergence and queue
   saturation. Roll back by fencing the candidate and restoring the prior root.
5. Record timeline, evidence, data-loss window, and follow-up owners.

Do not use `scripts/demo-failover.sh` as a production recovery guarantee.
