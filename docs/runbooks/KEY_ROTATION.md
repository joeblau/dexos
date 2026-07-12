# Key rotation runbook

Key rotation is not yet a fully implemented online protocol. Do not improvise it
on a live network.

1. Inventory the key purpose, owner, storage, dependents, and compromise status.
2. For suspected compromise, fence the identity, revoke access, preserve audit
   evidence, and require incident-command approval before continuing.
3. Generate the replacement in the intended HSM/secure environment. Never print
   or copy private material through logs, tickets, or chat.
4. Add the new public key through the reviewed membership/configuration process,
   overlap validity only for the documented window, and verify quorum health.
5. Remove the old public key, confirm rejection at every boundary, then destroy
   old private material per retention policy. Record approvals and fingerprints.
