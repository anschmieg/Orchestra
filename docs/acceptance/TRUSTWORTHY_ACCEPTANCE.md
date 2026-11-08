# Trustworthy acceptance

This is the smallest trustworthy acceptance extension for the Orchestra fork.
It preserves Orchestra's four roles, native T3 orchestration, compact
handoffs, Git phase checkpoints, explicit approval and upstream compatibility,
and adds one thing: an implementer can know the behavioral contract but cannot
forge or read the acceptance result of a verifier running in a separate
boundary.

## What it is not

It is not a new agent daemon, a task manager, a scheduler or a hidden test
suite. It does not change the flow assignment, role skills or delivery policy.
It exposes a small CLI/API surface (`start`, `status`, `approve`, `enroll`,
`list`) for later PaiOS/Rakazo integration.

## The four pieces

| Piece | Script | Purpose |
| --- | --- | --- |
| Keyring | `codex/scripts/acceptance_keyring.py` | Holds verifier Ed25519 key material outside any task checkout. |
| Evidence | `codex/scripts/acceptance_evidence.py` | Deterministic, machine-readable evidence bound to a commit SHA and tree. |
| Gate | `codex/scripts/acceptance_gate.py` | Fail-closed decision over a signed envelope and a contract. |
| Reconcile | `codex/scripts/acceptance_reconcile.py` | Durable T3 launch receipts so restarts replay instead of duplicating. |
| Policy | `codex/scripts/acceptance_policy.py` | Explicit, checked permission boundaries. |
| CLI | `codex/scripts/acceptance_cli.py` | `start` / `status` / `approve` / `enroll` / `list`. |

## How acceptance works

1. The implementer writes the unsigned payload: a commit SHA, the tree it
   points at, a file manifest and the checks it ran. It can claim a pass; it
   cannot sign.
2. Only a verifier holding the signing key can produce the signature. The
   keyring lives under `~/.orchestra-acceptance`, never in a task checkout.
3. The gate verifies signed evidence against the commit and verifier-provided spec. **Until a separately verified privileged OS-principal broker is implemented, all evaluator checks are blocked without launching any process.** There is no same-UID fallback, including with chmod, an environment variable or an unprivileged container.
4. A result is `accepted`, `rejected` or `blocked`. Unknown or ambiguous
   states are `blocked`; there is no silent pass.

## Isolation

**Current status: NO-GO.** OS-principal isolation and a root-controlled broker have not been demonstrated or installed. Commit-bound signatures do not make execution safe. Untrusted checks cannot execute, and no accepted result can be issued by the current gate. A future broker must prove distinct UIDs, secret isolation, root-controlled provisioning and cgroup/process-tree cleanup after broker SIGKILL and double-fork. Installation requires explicit operator authorization.

## Adversarial pilot

`codex/tests/test_acceptance_adversarial.py` checks signature, key and commit rejection. `codex/tests/test_acceptance_fail_closed_milestone.py` additionally proves that unprivileged execution never launches a malicious check, so a dummy private key cannot be accessed and a forged PASS marker cannot be written. These are non-privileged regression tests, **not** installed-broker acceptance.

## Recovery

`codex/tests/test_acceptance_recovery.py` verifies receipt replay and that all checks remain blocked without a broker. Recording requires complete canonical task, phase, 40-hex commit and absolute worktree identities before ledger creation; repeat requests with unchanged identity are idempotent and changed identities fail closed.

## Grants

Operations that mutate the host require a grant named in
`acceptance_policy.py`, set through `ORCHESTRA_ACCEPTANCE_GRANT`. Read-only
inspection needs no grant. The default home is `~/.orchestra-acceptance`.

## Conformance

`python3 codex/scripts/validate_suite.py --full` runs the acceptance
conformance check alongside the existing suite.
