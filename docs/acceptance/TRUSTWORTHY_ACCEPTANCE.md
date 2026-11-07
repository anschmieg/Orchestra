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
3. The gate loads `.orchestra-acceptance/gate.json` from the evidence commit
   and re-runs its checks. It compares the signed tree with the checked-out
   tree, so tampering after signing is detected.
4. A result is `accepted`, `rejected` or `blocked`. Unknown or ambiguous
   states are `blocked`; there is no silent pass.

## Isolation

The verifier runs an immutable commit SHA in a separate OS/container/security
boundary. It shares no secret with the implementer and writes no result path
the implementer can read. Evidence is valid only against a trusted public key;
a self-claimed pass is rejected because the implementer has no signing key.

## Adversarial pilot

`codex/tests/test_acceptance_adversarial.py` deliberately produces a false
PASS and proves the gate rejects it: unsigned envelope, wrong-key signature,
a deliberately failing implementation and tampered-after-signing evidence are
all rejected, while a legitimately signed pass is accepted.

## Recovery

`codex/tests/test_acceptance_recovery.py` proves that a duplicate T3 launch
replays from its receipt rather than spawning a second scheduler run, that an
unknown launch fails closed, and that a crashed or unstartable check is
`blocked` or `rejected`, never silently accepted.

## Grants

Operations that mutate the host require a grant named in
`acceptance_policy.py`, set through `ORCHESTRA_ACCEPTANCE_GRANT`. Read-only
inspection needs no grant. The default home is `~/.orchestra-acceptance`.

## Conformance

`python3 codex/scripts/validate_suite.py --full` runs the acceptance
conformance check alongside the existing suite.
