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

## Verifier executable provenance

An implementer-controlled checkout is not a verifier installation: it can replace
the Python entrypoint or imports, and a caller-supplied `PYTHONPATH` can run
`sitecustomize` before signatures or protected-keyring checks. The gate
subprocess therefore uses isolated Python (`-I`), a minimal allowlisted
environment and the verifier home as cwd, not the candidate checkout.
**This does not authenticate the parent CLI**: production approval requires a
separately installed, immutable verifier executable and trusted Python runtime,
invoked by a privileged broker with sanitized process startup and distinct OS
principal. Running `acceptance_cli.py` from a candidate checkout, even with
these subprocess safeguards, is not authoritative and cannot grant GO.

## Pre-initialization executable and interpreter provenance

**Unprivileged counterexamples, not an installed-verifier acceptance:** The
real-process tests in `test_acceptance_preinit_provenance.py` demonstrate that
an implementer-controlled `PYTHONPATH/sitecustomize` runs *before* the parent
CLI imports; a writable Python virtual environment executes an attacker `.pth`
file even with Python `-I`; and an attacker-owned interpreter binary or
swappable executable symlink can ignore `-I` entirely. An unprotected copy of
the verifier CLI can likewise be replaced before any in-Python guard executes.
These are bootstrap compromises, not successful authorized acceptance.

**Operator-only blocker:** The privileged broker must `execve` an absolute,
operator-pinned Python executable and verifier entrypoint from a protected
independently installed root, with an allowlisted environment fixed *before*
starting the interpreter. The entire executable, dynamic-loader/library chain,
symlink path, Python environment, site-packages and `.pth` files must be
non-writable by implementers; otherwise `-I`, `-S`, Python ownership checks
and child-only environment sanitization cannot establish the trust boundary.
Provisioning and validating this installation, separate evaluator/verifier OS
UIDs, protected keys, and cgroup SIGKILL/double-fork cleanup require explicit
operator authorization. No rootless test grants GO.

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

## Installed verifier admission (rootless negative screening)

`approve` now denies paths with symlinked, non-root-owned or group/world-writable
interpreter, verifier Python code, or ancestor components, and checks the entire
verifier-home ancestry as well as the leaf grants and keyring. It rejects
non-isolated startup, virtual environments and `.pth`-enabled site startup.
The broker's existing nonce/PIDFD transport probe is **not** identity or
containment attestation, so even a claimed `ready` cannot grant `accepted`.

These `lstat` checks are **diagnostic rejection only**. They run after Python
startup, so cannot stop malicious `sitecustomize`, a replaced interpreter or
entrypoint, preloaded modules, or mutable dynamic libraries. Their path/inode
identity can change between checking and executing (TOCTOU), even with clean
UID/mode metadata. A privileged operator-installed launcher must bind and
verify descriptors and executable/dependency digests before `execve`, isolate
verifier/evaluator identities, supply protected signing keys and use a
challenge-bound broker attestation tied to each accepted result and cgroup
generation. Until that is deployed and demonstrated, production admission is
**BLOCKED_SAFE / NO-GO**, irrespective of passing rootless tests.

## Task/context-bound broker challenge (negative screen)

`acceptance_broker_ipc.attest_broker(task_id=..., context_id=...)` now issues
a fresh 256-bit nonce per invocation with a five-second monotonic deadline.
A response must match the exact task, context, nonce, verifier PID and
kernel-reported real/effective UID, and an executable descriptor held open
through the exchange. The connection checks root-owned peer credentials and
a kernel-supplied peer PIDFD, including broker death during the handshake.
It also rejects an expired challenge, changed verifier UID or executable
descriptor, replayed task/context and unprivileged evaluator-UID claims.

The evaluator UID in an offline response is still a **claim**, not a
kernel measurement by an installed privileged broker. There is no protected
broker signing key, replay ledger, installed launcher, evaluator process
identity or cgroup generation proof yet. A well-formed response returns
`connected_unverified`, never `accepted`; `approve` remains blocked.
Unit tests with forged root peers are simulation only; a Linux child
descriptor-handoff/exec-after-parent-death regression demonstrates a real
OS lifecycle counterexample without protected-host acceptance. The broker
must independently verify peer executable identities, evaluator UID and
cgroup containment, use a protected one-shot nonce record and a
challenge-bound signed receipt before any positive production admission.

## One-use signed admission receipt (independent rootless screening)

The additional `acceptance_receipt.py` verifies Ed25519-signed task/context/nonce,
cgroup generation, verifier PID/UID/open executable descriptor, and a live
PIDFD-pinned evaluator's kernel-observed real/effective UID and executable.
The five-second monotonic expiry is checked before and after consuming the nonce.
A pre-provisioned private per-verifier replay ledger (never auto-created after deletion) uses a file lock, exact-record integrity
checks, fsync of file and directory, and single-use consumption, including
after SIGKILL/restart. Corrupt or inaccessible storage blocks.

This API intentionally returns `verified_uninstalled`, **never** `accepted`
or GO. Its injectable public key and the offline fake evaluator in unit
tests are not operator-provisioned trust anchors. An operator-controlled,
protected launcher must provide the immutable signing public key,
replay-storage ancestry and identity/cgroup-generation provenance before
the screen can be used for protected admission. `approve` remains blocked,
the evaluator gate never runs untrusted checks, and mock broker success
cannot overcome those requirements. This milestone is a negative security
screen, **not** an end-to-end privileged acceptance.
