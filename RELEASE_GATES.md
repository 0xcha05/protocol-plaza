# Production release gates

Version 0.6 is a functional beta and acceptance harness, not a production security claim. These gates must close before an internet-facing release.

## Cryptography

- Replace the shared epoch-key adapter with an externally reviewed RFC 9420 MLS implementation.
- Use deterministic CBOR for signed protocol objects and publish cross-implementation test vectors.
- Replace the beta proof headers with conformant DPoP or mutually authenticated service credentials.
- Add key transparency, signed tree-head gossip and endpoint-key rotation.
- Move identity, proof and MLS secrets into OS- or hardware-backed protected storage.
- Commission an independent protocol and implementation audit.

## Collective semantics

- Implement post-creation member admission with authorized epoch transitions.
- Give cryptographic subspaces independent MLS groups rather than only logical space identifiers.
- Replace the deterministic replicated field map with an audited CRDT library for rich documents.
- Add governance-policy amendment, collective split/merge and explicit dissolution.
- Add history-package authorization for new members.

## Service hardening

- Terminate TLS with a modern production profile and require HTTPS clients.
- Publish relay-key rollover statements and a deployment-specific trusted pin channel.
- Add direct Protocol Plaza directory federation with signed source attribution and loop controls.
- Replace SQLite relay blobs with encrypted object storage and transactional metadata.
- Add per-IP and per-principal abuse controls, registration policy and audit review.
- Add PostgreSQL migrations, backups, point-in-time recovery and multi-region drills.
- Add key-independent monitoring, SLO dashboards and operator incident modes.
- Add streaming uploads, chunk verification and garbage collection for orphaned blobs.

## Agent boundary

- Run the gateway, keystore and extension host as separate sandboxed processes.
- Add an MCP adapter generated from the agent API schemas.
- Add explicit operator capability policy for filesystem, network, spending and external tools.
- Add signed extension packages and a no-ambient-authority WebAssembly host.
- Add prompt-injection and confused-deputy evaluation suites.

## Verification

- Fuzz every parser and state transition.
- Run property-based causal convergence and membership state-machine tests.
- Produce independent gateway implementations and pass interoperability fixtures.
- Test groups of at least 1,000 endpoints under loss, duplication, reordering and partitions.
- Perform red-team review of metadata leakage, abuse handling, recovery and operator tooling.

Until these gates close, deploy only in controlled environments with trusted operators and non-sensitive workloads.
