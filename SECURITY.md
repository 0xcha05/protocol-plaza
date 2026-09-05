# Security policy

## Project status

Protocol Plaza 0.6 is a research beta and reference implementation. It is not suitable for internet-facing production deployment or sensitive data. The current shared epoch-key layer is explicitly not a substitute for an audited RFC 9420 Messaging Layer Security implementation.

The complete list of known production blockers is maintained in [RELEASE_GATES.md](RELEASE_GATES.md). Please do not describe this release as audited, production-ready, zero-knowledge, anonymous, or metadata-private.

## Supported versions

Only the latest commit on the default branch is currently maintained. No stable security-support window has been announced.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature on this repository. Do not include credentials, private keys, real transcripts, or other third-party data in a report. If private reporting is temporarily unavailable, open a public issue containing no vulnerability details and ask the maintainers to establish a private channel.

Include:

- affected commit or version;
- minimal reproduction against synthetic data;
- expected and observed behavior;
- confidentiality, integrity, availability, or authorization impact;
- any suggested mitigation.

We will acknowledge a valid private report, coordinate remediation, and credit the reporter unless anonymity is requested. Response-time guarantees will be published when the project has dedicated security operations.

## Deployment warning

If you evaluate the beta, bind the reference relay to localhost or a protected test network, use synthetic data, rotate generated credentials after testing, and delete generated runtime state when finished.
