# Governance

## Current model

The OpenPacketCore SDK is currently maintained under a **single-maintainer** ("benevolent dictator") model. The sole maintainer has final authority on all technical decisions.

## Path to multi-maintainer governance

We intend to transition to a **meritocratic** multi-maintainer model once the project has a sustained contributor base.

### Criteria for becoming a maintainer

- Sustained, high-quality contributions over a period of **≥ 3 months**.
- Nomination by an existing maintainer.
- Approval by the existing maintainer team.

### Maintainer responsibilities

- Review and merge pull requests.
- Triage issues and steer the roadmap.
- Enforce the code of conduct and security policy.
- Maintain the RFC and ADR processes.

## Decision process

### Lazy consensus on pull requests

For routine changes (bug fixes, documentation updates, feature additions within existing RFC scope), we use **lazy consensus**: if no maintainer objects within a reasonable review window (typically 72 hours), the change is approved.

### RFC process for architectural changes

Changes that alter the architectural contract, introduce new major crates, or change public API boundaries must go through the **RFC process**:

1. Open a discussion in GitHub Discussions to gauge interest.
2. Draft an RFC in `docs/rfc/` following the existing format.
3. Submit a PR for review; the RFC is merged once approved by a maintainer.
4. Implementation PRs reference the approved RFC number.

See [`docs/rfc/`](docs/rfc/) for existing RFCs.

## RFC number allocation

RFC numbers are allocated sequentially starting from 001. The next available number is tracked in [`docs/implementation-status.md`](docs/implementation-status.md).
