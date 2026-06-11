# Security Policy

## Supported versions

| Version | Status     | Notes          |
| :------ | :--------- | :------------- |
| 0.1.x   | Supported  | Pre-release    |

## Reporting a vulnerability

**Please do not open public issues for vulnerabilities.**

Report security vulnerabilities exclusively via **GitHub Private Vulnerability Reporting**:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Follow the guided form to submit your report.

## Disclosure policy

- We will acknowledge receipt of your report within **7 days**.
- Our target for coordinated disclosure is **90 days** from acknowledgment, or sooner if a fix is released.
- We will keep you informed of our progress and credit you in the advisory unless you request otherwise.

## Scope

The security policy covers:

- Rust crates in this workspace (`crates/*`)
- The reference Go operator (`operators/sdk-reference-operator/`)

The reference operator is a development and testing harness; it is explicitly **not** intended for production deployment. See its [README](operators/sdk-reference-operator/README.md) for boundary details.
