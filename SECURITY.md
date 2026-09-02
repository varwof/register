# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in `varwof/register`, please do not
open a public issue. Report it privately to
[pki@varwof.com](mailto:pki@varwof.com).

Please include:

- The affected version(s)
- A description of the vulnerability and its impact
- A minimal reproducer if available

You should receive an acknowledgement within a few business days.
We ask that you give us reasonable time to address the issue before
public disclosure.

## Scope

This project is the capability registry and validation module of the varwof AIC ecosystem. Issues of
interest include:

- capability/parameter validation bypass, JSON-Schema handling, PKCS#7 signature verification
- dependency and supply-chain integrity

## Supported Versions

Security fixes are applied to the latest release. Older releases are
supported on a best-effort basis.

## Funding note: no paid third-party audit

This is an individual / open-source project; no paid third-party
security audit has been conducted. Validation relies on internal
AI-assisted review, automated tests, and independent cross-implementation
exercise where available.

## Security Audit History

Review practice: development includes AI-assisted security review and
RFC compliance cross-checks. Consolidated findings are logged below;
each is retained as a historical record after resolution.

No consolidated findings to date for this repository. A full
ecosystem security review is scheduled quarterly (next: 2026-12-01);
results will be appended here.
