# Security policy

meshvpn connects machines and carries their traffic, so we treat vulnerabilities in it as urgent.

## Reporting a vulnerability

Please **don't open a public issue**. Report privately:

- through GitHub: **Security → Report a vulnerability** on this repository, or
- by e-mail to **security@plugovr.ai**.

Please include the version (`meshvpn --version`), the platform, what an attacker needs (network
position, keys, an invite, ...) and what they gain, and if possible steps or a proof of concept to
reproduce it. You may write in English or German.

What happens next:

| Step | Within |
|---|---|
| We confirm we received the report | 3 working days |
| First assessment (severity, affected versions) | 10 working days |
| Fix released for critical/high severity | 30 days, usually much sooner |
| Fix released for medium/low severity | 90 days, or with the next release |

We keep you informed, agree the publication date with you, and credit you in the advisory unless
you prefer otherwise. We don't take legal action against research done in good faith: testing
only on your own systems or with permission, no access to other people's data beyond what is
needed to show the problem, no denial of service, and giving us reasonable time before disclosure.

## Supported versions

Security fixes are made for the **latest release**. Update with `meshvpn update` (or the
installer). Versions older than the latest minor release (e.g. 0.15.x once 0.16.0 is out) don't
get fixes.

## Advisories

Fixed vulnerabilities are published as GitHub security advisories of this repository (with a CVE
where appropriate) and named in the release notes.

## What helps you check a release

- `SHA256SUMS` and a `.sha256` file for every archive of a release; `meshvpn update` checks them.
- A software bill of materials (CycloneDX, `meshvpn-<version>.cdx.json`) with every crate the
  release is built from, to match against vulnerability databases.

## Scope

In scope: the `meshvpn` program and its installers in this repository. The enterprise edition is
covered by the same address and process. Out of scope: vulnerabilities in the operating system,
in dependencies that are already fixed in a newer version we don't ship yet (tell us anyway), and
findings that need root access on the machine meshvpn runs on.
