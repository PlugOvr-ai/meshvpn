# Security policy

meshvpn connects machines and carries their traffic, so we treat vulnerabilities in it as urgent.

## Reporting a vulnerability

Please **don't open a public issue**. Report privately:

- through GitHub (preferred): **Security → Report a vulnerability** on this repository, or
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

- `SHA256SUMS` and a `.sha256` file for every archive of a release.
- `SHA256SUMS.sig`: an Ed25519 signature of `SHA256SUMS` (and of the version, so an older
  release's list can't be passed off as a newer one's). `meshvpn update` and `meshvpn desktop
  setup` install a release only if it verifies, and the file's checksum is in the signed list.
  Releases before 0.27.0 are checked against their checksums only.

  The keys come in two levels (as with TUF or Tailscale's distsign):
  - **Root keys**, built into meshvpn and kept offline. They certify release keys, and in an
    emergency sign a release themselves.
  - **The release key** signs releases automatically in the release workflow. It is a GitHub
    secret that only `v*` tags (which only maintainers may create) can use, on GitHub's own
    runners. `release-key.cert` in every release (and in the repository) is a root key's
    statement that this key may sign releases until a date. A release key that leaks is
    replaced by certifying a new one; it stops counting at its expiry date, at once in builds
    that list it as revoked, and it can never sign an update past its date.

  Root key (raw, base64url): `hHYAO3iLkvQIVXUW8GHBOaGOY-6HqTPAFEH7XofinYk`, as PEM:

  ```
  -----BEGIN PUBLIC KEY-----
  MCowBQYDK2VwAyEAhHYAO3iLkvQIVXUW8GHBOaGOY+6HqTPAFEH7XofinYk=
  -----END PUBLIC KEY-----
  ```

  To check a download by hand (OpenSSL 3 and jq): put `SHA256SUMS`, `SHA256SUMS.sig`,
  `release-key.cert` and the files into one directory and run
  [`scripts/verify-release.sh`](scripts/verify-release.sh) `<version> <directory>`. It checks
  the certificate against the root key, the signature against the certified key, and the files
  against `SHA256SUMS`, the same way `meshvpn update` does; read it, it is short.

  The installer (`install.sh`) itself comes from the release it installs, so `curl | sh`
  can't be safer than the release page; check it as above first if that matters to you.
- A software bill of materials (CycloneDX, `meshvpn-<version>.cdx.json`) with every crate the
  release is built from, to match against vulnerability databases.

## Scope

In scope: the `meshvpn` program and its installers in this repository. The enterprise edition is
covered by the same address and process. Out of scope: vulnerabilities in the operating system,
in dependencies that are already fixed in a newer version we don't ship yet (tell us anyway), and
findings that need root access on the machine meshvpn runs on.
