# Security policy

traefik-gatekeeper decides who can reach protected sites, so security reports
are very welcome.

## Supported versions

| Version | Supported |
|---|---|
| Latest release (`X.Y.Z`, `latest` image tag) | ✅ |
| `edge` (main branch) | ✅ best effort |
| Older releases | ❌ please upgrade |

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/mkopnsrc/traefik-gatekeeper/security/advisories/new)
(Security tab → Advisories → Report a vulnerability).

Include:

- the version (`traefik-gatekeeper version`) and how you run it;
- what an attacker can do, and the steps or a proof of concept;
- relevant configuration and logs, with tokens, IDs, addresses and hostnames
  replaced by placeholders.

What happens next:

- acknowledgement within **7 days**;
- an assessment and, if confirmed, a plan and timeline within **14 days**;
- a fixed release and a published advisory (GHSA, with a CVE where it applies),
  crediting you unless you prefer otherwise.

Please give a reasonable time to release a fix before disclosing publicly.

## Scope

In scope, for example:

- approving or extending access without a valid button press from a configured
  approver;
- getting an address (or any other content) into the traefik configuration
  other than through an approval;
- spoofing the client address the gatekeeper records;
- CSRF, XSS or other browser attacks on the request page;
- leaking the bot token, or denial of service through a single request.

Out of scope:

- the documented design limit that access is per **IP address** (anyone behind
  an approved address gets in);
- attacks that require control of the approver's Telegram account, the host,
  or the traefik configuration;
- volumetric denial of service (handle it in front of traefik);
- findings in dependencies without a way to exploit them here (report those
  upstream; Dependabot keeps them updated).

## How the project protects itself

- CI runs `go test -race`, `go vet` and `govulncheck` on every change, and
  CodeQL code scanning for Go and the GitHub Actions workflows.
- Dependabot updates Go modules, base images and workflow actions.
- Images are built by GitHub Actions with an SBOM and signed build provenance:
  `gh attestation verify oci://ghcr.io/mkopnsrc/traefik-gatekeeper:<tag> --owner mkopnsrc`.
