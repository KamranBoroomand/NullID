# Security Policy

## Supported Versions

Security fixes are applied to the latest code on `main` and current tagged releases.

## Reporting a Vulnerability

Please do not open public issues for security problems.

Use one of these private channels:

1. Open a GitHub Security Advisory draft for this repository.
2. If advisories are unavailable in your environment, contact the maintainers directly with:
   - affected component/path
   - impact summary
   - reproduction steps or proof of concept
   - suggested remediation (if available)

## Response Targets

- Initial triage acknowledgement: within 3 business days.
- Severity assessment and fix plan: within 7 business days.
- Public disclosure: after a fix is available and users have a reasonable patch window.

## Scope Notes

- Runtime network calls in `src/` are out of policy by design and treated as high-priority defects.
- Build/release integrity regressions (manifest/checksum/signature/provenance pipeline) are security-impacting.
- Clipboard/storage residue risks are documented limitations and evaluated case by case.

## Temporary Dependency Audit Exception

A narrow temporary exception is tracked in `security/dependency-audit-policy.json` for GHSA-mh99-v99m-4gvg in transitive development-only `brace-expansion` 1.x and 2.x paths used by ESLint/a11y linting and CycloneDX SBOM tooling. Production dependency audits must remain clean, these packages are not bundled into the browser application, and NullID does not pass attacker-controlled glob patterns into those tools. This is reviewed for upstream remediation and does not claim a completely clean full dev-dependency audit while the exception remains active.
