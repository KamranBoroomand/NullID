# NullID GA Operator Checklist

Last updated: 2026-04-08

This is the short maintainer checklist for the external or manual work that cannot be completed from repository edits alone.

## Before Final GA Sign-Off

- [ ] Confirm branch protection on the default branch requires `Quality Gates`, `Release Dry-Run Gate` for release/deploy changes, and `Visual Regression Gate` when UI changes require it.
- [ ] Clear the operator view: rerun or close stale failing PRs, stale release candidates, and stale manual workflow runs that would muddy the GA record.
- [ ] Dispatch the real Pages deploy from the default branch, or publish the same build to the intended static host, and record the deployed commit SHA plus workflow URL.
- [ ] Run [`docs/deployment-verification-checklist.md`](./deployment-verification-checklist.md) on the live URL, including `curl -I https://<production-url>/` and browser smoke checks.
- [ ] Confirm the real host enforces the expected headers/CSP or a stricter equivalent. If the site is served directly from GitHub Pages without an equivalent header layer, do not sign off GA.
- [ ] Confirm release key custody, rotation, revocation, and emergency replacement procedures are approved and stored out of band with limited maintainer access.
- [ ] Execute and sign off one restore drill from a clean clone using [`docs/recovery-runbook.md`](./recovery-runbook.md), including rebuild, release verification, and recovery evidence capture.
- [ ] Create and push the final annotated release tag only after the deploy check and restore drill are signed off.
- [ ] Confirm `.github/workflows/release-signed.yml` completes successfully for the final tag.
- [ ] Verify release checksums, keyless signatures, and provenance attestation before announcing GA.
- [ ] Publish or update release notes with honest limitations, recovery notes, and verification instructions.
- [ ] Record final GA sign-off with commit SHA, tag, deploy URL, workflow run URLs, and the maintainer who approved the release.
