# NullID Deployment Verification Checklist

Use this checklist after Cloudflare Pages deploys the current `main` commit through Git integration. These checks must be performed against the real hosted site; they cannot be completed from the repo alone.

## 1. Hosting Assumptions

- Site is served over HTTPS.
- `main` is the source branch for the Cloudflare Pages project.
- Cloudflare Pages builds and serves static assets from this repository.
- The production origin is `https://nullid.kamranboroomand.ir/`.
- Product behavior remains local-first with no required runtime backend or cloud dependency.
- Header policy on the real host is at least as strict as the repo baseline in `public/_headers`.

Expected header baseline on the HTML document response:

- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self'; connect-src 'self'; worker-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'`
- `Cache-Control: public, max-age=0, must-revalidate, no-transform`
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`
- `Cross-Origin-Opener-Policy: same-origin`

## 2. Workflow Expectations

- `Quality Gates` passed on the deployed commit.
- `Release Dry-Run Gate` passed if release/deploy surfaces changed.
- Cloudflare Pages Git deployment completed successfully from the default branch.
- If a release tag is being published, `Signed Release + Provenance` completes after deployment verification is done.

## 3. Asset Path Sanity

Check these manually in the browser and/or with devtools:

1. Fetch the document headers from the real production URL:
   ```bash
   curl -I https://<production-url>/
   ```
2. Open the site in a browser with devtools open on the `Network` panel.
3. Reload once with cache disabled.

- The root document loads from the intended production URL.
- No `404` requests appear for hashed `/assets/*` files.
- Reloading the root page does not break asset paths.
- The site does not attempt runtime requests to third-party origins.
- Service worker and manifest assets load from the same origin.
- HTML document responses include `no-transform` so edge middleware does not alter bytes used by service-worker precache integrity checks.

## 4. Smoke Checks

Perform these short manual checks on the deployed site:

1. Open the app and confirm the shell renders without console errors.
2. Switch language across `EN`, `RU`, and `FA`.
3. Open `Safe Share`, `Incident Workflow`, and `Verify Package`.
4. Confirm the major page titles and controls render in the selected locale.
5. Export one local sample package and inspect it in `Verify Package`.
6. Watch devtools `Network` and confirm the site still makes no required runtime request to third-party origins for normal product behavior.

## 5. Visual Sanity

- Confirm layout is usable on a desktop viewport.
- Confirm no obvious clipping or overflow in the header, module rail, and main panels.
- Confirm RU and FA strings are not visibly truncated in the key release surfaces.
- If the release changed UI surfaces, review the visual regression artifacts alongside the live site.

## 6. Manual Post-Deploy Sign-Off

- Record the deployed URL.
- Record the deployed commit SHA.
- Record the Cloudflare Pages deployment status for the commit.
- Record the exact `curl -I` output or browser-captured header values used for verification.
- Record whether headers/CSP matched the expected baseline or document any stricter host-specific variation.
- Record whether smoke checks passed.
- Continue with tags or release publication only after these checks pass.
