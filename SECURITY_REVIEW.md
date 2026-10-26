# Security review — 2026-10-26

This review covers upstream `kavdau/n8n-oidc` commit `bf432a1356cde1195b1048725a30b64d6bcf1b12` and the small patch in release `2.1.1-jeserga.1`. The upstream `hooks.js` SHA-256 is `3ba5fda89880a397fcaae8415042f828ae2587d78b9af547c3be3cd840d61ed0`. Review the diff and test the exact release before upgrading. This is a source review and adversarial functional test, not a certification or proof that no vulnerability exists.

## Source and dependency review

The production hook imports only Node built-ins and modules already installed by n8n. No additional production npm dependencies, lifecycle install scripts, shell commands, dynamic code downloads, credential collection or unrelated outbound destinations were found. Network requests are for discovery, token exchange, JWKS and UserInfo at the configured identity provider’s endpoints, with timeouts and redirects disabled. Provider configuration is trusted administrator input; do not let untrusted users control it. Do not install arbitrary community nodes into an authentication trust boundary.

The frontend embeds configuration with script-safe JSON, uses `textContent` for labels and constant messages for errors, and does not inspect passwords or request bodies. The logout wrappers observe the request URL to prevent auto-login loops. Account operations use n8n repositories. Token signatures, allowed algorithms, issuer, audience, authorized party, expiry, nonce and UserInfo subject are checked. The code uses PKCE S256 and an AES-256-GCM authenticated transaction cookie. These mechanisms were inspected and tested; they do not make the IdP or n8n internals untrusted components.

## Changes made during review

- Secure deployments use `__Host-n8n-oidc-tx`, without Domain and with Path=/, Secure, HttpOnly and SameSite=Lax. This blocks sibling subdomains from planting a parent-domain transaction cookie. Local HTTP development retains the upstream cookie name and path.
- Log messages strip control characters and have a length limit. Provider response bodies and arbitrary error descriptions are excluded from HTTP error messages, reducing log injection and accidental token disclosure.
- HTTPS discovery cannot downgrade authorization, token, JWKS or UserInfo endpoints to HTTP. Malformed endpoint URLs with embedded credentials or fragments are rejected.
- Signed ID tokens with non-finite numeric date claims are rejected.

These are defensive improvements. The review did not identify intentional malicious behavior or demonstrate an account takeover in the original release.

## Verification

All 74 automated tests passed inside the official n8n 2.7.5 container, using its Node 22 runtime, a read-only root filesystem, dropped capabilities and no external network. This comprises 46 unit/security tests and 28 tests against real disposable n8n processes and a local mock provider. Tests cover signature forgery, algorithm confusion, nonce/state/audience/expiry failures, mix-up, redirects, encrypted-cookie tampering, code replay, native-session logout and REST access, HTTPS cookie attributes, a one-hour session, disabled provisioning and disabled profile sync. The test harness accepts the external-script markup used by n8n 2.7.5; no n8n production files are patched for this compatibility.

```sh
npm test
N8N_BIN=/path/to/n8n/bin/n8n npm run test:e2e
```

The mock provider and test harness are development tools and must never be exposed or mounted in production. Operational browser tests and backup evidence belong in the deployment repository, without production credentials in this public fork.

## Deployment constraints

For an existing instance, disable `OIDC_AUTO_PROVISION` and `OIDC_SYNC_PROFILE` unless creating members and overwriting names/emails are explicitly intended. Require verified email and restrict access in the IdP. When provider and native account emails differ, verify the subject independently and create one explicit native `AuthIdentity` link; do not change the native email to force a match. Password login remains an independent access path. Authentication relies on the IdP’s MFA policy because the hook calls n8n’s native session issuer with provider MFA trusted.

Deploy only the reviewed `hooks.js` as a read-only mount in the official pinned n8n image. Pin its commit and checksum. The sidecar image and mutable upstream branches are unnecessary for this installation. The fork does not automatically publish an image or deploy to production. Inherited image workflows target `main`; the audited feature branch and release are maintained separately. Scheduled upstream tests were removed from this branch; push, PR and manual checks remain available.

This is an external hook using private n8n APIs, not a community node, an official authentication plugin API, or a license activation. It can break after n8n upgrades. Sessions and existing WebSocket connections follow native n8n behavior; this fork adds no forced socket-expiry patch, backchannel logout or continuous IdP revocation checks. Re-test password login, actual IdP MFA, account mapping and webhooks before deploying an upgrade. A review of this JavaScript file does not audit the entire n8n image, IdP, browser or infrastructure.
