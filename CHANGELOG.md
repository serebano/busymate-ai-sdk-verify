# Changelog

## 0.1.2

- Release through npm trusted publishing (GitHub OIDC) only; `release.yml` no longer reads an `NPM_TOKEN` secret. No code change from 0.1.1.

## 0.1.1

- First npm publish of `@busymate/ai-verify` and `@busymate/identity-check`, with provenance (`release.yml` uses GitHub OIDC, `--provenance --access public`). No code change from 0.1.0.

## 0.1.0

First release.

- `@busymate/ai-verify` 0.1.0: `verifyBusymateActor(req | headers | token, { audience, tenantId, connectorId, idp?, tool?, jwksUrl?, replayCache? })` returns `{ sub, idp, confirmed, tool, jti, supportSessionId }`. ES256 only, `typ bmai-actor+jwt`, exact `aud`, `tenant_id`, `connector_id`, optional `idp`, `actor_kind identified`, `exp - iat <= 120`, 10 s skew, `jti` replay (pluggable cache, in-memory default), optional `tool` match. Cached JWKS with refetch on unknown `kid`. Typed `BusymateActorError` with stable reason codes. `requireConfirmed()`. ESM + types, Node >= 18 and Deno, one dependency (`jose`).
- Python, PHP and Go single-file verifiers with the same check order and reason codes.
- Shared test vectors (`vectors/actor-v3.json`, 37 cases: valid and every rejection), run in CI by all five languages. Local set until the identity contract vectors are vendored (`scripts/sync-vectors.mjs`).
- `@busymate/identity-check` 0.1.0: JWKS, mint (signed out, optional signed in with a test session), `login_url` `bmai_prompt=none`, framing headers, `SameSite=None` cookies, actor round trip; human and `--json` output; zero dependencies.
- CI (`sdk-check`), a `release.yml` that attaches tarballs to the GitHub release and publishes to npm only when `NPM_TOKEN` exists.
