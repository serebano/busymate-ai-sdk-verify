# Busymate AI verify — 0.1.2

Official customer-side verification of the Busymate AI **connector actor token** (`bmai.actor/3`, contract `bmai-identity` 2.0.0), plus a CLI that checks your whole identity integration from a clean machine.

When a signed-in customer asks your assistant for something only your account tools can answer, Busymate calls your MCP server or API with a short-lived, ES256-signed token that says "Busymate verified this person as `sub`". You verify it and act as that user. No shared secret, no second login, no "Authorize" card.

| Piece | What | Where |
|---|---|---|
| `@busymate/ai-verify` | Verifier for Node >= 18 and Deno. One dependency: [`jose`](https://github.com/panva/jose). | [`packages/ai-verify`](packages/ai-verify) |
| Python, PHP, Go | Single-file verifiers, tested against the same vectors in CI. | [`snippets/`](snippets) |
| `@busymate/identity-check` | CLI: issuer JWKS, mint endpoint, `login_url` silent check, framing headers, cookies, actor round trip. Zero dependencies. | [`packages/identity-check`](packages/identity-check) |
| Test vectors | One JSON set that every language must pass: valid tokens and every rejection case. | [`vectors/`](vectors) |

The token format and the vectors are owned by the identity contract in the private product repository. This repository vendors the vectors (`scripts/sync-vectors.mjs`) and CI fails when they diverge. See [`docs/token-v3.md`](docs/token-v3.md).

## Install

```sh
npm install @busymate/ai-verify
npx @busymate/identity-check --help
```

The same tarballs are attached to each [GitHub release](https://github.com/serebano/busymate-ai-sdk-verify/releases) with `SHA256SUMS` (for example `npm install https://github.com/serebano/busymate-ai-sdk-verify/releases/download/0.1.2/busymate-ai-verify-0.1.2.tgz`). Python, PHP and Go: copy the file from `busymate-ai-verify-snippets-<version>.tgz` (or this repo) into your project.

## Verify in your MCP server (Node / Deno)

```ts
import { verifyBusymateActor, requireConfirmed, BusymateActorError } from "@busymate/ai-verify";

// before your API-key / OAuth checks; toolName is the MCP tools/call name
try {
  const actor = await verifyBusymateActor(req, {          // req, a Headers object, a headers record or a raw token
    audience: "https://mcp.acme.com",                      // EXACT origin of your connector URL
    tenantId: "acme",
    connectorId: process.env.BMAI_CONNECTOR_ID!,
    idp: process.env.BMAI_IDP,                             // optional, recommended
    tool: toolName,                                        // optional, recommended: token must be for this tool
  });
  const user = await users.findByBusymateIdentity(actor.idp, actor.sub);   // map (idp, sub) only
  requireConfirmed(actor, WRITE_TOOLS.has(toolName));      // money and write tools need confirmed === true
  // run the tool as `user`. Never read an account id from tool arguments.
} catch (e) {
  if (e instanceof BusymateActorError) return reply(401, { "WWW-Authenticate": 'Bearer error="invalid_token"' }); // e.reason is a stable code
  throw e;
}
```

- Reads `X-Bmai-Actor` first, else `Authorization: Bearer` **only when** the token header `typ` is `bmai-actor+jwt` (so your own API keys and OAuth tokens pass through untouched).
- Enforces: `alg=ES256`, `typ`, `kid` in the JWKS, `iss=https://busymate.ai`, exact `aud`, `tenant_id`, `connector_id`, optional `idp`, `actor_kind=identified`, `exp - iat <= 120`, clock skew <= 10 s, `jti` replay and (when given) `tool`.
- Keys come from `https://busymate.ai/.well-known/bmai-actor-jwks.json` (cached 10 min, refetched once on an unknown `kid`, at most every 30 s).
- The replay cache is in memory by default. Behind several instances, pass `replayCache: { add(jti, exp, now) }` backed by Redis `SET NX EX`.
- Serve `GET /api/bmai/status` returning `{"actorVerifier": true, "actor": 3}` (exported as `STATUS_BODY`) so the Console shows "connected".

Reason codes: `missing_token`, `malformed`, `bad_alg`, `bad_typ`, `unknown_kid`, `bad_signature`, `bad_issuer`, `bad_audience`, `missing_claim`, `expired`, `not_yet_valid`, `lifetime_too_long`, `tenant_mismatch`, `connector_mismatch`, `idp_mismatch`, `not_identified`, `tool_mismatch`, `replay`, `jwks_unavailable`, `confirmation_required`. Log the reason; show the caller nothing but 401.

Deno: `import { verifyBusymateActor } from "npm:@busymate/ai-verify"` (or the release tarball). CI runs the vectors under Deno.

## Python, PHP, Go

```python
from busymate_verify import verify_busymate_actor, require_confirmed, BusymateActorError   # pip install cryptography
actor = verify_busymate_actor(request.headers, audience="https://mcp.acme.com", tenant_id="acme", connector_id="conn_1", tool=tool_name)
```

```php
require 'BusymateVerify.php';                                                              // PHP >= 8.1, ext-openssl
$actor = BusymateVerify::verify(getallheaders(), ['audience' => 'https://mcp.acme.com', 'tenant_id' => 'acme', 'connector_id' => 'conn_1']);
```

```go
v := busymateverify.New(busymateverify.Options{Audience: "https://mcp.acme.com", TenantID: "acme", ConnectorID: "conn_1"}) // stdlib only
actor, err := v.Verify(r.Header)
```

All five implementations follow the same check order and return the same reason codes.

## identity-check

```sh
npx @busymate/identity-check \
  --issuer https://api.acme.com --mint https://api.acme.com/api/bmai/identity \
  --login-url https://acme.com/login --chat-origin https://assistant.acme.com \
  --mcp https://mcp.acme.com --probe-url https://mcp.acme.com/mcp --tenant-id acme
```

Checks: JWKS reachable with an ES256 key; mint endpoint answers `401` signed out (and, with a **test** `--cookie`/`--bearer`, `201 { token, nonce, expiresIn }` with `Cache-Control: no-store`, a correct ES256 token and unique `jti`); `login_url` with `bmai_prompt=none` redirects to `return_to#error=login_required` without UI; the login page can be framed by the chat origin (CSP `frame-ancestors`, no `X-Frame-Options: DENY`) and cookies are `SameSite=None; Secure`; connector `GET /api/bmai/status`, and a forged actor token gets `401`. `--json` for machines. Exit code 0 / 1 (a check failed) / 2 (usage). `--help` lists every option.

Try it without a tenant: `node demo/demo-tenant.mjs 8787` starts a demo tenant (add `--broken` for a failing one).

## Develop

```sh
npm install && npm run typecheck && npm test           # Node
npm run test:deno -w @busymate/ai-verify               # Deno
python3 -m unittest -q test_vectors                    # in snippets/python (needs cryptography)
php snippets/php/test_vectors.php                      # PHP >= 8.1
go test ./...                                          # in snippets/go
node scripts/gen-vectors.mjs                           # regenerate the local vector set (while no contract vectors are vendored)
node scripts/sync-vectors.mjs --check
```

Releases: push a tag equal to the package version after `sdk-check` is green on `main`. `release.yml` creates the GitHub release with tarballs and `SHA256SUMS`, then publishes both packages to npm with provenance.

Status: pre-1.0. The token format is fixed by the contract; the package API may still change in 0.x.
