# Actor token `bmai.actor/3`: what the verifier enforces

Source of truth: the `bmai-identity` 2.0.0 identity contract. This page restates what every implementation here checks, in order. A refusal at an earlier step wins.

| # | Step | Refusal reason |
|---|---|---|
| 1 | Token from `X-Bmai-Actor`, else `Authorization: Bearer` whose header `typ` is `bmai-actor+jwt`, else none | `missing_token` |
| 2 | Three dot-separated segments, header and payload are JSON objects | `malformed` |
| 3 | Header `alg == "ES256"` | `bad_alg` |
| 4 | Header `typ == "bmai-actor+jwt"` | `bad_typ` |
| 5 | Header `kid` present and in the JWKS (refetch once on unknown) | `unknown_kid` |
| 6 | ES256 signature (raw `r||s`, 64 bytes) | `bad_signature` |
| 7 | `iss == "https://busymate.ai"` | `bad_issuer` |
| 8 | `aud` equals your connector origin exactly (a one-element array is allowed) | `bad_audience` |
| 9 | `sub`, `jti` non-empty strings; `iat`, `exp` numbers | `missing_claim` |
| 10 | `now <= exp + 10` | `expired` |
| 11 | `iat <= now + 10` and `nbf <= now + 10` (when present) | `not_yet_valid` |
| 12 | `exp - iat <= 120` | `lifetime_too_long` |
| 13 | `tenant_id`, `connector_id` equal yours | `tenant_mismatch`, `connector_mismatch` |
| 14 | `idp` equals yours (only when you configure it) | `idp_mismatch` |
| 15 | `actor_kind == "identified"` | `not_identified` |
| 16 | `tool` equals the called tool (only when you pass it) | `tool_mismatch` |
| 17 | `jti` not seen before until its `exp`. Recorded only after steps 1-16 pass | `replay` |

Other reasons: `jwks_unavailable` (the JWKS could not be fetched), `confirmation_required` (`requireConfirmed`).

Claims returned: `sub` (map users by `(idp, sub)`), `idp`, `confirmed` (`true` only when the customer confirmed this call), `tool`, `jti`, `support_session_id` (logging only).

Rules for callers: take the user only from `sub`; never from tool arguments. Require `confirmed` for money-moving and write tools. Answer 401 with `WWW-Authenticate: Bearer error="invalid_token"` and never fall through to another user. JWKS keys rotate every 90 days with a 14-day overlap.
