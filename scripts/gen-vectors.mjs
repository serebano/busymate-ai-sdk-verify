// Generates vectors/actor-v3.json (own vector set, same shape the identity contract ships).
// The test key pair is committed (vectors/test-keys.private.json) so regeneration is stable; it signs test tokens only.
import { SignJWT, generateKeyPair, exportJWK, importJWK } from "jose";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vdir = join(root, "vectors");
const NOW = 1793000000; // fixed clock for every language
const ISS = "https://busymate.ai";
const config = {
  audience: "https://mcp.example.test",
  tenant_id: "acme",
  connector_id: "conn_acme_1",
  idp: "idp_acme",
};

await mkdir(vdir, { recursive: true });
const keyFile = join(vdir, "test-keys.private.json");
let keys;
if (existsSync(keyFile)) keys = JSON.parse(await readFile(keyFile, "utf8"));
else {
  keys = {};
  for (const kid of ["test-1", "test-2", "test-other"]) {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    keys[kid] = { private: await exportJWK(privateKey), public: { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" } };
    keys[kid].private.kid = kid;
  }
  await writeFile(keyFile, JSON.stringify({ _warning: "TEST KEYS ONLY. Never used in production.", ...keys }, null, 2) + "\n");
}
delete keys._warning;

const claims = (over = {}) => ({
  iss: ISS, aud: config.audience, sub: "user_123", idp: config.idp, tenant_id: config.tenant_id,
  connector_id: config.connector_id, support_session_id: "ss_1", actor_kind: "identified", confirmed: false,
  tool: "get_wallet_balance", iat: NOW - 10, nbf: NOW - 10, exp: NOW + 100, jti: "jti-base", ...over,
});
async function sign(payload, { kid = "test-1", alg = "ES256", typ = "bmai-actor+jwt", signWith = kid, omitKid = false } = {}) {
  const k = await importJWK(keys[signWith].private, "ES256");
  const header = { alg, typ, ...(omitKid ? {} : { kid }) };
  return new SignJWT(payload).setProtectedHeader(header).sign(k);
}
const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");

let n = 0;
const jti = () => `jti-${++n}`;
const X = (token) => ({ "X-Bmai-Actor": token });
const ok = (over = {}, extra = {}) => ({
  ok: true,
  actor: { sub: "user_123", idp: config.idp, confirmed: false, tool: "get_wallet_balance", jti: "", supportSessionId: "ss_1", ...extra, ...over },
});
const bad = (reason) => ({ ok: false, reason });
const cases = [];
async function add(name, description, headers, expect, options = {}) {
  cases.push({ name, description, options, calls: [{ headers, expect }] });
}
async function valid(name, description, payloadOver, signOpts, options, headerKind = "x") {
  const p = claims({ jti: jti(), ...payloadOver });
  const t = await sign(p, signOpts);
  const headers = headerKind === "x" ? X(t) : { Authorization: `Bearer ${t}` };
  await add(name, description, headers, ok({ jti: p.jti, tool: p.tool, confirmed: p.confirmed === true, sub: p.sub, idp: p.idp }), options);
}
async function reject(name, description, reason, payloadOver, signOpts, options, tokenFn) {
  const p = claims({ jti: jti(), ...payloadOver });
  for (const k of Object.keys(p)) if (p[k] === undefined) delete p[k];
  let t = await sign(p, signOpts);
  if (tokenFn) t = tokenFn(t);
  await add(name, description, X(t), bad(reason), options);
}

await valid("valid_x_header", "Token in X-Bmai-Actor", {});
await valid("valid_bearer_typ", "Token in Authorization: Bearer with header typ bmai-actor+jwt", {}, {}, {}, "bearer");
await valid("valid_confirmed", "confirmed:true is passed through", { confirmed: true });
await valid("valid_second_key", "Second JWKS key selected by kid", {}, { kid: "test-2" });
await valid("valid_tool_matches", "Optional tool check passes when equal", { tool: "create_delivery" }, {}, { tool: "create_delivery" });
await valid("valid_idp_not_configured", "idp is optional on the verifier", { idp: "idp_other" }, {}, { idp: null });
await valid("valid_lifetime_120", "exp-iat of exactly 120 s is allowed", { iat: NOW - 20, nbf: NOW - 20, exp: NOW + 100 });
await valid("valid_expired_within_skew", "Expired by 5 s is inside the 10 s skew", { iat: NOW - 60, nbf: NOW - 60, exp: NOW - 5 });
await valid("valid_nbf_within_skew", "nbf 5 s in the future is inside the 10 s skew", { iat: NOW - 5, nbf: NOW + 5, exp: NOW + 100 });

await add("missing_token", "No header at all", {}, bad("missing_token"));
await add("bearer_not_actor_typ", "Authorization Bearer whose typ is JWT is not an actor token", {
  Authorization: `Bearer ${await sign(claims({ jti: jti() }), { typ: "JWT" })}`,
}, bad("missing_token"));
await add("bearer_opaque", "Authorization Bearer with an opaque (API key) value", { Authorization: "Bearer sk_live_abc123" }, bad("missing_token"));
await reject("x_header_wrong_typ", "X-Bmai-Actor token with typ JWT", "bad_typ", {}, { typ: "JWT" });
await add("malformed", "X-Bmai-Actor is not a JWT", X("not.a.jwt"), bad("malformed"));
await add("malformed_two_parts", "Only two segments", X("aaaa.bbbb"), bad("malformed"));
await add("bad_alg_hs256", "alg HS256 is refused", X(`${b64u({ alg: "HS256", typ: "bmai-actor+jwt", kid: "test-1" })}.${b64u(claims({ jti: jti() }))}.${b64u("sig")}`), bad("bad_alg"));
await add("bad_alg_none", "alg none is refused", X(`${b64u({ alg: "none", typ: "bmai-actor+jwt", kid: "test-1" })}.${b64u(claims({ jti: jti() }))}.`), bad("bad_alg"));
await reject("unknown_kid", "kid not in the JWKS", "unknown_kid", {}, { kid: "test-1" }, {}, (t) => {
  const [h, p, s] = t.split("."); const hd = JSON.parse(Buffer.from(h, "base64url")); hd.kid = "nope";
  return `${b64u(hd)}.${p}.${s}`;
});
await reject("missing_kid", "no kid in the header", "unknown_kid", {}, { omitKid: true });
await reject("bad_signature_tampered", "Payload changed after signing", "bad_signature", {}, {}, {}, (t) => {
  const [h, p, s] = t.split("."); const pl = JSON.parse(Buffer.from(p, "base64url")); pl.sub = "user_999";
  return `${h}.${b64u(pl)}.${s}`;
});
await reject("bad_signature_other_key", "Signed by a key that is not published under that kid", "bad_signature", {}, { kid: "test-1", signWith: "test-other" });
await reject("bad_issuer", "iss differs", "bad_issuer", { iss: "https://evil.example" });
await reject("bad_audience", "aud is another connector", "bad_audience", { aud: "https://other.example.test" });
await reject("bad_audience_trailing_slash", "aud must match the origin exactly", "bad_audience", { aud: "https://mcp.example.test/" });
await reject("expired", "exp 11 s in the past (skew is 10 s)", "expired", { iat: NOW - 60, nbf: NOW - 60, exp: NOW - 11 });
await reject("not_yet_valid", "nbf 11 s in the future", "not_yet_valid", { iat: NOW - 5, nbf: NOW + 11, exp: NOW + 100 });
await reject("lifetime_too_long", "exp-iat is 121 s", "lifetime_too_long", { iat: NOW - 21, nbf: NOW - 21, exp: NOW + 100 });
await reject("tenant_mismatch", "tenant_id differs", "tenant_mismatch", { tenant_id: "other" });
await reject("connector_mismatch", "connector_id differs", "connector_mismatch", { connector_id: "conn_other" });
await reject("idp_mismatch", "idp differs when the verifier pins it", "idp_mismatch", { idp: "idp_other" });
await reject("not_identified_anonymous", "actor_kind anonymous", "not_identified", { actor_kind: "anonymous", sub: "anonymous:abc" });
await reject("not_identified_missing", "actor_kind absent", "not_identified", { actor_kind: undefined });
await reject("tool_mismatch", "token is for another tool", "tool_mismatch", { tool: "create_delivery" }, {}, { tool: "get_wallet_balance" });
await reject("missing_claim_jti", "no jti", "missing_claim", { jti: undefined });
await reject("missing_claim_sub", "no sub", "missing_claim", { sub: undefined });

// Replay: same token twice with one shared replay cache.
{
  const p = claims({ jti: jti() });
  const t = await sign(p);
  cases.push({
    name: "replay", description: "Second use of the same jti is refused", options: {},
    calls: [
      { headers: X(t), expect: ok({ jti: p.jti }) },
      { headers: X(t), expect: bad("replay") },
    ],
  });
}
// A rejected token must not burn its jti.
{
  const p = claims({ jti: jti() });
  const t = await sign(p);
  cases.push({
    name: "rejected_does_not_consume_jti", description: "A call refused for tool_mismatch leaves the jti usable", options: {},
    calls: [
      { headers: X(t), options: { tool: "other_tool" }, expect: bad("tool_mismatch") },
      { headers: X(t), expect: ok({ jti: p.jti }) },
    ],
  });
}

const out = {
  contract: "bmai-identity",
  contract_version: "2.0.0",
  token_format: "bmai.actor/3",
  vector_set: "busymate-ai-sdk-verify/local-1",
  source: "local",
  now: NOW,
  issuer: ISS,
  skew_seconds: 10,
  max_lifetime_seconds: 120,
  config,
  jwks: { keys: [keys["test-1"].public, keys["test-2"].public] },
  reasons: [
    "missing_token", "malformed", "bad_alg", "bad_typ", "unknown_kid", "bad_signature", "bad_issuer", "bad_audience",
    "missing_claim", "expired", "not_yet_valid", "lifetime_too_long", "tenant_mismatch", "connector_mismatch",
    "idp_mismatch", "not_identified", "tool_mismatch", "replay", "jwks_unavailable", "confirmation_required",
  ],
  cases,
};
await writeFile(join(vdir, "actor-v3.json"), JSON.stringify(out, null, 2) + "\n");
await writeFile(join(vdir, "jwks.json"), JSON.stringify(out.jwks, null, 2) + "\n");
console.log(`wrote ${cases.length} cases`);
