// Checks for a Busymate AI identity integration. Zero dependencies, Node >= 18.14 (fetch, getSetCookie).
import { createPublicKey, verify as cryptoVerify, randomBytes } from "node:crypto";

export const VERSION = "0.1.1";
const b64u = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const res = (id, status, detail, extra = {}) => ({ id, status, detail, ...extra });
const nonce = () => randomBytes(18).toString("base64url");

async function http(url, { method = "GET", headers = {}, body, timeout = 10000 } = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    return await fetch(url, { method, headers, body, redirect: "manual", signal: ctl.signal });
  } finally { clearTimeout(t); }
}

/** Follows redirects by hand (no cookies) until one leaves `stopOrigin`'s boundary or `max` hops. */
async function chain(url, stopOrigin, opts) {
  const hops = [];
  for (let i = 0; i < 6; i++) {
    const r = await http(url, opts);
    const loc = r.headers.get("location");
    hops.push({ url, status: r.status, headers: r.headers, location: loc ? new URL(loc, url).toString() : null, type: r.headers.get("content-type") || "" });
    if (!loc || r.status < 300 || r.status > 399) break;
    url = new URL(loc, url).toString();
    if (stopOrigin && new URL(url).origin === stopOrigin) { hops.push({ url, status: null, stop: true }); break; }
  }
  return hops;
}

export async function loadJwks(url, o) {
  const r = await http(url, { headers: { accept: "application/json" }, timeout: o.timeout });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const doc = await r.json();
  if (!Array.isArray(doc?.keys)) throw new Error("no keys array");
  return doc;
}

export async function checkJwks(o) {
  const url = o.jwks || (o.issuer && `${o.issuer.replace(/\/$/, "")}/.well-known/jwks.json`);
  if (!url) return [res("jwks", "skip", "no --issuer or --jwks given")];
  let doc;
  try { doc = await loadJwks(url, o); } catch (e) { return [res("jwks", "fail", `${url} not reachable: ${e.message}`)]; }
  const ec = doc.keys.filter((k) => k.kty === "EC" && k.crv === "P-256" && k.kid);
  if (!ec.length) return [res("jwks", "fail", `${url} has no EC P-256 key with a kid (ES256 required; found ${doc.keys.map((k) => k.kty + (k.crv ? "/" + k.crv : "")).join(", ") || "none"})`)];
  const notes = ec.flatMap((k) => [k.alg !== "ES256" && `${k.kid}: alg should be "ES256"`, k.use !== "sig" && `${k.kid}: use should be "sig"`]).filter(Boolean);
  o._jwks = doc;
  return [res("jwks", notes.length ? "warn" : "pass", `${url}: ${ec.length} ES256 key(s) [${ec.map((k) => k.kid).join(", ")}]${notes.length ? "; " + notes.join("; ") : ""}`)];
}

function mintInit(o, auth) {
  const headers = { "content-type": "application/json", accept: "application/json" };
  if (o.origin) headers.origin = o.origin;
  if (auth && o.cookie) headers.cookie = o.cookie;
  if (auth && o.bearer) headers.authorization = `Bearer ${o.bearer}`;
  return { method: "POST", headers, body: JSON.stringify({ nonce: nonce(), returnTo: (o.origin || o.chatOrigin || "https://example.com") + "/" }), timeout: o.timeout };
}

export async function checkMintSignedOut(o) {
  if (!o.mint) return [res("mint_signed_out", "skip", "no --mint given")];
  let r;
  try { r = await http(o.mint, mintInit(o, false)); } catch (e) { return [res("mint_signed_out", "fail", `${o.mint} not reachable: ${e.message}`)]; }
  const out = [];
  if (r.status === 401 || r.status === 403) out.push(res("mint_signed_out", "pass", `signed out -> ${r.status}, no token`));
  else if (r.status >= 200 && r.status < 300) out.push(res("mint_signed_out", "fail", `signed out returned ${r.status}: the endpoint must require your own session and answer 401`));
  else out.push(res("mint_signed_out", "fail", `signed out returned ${r.status}, expected 401`));
  if (o.origin && new URL(o.mint).origin !== o.origin) {
    const acao = r.headers.get("access-control-allow-origin"), acc = r.headers.get("access-control-allow-credentials");
    out.push(acao === o.origin && acc === "true"
      ? res("mint_cors", "pass", `CORS allows ${o.origin} with credentials`)
      : res("mint_cors", "fail", `cross-origin mint must answer Access-Control-Allow-Origin: ${o.origin} and Allow-Credentials: true (got ${acao ?? "none"} / ${acc ?? "none"})`));
  }
  return out;
}

function claimsOf(token) {
  const [h, p, s] = token.split(".");
  return { header: JSON.parse(b64u(h)), payload: JSON.parse(b64u(p)), signing: `${h}.${p}`, sig: b64u(s) };
}

export async function checkMintSignedIn(o) {
  if (!o.mint) return [];
  if (!o.cookie && !o.bearer) return [res("mint_signed_in", "skip", "pass --cookie or --bearer (a test session) to check the 201 shape")];
  const out = [];
  const tokens = [];
  for (let i = 0; i < 2; i++) {
    const init = mintInit(o, true);
    const sent = JSON.parse(init.body).nonce;
    let r;
    try { r = await http(o.mint, init); } catch (e) { return [res("mint_signed_in", "fail", `not reachable: ${e.message}`)]; }
    if (r.status !== 201) return [res("mint_signed_in", "fail", `signed in returned ${r.status}, expected 201`)];
    let b;
    try { b = await r.json(); } catch { return [res("mint_signed_in", "fail", "201 body is not JSON")]; }
    const problems = [];
    if (typeof b.token !== "string" || b.token.split(".").length !== 3) problems.push("body.token is not a JWT");
    if (b.nonce !== sent) problems.push("nonce is not echoed unchanged");
    if (!/no-store/i.test(r.headers.get("cache-control") || "")) problems.push("Cache-Control must include no-store");
    if (typeof b.expiresIn !== "number") problems.push("expiresIn missing");
    else if (b.expiresIn > 120) problems.push(`expiresIn ${b.expiresIn} > 120`);
    if (problems.length) return [res("mint_signed_in", "fail", problems.join("; "))];
    tokens.push({ token: b.token, nonce: sent });
  }
  out.push(res("mint_signed_in", "pass", "201 { token, nonce, expiresIn }, nonce echoed, Cache-Control: no-store"));
  const c = [];
  let warn = [];
  try {
    const t = claimsOf(tokens[0].token), u = claimsOf(tokens[1].token);
    if (t.header.alg !== "ES256") c.push(`alg ${t.header.alg}, need ES256`);
    const jwk = o._jwks?.keys?.find((k) => k.kid === t.header.kid);
    if (o._jwks) {
      if (!jwk) c.push(`kid ${t.header.kid} not in the JWKS`);
      else if (!cryptoVerify("sha256", Buffer.from(t.signing), { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, t.sig)) c.push("signature does not verify against the JWKS (ES256 needs raw r||s, 64 bytes)");
    } else warn.push("JWKS not loaded, signature not verified");
    const p = t.payload;
    if (o.issuer && p.iss !== o.issuer.replace(/\/$/, "")) c.push(`iss ${p.iss} != ${o.issuer}`);
    if (p.aud !== (o.audience || "busymate-ai")) c.push(`aud ${JSON.stringify(p.aud)} != ${o.audience || "busymate-ai"}`);
    if (!p.sub) c.push("sub missing");
    else if (/@/.test(p.sub)) warn.push("sub looks like an e-mail address; use an immutable internal user id");
    if (o.tenantId && p.tenant_id !== o.tenantId) c.push(`tenant_id ${p.tenant_id} != ${o.tenantId}`);
    if (p.nonce !== tokens[0].nonce) c.push("nonce claim differs from the request nonce");
    if (!p.jti) c.push("jti missing");
    if (typeof p.exp !== "number" || typeof p.iat !== "number") c.push("iat/exp missing");
    else if (p.exp - p.iat > 120) c.push(`exp-iat is ${p.exp - p.iat} s, keep it at 120 s or less`);
    if (u.payload.jti === p.jti) c.push("jti repeats between mints; it must be unique per token");
  } catch (e) { c.push(`token could not be decoded: ${e.message}`); }
  out.push(res("mint_token", c.length ? "fail" : warn.length ? "warn" : "pass", c.length ? c.join("; ") : `ES256 token, claims ok${warn.length ? "; " + warn.join("; ") : ""}`));
  return out;
}

function withParams(url, params) {
  const u = new URL(url);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

export async function checkPromptNone(o) {
  if (!o.loginUrl) return [res("prompt_none", "skip", "no --login-url given (script-tag and SDK sites do not need one)")];
  if (!o.chatOrigin) return [res("prompt_none", "skip", "no --chat-origin given")];
  const returnTo = `${o.chatOrigin}/`;
  const url = withParams(o.loginUrl, { return_to: returnTo, bmai_nonce: nonce(), bmai_client: "web", bmai_prompt: "none" });
  let hops;
  try { hops = await chain(url, o.chatOrigin, { timeout: o.timeout }); } catch (e) { return [res("prompt_none", "fail", `${o.loginUrl} not reachable: ${e.message}`)]; }
  const last = [...hops].reverse().find((h) => h.location) ;
  const stopHop = hops[hops.length - 1];
  const final = stopHop.stop ? stopHop.url : last?.location;
  if (final && new URL(final).origin === o.chatOrigin) {
    const frag = new URL(final).hash.slice(1);
    const q = new URLSearchParams(frag);
    if (q.get("error") === "login_required") return [res("prompt_none", "pass", `signed out + bmai_prompt=none -> redirect to ${returnTo}#error=login_required, no UI`)];
    if (q.get("bmai_token")) return [res("prompt_none", "warn", "got a token while signed out (the identity-check request carried no cookies); is the login page minting for anonymous users?")];
    return [res("prompt_none", "fail", `redirected to ${final} but the fragment is "${frag}", expected #error=login_required`)];
  }
  const l = hops[hops.length - 1];
  if (l.status >= 400) return [res("prompt_none", "fail", `login page answered ${l.status} for bmai_prompt=none`)];
  if (l.status === 200) return [res("prompt_none", "warn", `login page answered 200 (${l.type.split(";")[0] || "no type"}) instead of redirecting to return_to#error=login_required. If it redirects with JavaScript and shows no UI that is fine, but an HTTP redirect is safest. This check cannot run a browser.`)];
  return [res("prompt_none", "fail", `unexpected ${l.status} from the login page`)];
}

export function frameAncestors(csp) {
  for (const d of (csp || "").split(";")) {
    const [name, ...vals] = d.trim().split(/\s+/);
    if (name && name.toLowerCase() === "frame-ancestors") return vals;
  }
  return null;
}

export async function checkFraming(o) {
  if (!o.loginUrl) return [res("framing", "skip", "no --login-url given")];
  const url = withParams(o.loginUrl, { return_to: `${o.chatOrigin || "https://example.com"}/`, bmai_nonce: nonce(), bmai_client: "web" });
  let hops;
  try { hops = await chain(url, o.chatOrigin, { timeout: o.timeout }); } catch (e) { return [res("framing", "fail", `not reachable: ${e.message}`), res("cookies", "skip", "login page unreachable")]; }
  const doc = [...hops].reverse().find((h) => h.status && (h.status < 300 || h.status > 399));
  if (!doc) return [res("framing", "skip", "the login page only redirects; framing applies to the document it finally shows"), res("cookies", "skip", "no login document to inspect")];
  const out = [];
  const xfo = (doc.headers.get("x-frame-options") || "").trim();
  const fa = frameAncestors(doc.headers.get("content-security-policy"));
  const problems = [];
  if (xfo && /^(deny|sameorigin)$/i.test(xfo)) problems.push(`X-Frame-Options: ${xfo} blocks the hidden-frame silent check`);
  if (fa) {
    const ok = fa.includes("*") || (o.chatOrigin && fa.includes(o.chatOrigin));
    if (!ok) problems.push(`CSP frame-ancestors (${fa.join(" ")}) does not allow ${o.chatOrigin || "the chat origin"}`);
  }
  out.push(problems.length
    ? res("framing", "fail", problems.join("; ") + `. Send Content-Security-Policy: frame-ancestors ${o.chatOrigin || "<chat origin>"} and drop X-Frame-Options.`)
    : res("framing", "pass", fa ? `frame-ancestors allows the chat origin (${fa.join(" ")})` : "no X-Frame-Options or frame-ancestors restriction on the login page"));
  const cookies = doc.headers.getSetCookie?.() ?? [];
  if (!cookies.length) out.push(res("cookies", "warn", "login page set no cookie while signed out, so SameSite cannot be checked here. Your session cookie must be SameSite=None; Secure for the hidden-frame check to see signed-in users."));
  else {
    const weak = cookies.filter((c) => !/;\s*samesite=none/i.test(c) || !/;\s*secure/i.test(c)).map((c) => c.split("=")[0]);
    out.push(weak.length
      ? res("cookies", "warn", `cookie(s) ${weak.join(", ")} lack SameSite=None; Secure. The session cookie needs both, otherwise signed-in users stay guests on hosted pages.`)
      : res("cookies", "pass", `${cookies.length} cookie(s) set with SameSite=None; Secure`));
  }
  return out;
}

export async function checkActor(o) {
  if (!o.mcp) return [res("actor_roundtrip", "skip", "no --mcp given")];
  const base = o.mcp.replace(/\/$/, "");
  const out = [];
  let r;
  try { r = await http(`${base}/api/bmai/status`, { headers: { accept: "application/json" }, timeout: o.timeout }); } catch (e) { return [res("actor_roundtrip", "fail", `${base} not reachable: ${e.message}`)]; }
  if (r.status === 404) out.push(res("actor_roundtrip", "warn", `${base}/api/bmai/status is missing (optional, but the Console shows "connected" only when it answers {"actorVerifier":true,"actor":3})`));
  else if (r.status !== 200) out.push(res("actor_roundtrip", "fail", `${base}/api/bmai/status answered ${r.status}`));
  else {
    let b = {};
    try { b = await r.json(); } catch { /* handled below */ }
    if (b.actorVerifier !== true) out.push(res("actor_roundtrip", "fail", `status says actorVerifier=${JSON.stringify(b.actorVerifier)}; the verifier is not installed`));
    else if (b.actor !== 3) out.push(res("actor_roundtrip", "warn", `verifier is on, but reports actor=${JSON.stringify(b.actor)}; add bmai.actor/3 (ES256) support`));
    else out.push(res("actor_roundtrip", "pass", `${base}/api/bmai/status -> actorVerifier:true, actor:3`));
  }
  const probe = o.probeUrl;
  if (probe) {
    const garbage = `${Buffer.from('{"alg":"ES256","typ":"bmai-actor+jwt","kid":"identity-check"}').toString("base64url")}.${Buffer.from("{}").toString("base64url")}.${"A".repeat(86)}`;
    try {
      const bad = await http(probe, { headers: { "x-bmai-actor": garbage }, timeout: o.timeout });
      out.push(bad.status === 401 ? res("actor_rejects_bad", "pass", `${probe}: forged actor token -> 401`) : res("actor_rejects_bad", "fail", `${probe}: forged actor token answered ${bad.status}, expected 401`));
      if (o.actorToken) {
        const good = await http(probe, { headers: { "x-bmai-actor": o.actorToken }, timeout: o.timeout });
        out.push(good.status === 401 || good.status === 403 ? res("actor_accepts_good", "fail", `${probe}: real actor token answered ${good.status}`) : res("actor_accepts_good", "pass", `${probe}: real actor token -> ${good.status}`));
      }
    } catch (e) { out.push(res("actor_rejects_bad", "fail", `${probe} not reachable: ${e.message}`)); }
  } else out.push(res("actor_rejects_bad", "skip", "pass --probe-url (a protected MCP/API URL) to check that forged tokens get 401"));
  return out;
}

export async function runChecks(o) {
  o.timeout ||= 10000;
  const results = [];
  for (const f of [checkJwks, checkMintSignedOut, checkMintSignedIn, checkPromptNone, checkFraming, checkActor]) {
    try { results.push(...(await f(o))); } catch (e) { results.push(res(f.name, "fail", `check crashed: ${e.message}`)); }
  }
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0 };
  for (const r of results) counts[r.status]++;
  return { ok: counts.fail === 0, version: VERSION, counts, checks: results };
}
