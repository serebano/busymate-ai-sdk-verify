// @busymate/ai-verify: verifies the Busymate AI connector actor token (bmai.actor/3, contract bmai-identity 2.0.0).
// Runs on Node >=18 and Deno. One dependency: jose. Spec: README.md.
import { compactVerify, decodeProtectedHeader, importJWK, type JWK, type KeyLike } from "jose";

export const DEFAULT_JWKS_URL = "https://busymate.ai/.well-known/bmai-actor-jwks.json";
export const ACTOR_ISSUER = "https://busymate.ai";
export const ACTOR_TYP = "bmai-actor+jwt";

export type VerifyReason =
  | "missing_token" | "malformed" | "bad_alg" | "bad_typ" | "unknown_kid" | "bad_signature" | "bad_issuer"
  | "bad_audience" | "missing_claim" | "expired" | "not_yet_valid" | "lifetime_too_long" | "tenant_mismatch"
  | "connector_mismatch" | "idp_mismatch" | "not_identified" | "tool_mismatch" | "replay" | "jwks_unavailable"
  | "confirmation_required";

/** Thrown for every refusal. Answer 401 with `WWW-Authenticate: Bearer error="invalid_token"` and do not fall through to another user. */
export class BusymateActorError extends Error {
  readonly reason: VerifyReason;
  constructor(reason: VerifyReason, message?: string) {
    super(message ?? reason);
    this.name = "BusymateActorError";
    this.reason = reason;
  }
}

export interface BusymateActor {
  /** Your per-person user id from the launch token. Map users by (idp, sub) only. */
  sub: string;
  idp: string;
  /** True only when the customer confirmed this call in chat. Require it for money and write tools. */
  confirmed: boolean;
  tool: string;
  jti: string;
  supportSessionId?: string;
}

export interface ReplayCache {
  /** Remember `jti` until `exp` (epoch seconds). Return true when new, false when already seen. May be async (Redis SET NX). */
  add(jti: string, exp: number, now: number): boolean | Promise<boolean>;
}

export interface VerifyOptions {
  /** Exact origin of your connector URL, e.g. https://mcp.acme.com */
  audience: string;
  tenantId: string;
  connectorId: string;
  /** Identity provider id; when set, `idp` must match. */
  idp?: string;
  /** The MCP tool being called; when set, the token's `tool` must match. */
  tool?: string;
  jwksUrl?: string;
  /** Static JWKS (offline use and tests). Skips the network. */
  jwks?: { keys: JWK[] };
  replayCache?: ReplayCache;
  /** Epoch seconds, or a function returning them. Tests only. */
  now?: number | (() => number);
  fetch?: typeof fetch;
}

type HeadersLike = Record<string, string | string[] | undefined> | { get(name: string): string | null };
export type VerifyInput = string | HeadersLike | { headers: HeadersLike };

const SKEW = 10;
const MAX_LIFETIME = 120;
const JWKS_TTL_MS = 600_000;
const JWKS_COOLDOWN_MS = 30_000;

/** In-memory replay cache, bounded. Use a shared cache (Redis) when you run several instances. */
export class MemoryReplayCache implements ReplayCache {
  private seen = new Map<string, number>();
  constructor(private max = 50_000) {}
  add(jti: string, exp: number, now: number): boolean {
    if (this.seen.size >= this.max / 2) for (const [k, e] of this.seen) if (e < now) this.seen.delete(k);
    if (this.seen.has(jti) && (this.seen.get(jti) as number) >= now) return false;
    if (this.seen.size >= this.max) this.seen.delete(this.seen.keys().next().value as string);
    this.seen.set(jti, exp);
    return true;
  }
}
const defaultReplay = new MemoryReplayCache();

const jwksCache = new Map<string, { keys: Map<string, KeyLike | Uint8Array>; at: number; lastRefetch: number }>();

async function loadJwks(url: string, f: typeof fetch): Promise<Map<string, KeyLike | Uint8Array>> {
  let res: Response;
  try { res = await f(url, { headers: { accept: "application/json" } }); }
  catch (e) { throw new BusymateActorError("jwks_unavailable", `JWKS fetch failed: ${(e as Error).message}`); }
  if (!res.ok) throw new BusymateActorError("jwks_unavailable", `JWKS fetch failed: HTTP ${res.status}`);
  return importKeys(await res.json());
}
async function importKeys(doc: unknown): Promise<Map<string, KeyLike | Uint8Array>> {
  const out = new Map<string, KeyLike | Uint8Array>();
  const keys = (doc as { keys?: JWK[] })?.keys;
  if (!Array.isArray(keys)) throw new BusymateActorError("jwks_unavailable", "JWKS has no keys array");
  for (const jwk of keys) {
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.kid !== "string") continue;
    if (jwk.alg && jwk.alg !== "ES256") continue;
    if (jwk.use && jwk.use !== "sig") continue;
    out.set(jwk.kid, await importJWK({ ...jwk, alg: "ES256" }, "ES256"));
  }
  return out;
}

async function keyFor(kid: string, o: VerifyOptions, nowMs: number): Promise<KeyLike | Uint8Array> {
  if (o.jwks) {
    const key = (await importKeys(o.jwks)).get(kid);
    if (!key) throw new BusymateActorError("unknown_kid");
    return key;
  }
  const url = o.jwksUrl ?? DEFAULT_JWKS_URL;
  const f = o.fetch ?? fetch;
  let entry = jwksCache.get(url);
  if (!entry || nowMs - entry.at > JWKS_TTL_MS) {
    entry = { keys: await loadJwks(url, f), at: nowMs, lastRefetch: nowMs };
    jwksCache.set(url, entry);
  }
  let key = entry.keys.get(kid);
  if (!key && nowMs - entry.lastRefetch > JWKS_COOLDOWN_MS) { // unknown kid: rotation, refetch (rate-limited)
    entry = { keys: await loadJwks(url, f), at: nowMs, lastRefetch: nowMs };
    jwksCache.set(url, entry);
    key = entry.keys.get(kid);
  }
  if (!key) throw new BusymateActorError("unknown_kid");
  return key;
}

function pick(h: HeadersLike, name: string): string | undefined {
  if (typeof (h as { get?: unknown }).get === "function") return (h as { get(n: string): string | null }).get(name) ?? undefined;
  const rec = h as Record<string, string | string[] | undefined>;
  for (const k of Object.keys(rec)) if (k.toLowerCase() === name) { const v = rec[k]; return Array.isArray(v) ? v[0] : v; }
  return undefined;
}
function headerOf(token: string): { alg?: unknown; typ?: unknown; kid?: unknown } | null {
  try { return decodeProtectedHeader(token) as { alg?: unknown; typ?: unknown; kid?: unknown }; } catch { return null; }
}

/** Returns the raw actor token: `X-Bmai-Actor` first, else `Authorization: Bearer` only when its header typ is `bmai-actor+jwt`. */
export function actorTokenFrom(input: VerifyInput): string | null {
  if (typeof input === "string") return input.trim() || null;
  const h: HeadersLike = "headers" in (input as object) && typeof (input as { headers?: unknown }).headers === "object" && (input as { headers: unknown }).headers
    ? (input as { headers: HeadersLike }).headers : (input as HeadersLike);
  const x = pick(h, "x-bmai-actor");
  if (x && x.trim()) return x.trim();
  const m = /^Bearer\s+(.+)$/i.exec(pick(h, "authorization") ?? "");
  if (!m) return null;
  return headerOf(m[1].trim())?.typ === ACTOR_TYP ? m[1].trim() : null;
}

/**
 * Verifies a bmai.actor/3 token and returns the actor. Throws BusymateActorError (with a stable `reason`) on any failure.
 * Order: token -> header (alg, typ, kid) -> signature -> iss, aud, claims, time, tenant, connector, idp, identified, tool -> replay.
 */
export async function verifyBusymateActor(input: VerifyInput, options: VerifyOptions): Promise<BusymateActor> {
  const nowS = typeof options.now === "function" ? options.now() : options.now ?? Math.floor(Date.now() / 1000);
  const token = actorTokenFrom(input);
  if (!token) throw new BusymateActorError("missing_token");
  if (token.split(".").length !== 3) throw new BusymateActorError("malformed");
  const hdr = headerOf(token);
  if (!hdr) throw new BusymateActorError("malformed");
  if (hdr.alg !== "ES256") throw new BusymateActorError("bad_alg");
  if (hdr.typ !== ACTOR_TYP) throw new BusymateActorError("bad_typ");
  if (typeof hdr.kid !== "string" || !hdr.kid) throw new BusymateActorError("unknown_kid");
  const key = await keyFor(hdr.kid, options, nowS * 1000);
  let payloadBytes: Uint8Array;
  try { ({ payload: payloadBytes } = await compactVerify(token, key, { algorithms: ["ES256"] })); }
  catch { throw new BusymateActorError("bad_signature"); }
  let p: Record<string, unknown>;
  try { p = JSON.parse(new TextDecoder().decode(payloadBytes)); } catch { throw new BusymateActorError("malformed"); }
  if (p === null || typeof p !== "object") throw new BusymateActorError("malformed");

  if (p.iss !== ACTOR_ISSUER) throw new BusymateActorError("bad_issuer");
  const aud = p.aud;
  if (!(aud === options.audience || (Array.isArray(aud) && aud.length === 1 && aud[0] === options.audience))) throw new BusymateActorError("bad_audience");
  const { sub, jti, iat, exp, nbf } = p;
  if (typeof sub !== "string" || !sub || typeof jti !== "string" || !jti || typeof iat !== "number" || typeof exp !== "number") throw new BusymateActorError("missing_claim");
  if (nowS > exp + SKEW) throw new BusymateActorError("expired");
  if (iat > nowS + SKEW || (typeof nbf === "number" && nbf > nowS + SKEW)) throw new BusymateActorError("not_yet_valid");
  if (exp - iat > MAX_LIFETIME) throw new BusymateActorError("lifetime_too_long");
  if (p.tenant_id !== options.tenantId) throw new BusymateActorError("tenant_mismatch");
  if (p.connector_id !== options.connectorId) throw new BusymateActorError("connector_mismatch");
  if (options.idp !== undefined && p.idp !== options.idp) throw new BusymateActorError("idp_mismatch");
  if (p.actor_kind !== "identified") throw new BusymateActorError("not_identified");
  if (options.tool !== undefined && p.tool !== options.tool) throw new BusymateActorError("tool_mismatch");
  if (!(await (options.replayCache ?? defaultReplay).add(jti, exp, nowS))) throw new BusymateActorError("replay");
  return {
    sub, idp: typeof p.idp === "string" ? p.idp : "", confirmed: p.confirmed === true, tool: typeof p.tool === "string" ? p.tool : "",
    jti, supportSessionId: typeof p.support_session_id === "string" ? p.support_session_id : undefined,
  };
}

/** Money-moving and write tools need the customer's in-chat confirmation. Throws `confirmation_required`. */
export function requireConfirmed(actor: BusymateActor, isWriteTool = true): void {
  if (isWriteTool && !actor.confirmed) throw new BusymateActorError("confirmation_required");
}

/** Body for `GET /api/bmai/status` so the Busymate Console can show "connected". */
export const STATUS_BODY = { actorVerifier: true, actor: 3 } as const;
