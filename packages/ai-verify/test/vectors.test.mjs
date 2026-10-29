import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyBusymateActor, requireConfirmed, MemoryReplayCache, BusymateActorError, actorTokenFrom } from "../dist/index.js";

const V = JSON.parse(readFileSync(new URL("../../../vectors/actor-v3.json", import.meta.url), "utf8"));

function optionsFor(over) {
  const c = { ...V.config, ...over };
  const o = { audience: c.audience, tenantId: c.tenant_id, connectorId: c.connector_id, jwks: V.jwks, now: V.now };
  if (c.idp) o.idp = c.idp;
  if (c.tool) o.tool = c.tool;
  return o;
}

for (const c of V.cases) {
  test(`vector ${c.name}`, async () => {
    const cache = new MemoryReplayCache();
    for (const call of c.calls) {
      const o = { ...optionsFor({ ...c.options, ...(call.options ?? {}) }), replayCache: cache };
      if (call.expect.ok) {
        const a = await verifyBusymateActor(call.headers, o);
        assert.deepEqual(a, call.expect.actor);
      } else {
        await assert.rejects(verifyBusymateActor(call.headers, o), (e) => e instanceof BusymateActorError && e.reason === call.expect.reason, call.expect.reason);
      }
    }
  });
}

test("vector set covers every reason except jwks_unavailable and confirmation_required", () => {
  const seen = new Set(V.cases.flatMap((c) => c.calls.map((k) => k.expect.reason)).filter(Boolean));
  for (const r of V.reasons) if (!["jwks_unavailable", "confirmation_required"].includes(r)) assert.ok(seen.has(r), `no vector for ${r}`);
});

test("accepts a Fetch Headers object, a request-like and a raw token", async () => {
  const c = V.cases.find((x) => x.name === "valid_x_header");
  const token = c.calls[0].headers["X-Bmai-Actor"];
  const mk = () => ({ ...optionsFor({}), replayCache: new MemoryReplayCache() });
  assert.equal((await verifyBusymateActor(new Headers({ "x-bmai-actor": token }), mk())).sub, "user_123");
  assert.equal((await verifyBusymateActor({ headers: { "x-bmai-actor": token } }, mk())).sub, "user_123");
  assert.equal((await verifyBusymateActor(token, mk())).sub, "user_123");
  assert.equal(actorTokenFrom({}), null);
});

test("requireConfirmed", () => {
  requireConfirmed({ sub: "a", idp: "i", confirmed: true, tool: "t", jti: "j" });
  requireConfirmed({ sub: "a", idp: "i", confirmed: false, tool: "t", jti: "j" }, false);
  assert.throws(() => requireConfirmed({ sub: "a", idp: "i", confirmed: false, tool: "t", jti: "j" }), (e) => e.reason === "confirmation_required");
});

test("JWKS fetched once, refetched (rate-limited) on unknown kid, jwks_unavailable on failure", async () => {
  const c = V.cases.find((x) => x.name === "valid_second_key").calls[0];
  let calls = 0;
  const fetchOk = async () => { calls++; return new Response(JSON.stringify(V.jwks), { status: 200 }); };
  const base = { ...optionsFor({}) }; delete base.jwks;
  const url = "https://jwks.test/a";
  await verifyBusymateActor(c.headers, { ...base, jwksUrl: url, fetch: fetchOk, replayCache: new MemoryReplayCache() });
  assert.equal(calls, 1);
  const again = V.cases.find((x) => x.name === "valid_x_header").calls[0];
  await verifyBusymateActor(again.headers, { ...base, jwksUrl: url, fetch: fetchOk, replayCache: new MemoryReplayCache() });
  assert.equal(calls, 1, "cached");
  const unk = V.cases.find((x) => x.name === "unknown_kid").calls[0];
  await assert.rejects(verifyBusymateActor(unk.headers, { ...base, jwksUrl: url, fetch: fetchOk, replayCache: new MemoryReplayCache(), now: V.now + 40 }), (e) => e.reason === "unknown_kid");
  assert.equal(calls, 2, "refetched once on unknown kid after cooldown");
  const down = async () => new Response("no", { status: 503 });
  await assert.rejects(verifyBusymateActor(again.headers, { ...base, jwksUrl: "https://jwks.test/b", fetch: down, replayCache: new MemoryReplayCache() }), (e) => e.reason === "jwks_unavailable");
});
