// Deno run of the same vectors against the built package: `npm run test:deno -w @busymate/ai-verify`
import { deepStrictEqual as assertEquals } from "node:assert/strict";
import { verifyBusymateActor, MemoryReplayCache, BusymateActorError } from "../dist/index.js";

const V = JSON.parse(Deno.readTextFileSync(new URL("../../../vectors/actor-v3.json", import.meta.url)));

for (const c of V.cases) {
  Deno.test(`vector ${c.name}`, async () => {
    const cache = new MemoryReplayCache();
    for (const call of c.calls) {
      const cfg = { ...V.config, ...c.options, ...(call.options ?? {}) };
      const o: Record<string, unknown> = { audience: cfg.audience, tenantId: cfg.tenant_id, connectorId: cfg.connector_id, jwks: V.jwks, now: V.now, replayCache: cache };
      if (cfg.idp) o.idp = cfg.idp;
      if (cfg.tool) o.tool = cfg.tool;
      if (call.expect.ok) assertEquals(await verifyBusymateActor(call.headers, o as never), call.expect.actor);
      else {
        let err: unknown;
        try { await verifyBusymateActor(call.headers, o as never); } catch (e) { err = e; }
        assertEquals(err instanceof BusymateActorError && err.reason, call.expect.reason);
      }
    }
  });
}
