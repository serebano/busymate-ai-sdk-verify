# @busymate/ai-verify

Verify the Busymate AI connector actor token (`bmai.actor/3`, ES256 + JWKS) in your MCP server or API. Node >= 18 and Deno. One dependency: `jose`.

```ts
import { verifyBusymateActor, requireConfirmed } from "@busymate/ai-verify";
const actor = await verifyBusymateActor(req, { audience: "https://mcp.acme.com", tenantId: "acme", connectorId: "conn_1", tool: toolName });
// => { sub, idp, confirmed, tool, jti, supportSessionId }; throws BusymateActorError (e.reason) on any failure
```

Full guide, reason codes and the Python, PHP and Go versions: https://github.com/serebano/busymate-ai-sdk-verify#readme
