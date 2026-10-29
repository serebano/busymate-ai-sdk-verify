// A tiny demo tenant (issuer JWKS, mint endpoint, login page, MCP status) for trying identity-check locally and in CI.
//   node demo/demo-tenant.mjs [port] [--broken]     then:  npx @busymate/identity-check --issuer http://127.0.0.1:PORT ...
// TEST key generated at start. Never use in production.
import http from "node:http";
import { generateKeyPairSync, createSign, randomUUID } from "node:crypto";

export function startDemoTenant({ port = 0, broken = false } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "demo-1", alg: "ES256", use: "sig" };
  const SESSION = "demo-session";
  const sign = (claims) => {
    const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const input = `${enc({ alg: "ES256", kid: "demo-1", typ: "JWT" })}.${enc(claims)}`;
    const sig = createSign("sha256").update(input).sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
    return `${input}.${sig.toString("base64url")}`;
  };
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    const origin = `http://${req.headers.host}`;
    const send = (code, body, headers = {}) => { res.writeHead(code, { "content-type": "application/json", ...headers }); res.end(typeof body === "string" ? body : JSON.stringify(body)); };
    if (u.pathname === "/.well-known/jwks.json") return send(200, { keys: [jwk] });
    if (u.pathname === "/api/bmai/identity" && req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      return req.on("end", () => {
        if (!(req.headers.cookie || "").includes(`sid=${SESSION}`)) return send(401, { error: "signed_out" });
        const { nonce } = JSON.parse(b || "{}"); const now = Math.floor(Date.now() / 1000);
        const token = sign({ iss: origin, aud: "busymate-ai", sub: "demo-user-1", tenant_id: "demo", nonce, jti: randomUUID(), iat: now, exp: now + 120 });
        send(201, { token, nonce, expiresIn: 120 }, { "cache-control": broken ? "max-age=60" : "no-store" });
      });
    }
    if (u.pathname === "/login") {
      const rt = u.searchParams.get("return_to") || "";
      if (u.searchParams.get("bmai_prompt") === "none") { res.writeHead(302, { location: `${rt}#error=login_required` }); return res.end(); }
      const h = { "content-type": "text/html", "set-cookie": broken ? "csrf=1; Path=/; HttpOnly" : "csrf=1; Path=/; Secure; SameSite=None" };
      if (broken) h["x-frame-options"] = "DENY"; else h["content-security-policy"] = `frame-ancestors ${new URL(rt).origin}`;
      res.writeHead(200, h); return res.end("<h1>Sign in</h1>");
    }
    if (u.pathname === "/api/bmai/status") return send(200, { actorVerifier: true, actor: 3 });
    if (u.pathname === "/mcp") return send((req.headers["x-bmai-actor"] ?? "") === "" ? 401 : broken ? 200 : 401, { error: "invalid_token" });
    send(404, { error: "not_found" });
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}`, session: `sid=${SESSION}`, close: () => server.close() })));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const t = await startDemoTenant({ port: Number(process.argv[2]) || 8787, broken: process.argv.includes("--broken") });
  console.log(`demo tenant on ${t.url} (test cookie: ${t.session})`);
}
