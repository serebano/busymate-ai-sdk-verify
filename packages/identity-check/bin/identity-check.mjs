#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { runChecks, VERSION } from "../src/checks.mjs";

const HELP = `identity-check ${VERSION}: check a Busymate AI identity integration from a clean machine.

Usage: identity-check [options]

Where
  --issuer <url>        your token issuer (JWKS defaults to <issuer>/.well-known/jwks.json)
  --jwks <url>          JWKS URL when it is elsewhere
  --mint <url>          your mint endpoint (POST { nonce, returnTo })
  --login-url <url>     your hosted-page login_url (prompt=none and framing checks)
  --chat-origin <url>   the chat origin, e.g. https://acme.busymate.ai or https://assistant.acme.com
  --mcp <origin>        your connector origin (GET /api/bmai/status)
  --manifest <url|file> JSON with the values above (issuer, jwks_url, mint_url, login_url, chat_origin, mcp_origin, audience, tenant_id)
  --tenant <slug>       [planned] load the manifest from https://<slug>.busymate.ai/.well-known/bmai-integration.json

Optional
  --origin <url>        your page origin, sent as Origin to the mint endpoint (CORS check when the mint is cross-origin)
  --audience <aud>      expected token aud (default busymate-ai)
  --tenant-id <id>      expected tenant_id claim
  --cookie <header>     a TEST session Cookie header, to check the signed-in 201 shape and token
  --bearer <token>      a TEST session bearer token for the same purpose
  --probe-url <url>     a protected MCP/API URL: a forged actor token must get 401
  --actor-token <jwt>   a real actor token (from the Console test) that must NOT get 401 at --probe-url
  --timeout <ms>        per request (default 10000)
  --json                machine-readable output
  -h, --help, -v, --version

Exit code: 0 no failures, 1 at least one failed check, 2 usage error.
Checks send no credentials unless you pass --cookie, --bearer or --actor-token. Use test sessions only.
`;

function parse(argv) {
  const o = {};
  const map = { "--issuer": "issuer", "--jwks": "jwks", "--mint": "mint", "--login-url": "loginUrl", "--chat-origin": "chatOrigin", "--mcp": "mcp", "--manifest": "manifest", "--tenant": "tenant", "--origin": "origin", "--audience": "audience", "--tenant-id": "tenantId", "--cookie": "cookie", "--bearer": "bearer", "--probe-url": "probeUrl", "--actor-token": "actorToken", "--timeout": "timeout" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") o.help = true;
    else if (a === "-v" || a === "--version") o.version = true;
    else if (a === "--json") o.json = true;
    else if (map[a]) { const v = argv[++i]; if (v === undefined) throw new Error(`${a} needs a value`); o[map[a]] = v; }
    else if (a.startsWith("--") && a.includes("=") && map[a.slice(0, a.indexOf("="))]) o[map[a.slice(0, a.indexOf("="))]] = a.slice(a.indexOf("=") + 1);
    else throw new Error(`unknown option ${a}`);
  }
  if (o.timeout) o.timeout = Number(o.timeout);
  for (const k of ["issuer", "jwks", "mint", "loginUrl", "chatOrigin", "mcp", "origin", "probeUrl"]) if (o[k] && !/^https?:\/\//.test(o[k])) throw new Error(`--${k.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase())} must be an http(s) URL`);
  for (const k of ["chatOrigin", "mcp", "origin"]) if (o[k]) o[k] = new URL(o[k]).origin;
  return o;
}

async function loadManifest(o) {
  let doc;
  if (o.manifest) {
    doc = /^https?:\/\//.test(o.manifest) ? await (await fetch(o.manifest)).json() : JSON.parse(await readFile(o.manifest, "utf8"));
  } else if (o.tenant) {
    const r = await fetch(`https://${o.tenant}.busymate.ai/.well-known/bmai-integration.json`).catch(() => null);
    if (!r || !r.ok || !(r.headers.get("content-type") || "").includes("json")) throw new Error(`no integration manifest for tenant "${o.tenant}" yet (planned). Pass --issuer, --mint, --login-url, --chat-origin and --mcp, or --manifest.`);
    doc = await r.json();
  } else return;
  const pick = (...ks) => ks.map((k) => doc[k] ?? doc.integration?.[k]).find((v) => v);
  const set = (k, v) => { if (v && !o[k]) o[k] = v; };
  set("issuer", pick("issuer")); set("jwks", pick("jwks_url", "jwksUrl")); set("mint", pick("mint_url", "mintUrl"));
  set("loginUrl", pick("login_url", "loginUrl")); set("chatOrigin", pick("chat_origin", "chatOrigin")); set("mcp", pick("mcp_origin", "mcpOrigin", "connector_origin"));
  set("audience", pick("audience")); set("tenantId", pick("tenant_id", "tenantId"));
}

const ICON = { pass: "PASS", warn: "WARN", fail: "FAIL", skip: "SKIP" };
let o;
try {
  o = parse(process.argv.slice(2));
  if (o.version) { console.log(VERSION); process.exit(0); }
  if (o.help || process.argv.length <= 2) { console.log(HELP); process.exit(o.help ? 0 : 2); }
  await loadManifest(o);
} catch (e) { console.error(`identity-check: ${e.message}\nRun identity-check --help`); process.exit(2); }

const report = await runChecks(o);
if (o.json) console.log(JSON.stringify(report, null, 2));
else {
  for (const c of report.checks) console.log(`${ICON[c.status]}  ${c.id.padEnd(18)} ${c.detail}`);
  const n = report.counts;
  console.log(`\n${report.ok ? "OK" : "FAILED"}: ${n.pass} passed, ${n.warn} warnings, ${n.fail} failed, ${n.skip} skipped`);
}
process.exit(report.ok ? 0 : 1);
