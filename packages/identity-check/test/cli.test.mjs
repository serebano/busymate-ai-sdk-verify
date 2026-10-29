import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { startDemoTenant } from "../../../demo/demo-tenant.mjs";
import { runChecks, frameAncestors } from "../src/checks.mjs";

const run = promisify(execFile);
const CLI = new URL("../bin/identity-check.mjs", import.meta.url).pathname;
const args = (t) => ["--issuer", t.url, "--mint", `${t.url}/api/bmai/identity`, "--login-url", `${t.url}/login`, "--chat-origin", "https://chat.example.test", "--mcp", t.url, "--probe-url", `${t.url}/mcp`, "--tenant-id", "demo", "--cookie", t.session];
const by = (r, id) => r.checks.find((c) => c.id === id);

test("a correct tenant passes every check", async () => {
  const t = await startDemoTenant();
  try {
    const r = await runChecks({ issuer: t.url, mint: `${t.url}/api/bmai/identity`, loginUrl: `${t.url}/login`, chatOrigin: "https://chat.example.test", mcp: t.url, probeUrl: `${t.url}/mcp`, tenantId: "demo", cookie: t.session });
    assert.deepEqual(r.checks.filter((c) => c.status !== "pass").map((c) => `${c.id}:${c.status}:${c.detail}`), []);
    assert.equal(r.ok, true);
  } finally { t.close(); }
});

test("a broken tenant fails framing, cache headers and forged-token handling; warns on cookies", async () => {
  const t = await startDemoTenant({ broken: true });
  try {
    const r = await runChecks({ issuer: t.url, mint: `${t.url}/api/bmai/identity`, loginUrl: `${t.url}/login`, chatOrigin: "https://chat.example.test", mcp: t.url, probeUrl: `${t.url}/mcp`, cookie: t.session });
    assert.equal(r.ok, false);
    assert.equal(by(r, "framing").status, "fail");
    assert.equal(by(r, "mint_signed_in").status, "fail");
    assert.equal(by(r, "cookies").status, "warn");
    assert.equal(by(r, "actor_rejects_bad").status, "fail");
    assert.equal(by(r, "mint_signed_out").status, "pass");
    assert.equal(by(r, "prompt_none").status, "pass");
  } finally { t.close(); }
});

test("CLI: --help, --version, bad option, --json, exit codes", async () => {
  assert.match((await run(process.execPath, [CLI, "--help"])).stdout, /Usage: identity-check/);
  assert.match((await run(process.execPath, [CLI, "--version"])).stdout, /^\d+\.\d+\.\d+/);
  await assert.rejects(run(process.execPath, [CLI, "--nope"]), (e) => e.code === 2);
  const t = await startDemoTenant();
  try {
    const out = await run(process.execPath, [CLI, ...args(t), "--json"]);
    const j = JSON.parse(out.stdout);
    assert.equal(j.ok, true);
    assert.ok(j.checks.length >= 8);
  } finally { t.close(); }
  const t2 = await startDemoTenant({ broken: true });
  try { await assert.rejects(run(process.execPath, [CLI, ...args(t2)]), (e) => e.code === 1 && /FAIL\s+framing/.test(e.stdout)); } finally { t2.close(); }
});

test("frameAncestors parses CSP", () => {
  assert.deepEqual(frameAncestors("default-src 'self'; frame-ancestors https://a.test https://b.test"), ["https://a.test", "https://b.test"]);
  assert.equal(frameAncestors("default-src 'self'"), null);
});
