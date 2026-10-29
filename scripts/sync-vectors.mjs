// Vendors / checks the identity-contract test vectors.
//   node scripts/sync-vectors.mjs --from <file|url>   copy the contract's vectors into vectors/actor-v3.json and write vectors/contract.lock.json
//   node scripts/sync-vectors.mjs --check              fail when vectors/actor-v3.json was edited by hand or diverges from the contract
// --check compares with the contract when BMAI_CONTRACT_VECTORS (file or URL) is set. While vectors/contract.lock.json
// does not exist, the local vector set (source "local", made by scripts/gen-vectors.mjs) is in use.
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const active = join(root, "vectors", "actor-v3.json");
const lockFile = join(root, "vectors", "contract.lock.json");
const sha = (s) => createHash("sha256").update(s).digest("hex");
const canon = (s) => JSON.stringify(JSON.parse(s));
const load = async (src) => (/^https?:\/\//.test(src) ? (await fetch(src)).text() : readFile(src, "utf8"));
const arg = (n) => { const i = process.argv.indexOf(n); return i > -1 ? process.argv[i + 1] : undefined; };

function validate(doc) {
  for (const k of ["now", "config", "jwks", "cases"]) if (!(k in doc)) throw new Error(`vectors lack "${k}"`);
}

if (arg("--from")) {
  const text = await load(arg("--from"));
  validate(JSON.parse(text));
  const pretty = JSON.stringify(JSON.parse(text), null, 2) + "\n";
  await writeFile(active, pretty);
  await writeFile(join(root, "vectors", "jwks.json"), JSON.stringify(JSON.parse(text).jwks, null, 2) + "\n");
  await writeFile(lockFile, JSON.stringify({ source: arg("--from"), sha256: sha(canon(pretty)), syncedAt: new Date().toISOString() }, null, 2) + "\n");
  console.log(`vendored contract vectors from ${arg("--from")}`);
} else if (process.argv.includes("--check")) {
  const cur = await readFile(active, "utf8");
  validate(JSON.parse(cur));
  if (existsSync(lockFile)) {
    const lock = JSON.parse(await readFile(lockFile, "utf8"));
    if (lock.sha256 !== sha(canon(cur))) { console.error("vectors/actor-v3.json differs from vectors/contract.lock.json: it was edited by hand. Re-run sync-vectors --from."); process.exit(1); }
  }
  const src = process.env.BMAI_CONTRACT_VECTORS;
  if (!src) console.log(existsSync(lockFile) ? "vectors match the lock; set BMAI_CONTRACT_VECTORS to compare with the contract source" : "local vector set in use (no contract vendored yet)");
  else {
    const want = canon(await load(src));
    if (want !== canon(cur)) { console.error(`vectors/actor-v3.json diverges from the contract vectors at ${src}. Run: node scripts/sync-vectors.mjs --from ${src}`); process.exit(1); }
    console.log("vectors match the contract source");
  }
} else { console.error("usage: sync-vectors.mjs --from <file|url> | --check"); process.exit(2); }
