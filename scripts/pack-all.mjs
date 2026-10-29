// Packs both npm packages and the snippets bundle into ./release with SHA256SUMS.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const out = join(process.cwd(), "release");
rmSync(out, { recursive: true, force: true });
mkdirSync(out);
const version = JSON.parse(readFileSync("packages/ai-verify/package.json", "utf8")).version;
for (const ws of ["@busymate/ai-verify", "@busymate/identity-check"]) {
  execFileSync("npm", ["pack", "-w", ws, "--pack-destination", out], { stdio: "inherit" });
}
execFileSync("tar", ["--exclude=__pycache__", "--exclude=test-keys.private.json", "-czf", join(out, `busymate-ai-verify-snippets-${version}.tgz`), "snippets", "vectors"], { stdio: "inherit" });
const sums = readdirSync(out).filter((f) => f !== "SHA256SUMS").sort().map((f) => `${createHash("sha256").update(readFileSync(join(out, f))).digest("hex")}  ${f}`);
writeFileSync(join(out, "SHA256SUMS"), sums.join("\n") + "\n");
console.log(sums.join("\n"));
