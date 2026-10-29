# SDK repository ownership

This repository owns the Busymate AI customer-side verifier for the connector actor token (`bmai.actor/3`):
`@busymate/ai-verify` (Node and Deno), the Python, PHP and Go snippets, the shared test vectors and the
`@busymate/identity-check` CLI. Source, tests, CI and versioned GitHub releases live here only.

Land through protected PRs with `sdk-check` required; the skeleton commit was the only direct push to `main`. No admin bypass.
Never modify an existing release or tag. New bytes need a new version.
The identity contract (`bmai-identity`, package `packages/identity-contract` in the private `busymate-ai-src`) is the source of truth for the
token format and the vectors. `vectors/actor-v3.json` is vendored from it (`scripts/sync-vectors.mjs`); CI fails when they diverge.
busymate.ai may mirror versioned artifacts at `/sdk/verify/`; hashes must match this repository's release.
No production keys. The test key pair under `vectors/` signs test tokens only.
The verifier has one runtime dependency, `jose`. The CLI has none.
