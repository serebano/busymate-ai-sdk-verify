# @busymate/identity-check

Checks a Busymate AI identity integration from a clean machine. Zero dependencies, Node >= 18.14.

```sh
npx @busymate/identity-check --issuer https://api.acme.com --mint https://api.acme.com/api/bmai/identity \
  --login-url https://acme.com/login --chat-origin https://assistant.acme.com --mcp https://mcp.acme.com
```

`--help` lists every option; `--json` prints machine-readable results. Details: https://github.com/serebano/busymate-ai-sdk-verify#identity-check
