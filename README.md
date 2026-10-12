# 🔑 Leak Guard

A GitHub Action that **catches leaked secrets in a pull request** — API keys, private keys, committed `.env` files — before they merge into your history.

Part of [DevGuard Tools](https://ivosetyadi.github.io). Zero-dependency, runs on Node 20, no bundling.

## What it catches

| Rule | Severity |
|------|----------|
| AWS access key / secret key | error |
| GitHub token (`ghp_`, `gho_`, …) | error |
| Google API key (`AIza…`) | error |
| Stripe secret key (`sk_live_…`) | error |
| Slack token (`xox…`) | error |
| OpenAI / LLM key (`sk-…`) | error |
| Private key material (`BEGIN … PRIVATE KEY`) | error |
| Committed `.env`, `*.pem`, `id_rsa`, `secrets.*` | error |
| Hardcoded JWT | warn |
| Generic `secret = "…"` assignment | warn |

**Secrets are always redacted** in logs and PR comments (`AKIA…Xy (20 chars)`) — Leak Guard never echoes the full value.

## Usage

```yaml
# .github/workflows/leak-guard.yml
name: Leak Guard
on: pull_request
permissions:
  contents: read
  pull-requests: write   # to post the findings comment
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: ivosetyadi/leak-guard@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          fail-on: error
```

## Suppressing false positives

- Inline: add `leak-guard:allow` as a comment on the flagged line.
- Config `.leakguard.yml`:

```yaml
fail-on: error
ignore:
  - test/fixtures/
disable:
  - jwt
allow:
  - EXAMPLE_DUMMY_KEY_000000000000000000
```

## ⚠️ If a real secret is flagged

Rotate it **now** — it is already in git history, and redaction here does not remove it from past commits. Then purge history (`git filter-repo`) if needed.

## License

MIT © Ivo Setyadi
