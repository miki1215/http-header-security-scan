# http-header-security-scan

A tiny, dependency-free **HTTP information-disclosure scanner**. Point it at a
URL and it flags the classic web-hardening leaks that show up in pentest and
audit findings:

- `Server:` version banners (e.g. `nginx/1.25.3`)
- `X-Powered-By:` framework fingerprints (e.g. `Express`)
- version strings leaked in error-page **bodies**
- internal filesystem paths leaked in stack traces (`/usr/...`, `/app/dist/...`)

It's built as a **before/after baseline**: run it, apply the hardening, run it
again, and use the non-zero exit code to prove in CI that the leak is closed.

## Usage

```bash
# Default probe set (/, /health, /status, a random 404)
./http-header-security-scan.sh https://target.example.com

# Add your own paths to probe
./http-header-security-scan.sh https://target.example.com /api/devices /metrics
```

Exit code is `0` when clean, non-zero when any finding is present — drop it into
a pipeline as a lightweight security gate.

## Example

```
━━ https://target.example.com/ ━━
[LEAK] Server: nginx/1.25.3
[ok] no X-Powered-By header
[ok] no version banner in body
[ok] no internal file paths
==================================================
FAIL — 1 finding(s). Remediate:
  • hide Server banner (nginx: server_tokens off;)
```

## Remediation cheatsheet

| Leak | Fix |
|------|-----|
| `Server` banner | nginx: `server_tokens off;` (+ `more_clear_headers Server;` with headers-more module) |
| `X-Powered-By` | Express: `app.disable('x-powered-by')`; or strip at the proxy |
| version in error body | serve custom, static error pages |
| internal paths | disable verbose/debug error output in production |

## Requirements

- `curl`

## License

[MIT](./LICENSE)
