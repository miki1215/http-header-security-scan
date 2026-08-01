#!/usr/bin/env bash
#
# http-header-security-scan.sh
# Probe a web endpoint for information-disclosure issues: leaked server/version
# banners, framework fingerprints, and internal file paths in error pages.
# Useful as a lightweight, repeatable "hardening baseline" you can run before
# and after a fix to prove the leak is closed.
#
# Usage:
#   ./http-header-security-scan.sh https://target.example.com
#   ./http-header-security-scan.sh https://target.example.com /health /status /api/foo
#
# The first argument is the base URL. Any further arguments are extra paths to
# probe (in addition to a sensible default set).
#
# Requires: curl

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

BASE_URL="${1:-}"
if [[ -z "$BASE_URL" ]]; then
  echo "usage: $0 <base-url> [extra-path ...]" >&2
  echo "example: $0 https://target.example.com /health /status" >&2
  exit 1
fi
shift || true

command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }

# Default probe paths + any extras passed on the CLI
PATHS=( "/" "/health" "/status" "/does-not-exist-$(date +%s)" "$@" )

echo "=================================================="
echo "HTTP header / info-disclosure baseline"
echo "Target: ${BASE_URL}"
echo "=================================================="

findings=0

check_endpoint() {
  local url="$1"
  echo -e "\n${YELLOW}━━ ${url} ━━${NC}"

  local headers body
  headers=$(curl -s -I --max-time 10 "$url" 2>/dev/null || true)
  body=$(curl -s --max-time 10 "$url" 2>/dev/null || true)

  # 1) Server / X-Powered-By banners
  local server_hdr powered_hdr
  server_hdr=$(echo "$headers" | grep -i "^server:" || true)
  powered_hdr=$(echo "$headers" | grep -i "^x-powered-by:" || true)

  if [[ -n "$server_hdr" ]]; then
    echo -e "${RED}[LEAK] ${server_hdr}${NC}"; findings=$((findings+1))
  else
    echo -e "${GREEN}[ok] no Server header${NC}"
  fi
  if [[ -n "$powered_hdr" ]]; then
    echo -e "${RED}[LEAK] ${powered_hdr}${NC}"; findings=$((findings+1))
  else
    echo -e "${GREEN}[ok] no X-Powered-By header${NC}"
  fi

  # 2) Version strings in the body (nginx/apache/express versions in error pages)
  local ver
  ver=$(echo "$body" | grep -iE "nginx/[0-9]|apache/[0-9]|express" | head -3 || true)
  if [[ -n "$ver" ]]; then
    echo -e "${RED}[LEAK] version banner in body:${NC}"; echo "$ver"; findings=$((findings+1))
  else
    echo -e "${GREEN}[ok] no version banner in body${NC}"
  fi

  # 3) Internal filesystem paths leaked in stack traces / error pages
  local paths
  paths=$(echo "$body" | grep -oE "(/usr/|/var/|/app/|/dist/|/home/)[A-Za-z0-9._/-]+" | head -3 || true)
  if [[ -n "$paths" ]]; then
    echo -e "${RED}[LEAK] internal file paths:${NC}"; echo "$paths"; findings=$((findings+1))
  else
    echo -e "${GREEN}[ok] no internal file paths${NC}"
  fi
}

for p in "${PATHS[@]}"; do
  # Join base + path, avoiding a double slash
  check_endpoint "${BASE_URL%/}${p}"
done

echo -e "\n=================================================="
if [[ $findings -eq 0 ]]; then
  echo -e "${GREEN}PASS — no information-disclosure findings${NC}"
  exit 0
else
  echo -e "${RED}FAIL — ${findings} finding(s). Remediate:${NC}"
  echo "  • hide Server banner (nginx: server_tokens off;)"
  echo "  • drop X-Powered-By (app framework config)"
  echo "  • return generic error pages (no version / stack traces / paths)"
  exit 1
fi
