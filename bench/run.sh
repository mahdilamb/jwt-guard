#!/usr/bin/env bash
# Benchmark: jwt-guard vs Envoy proxy (JWT validation)
#
# Prerequisites:
#   - docker compose
#   - openssl
#   - node (for JWT signing)
#   - hey (HTTP load generator):  go install github.com/rakyll/hey@latest
#     or: brew install hey
#
# Usage:
#   ./bench/run.sh              # default: 10s duration, 50 concurrency
#   ./bench/run.sh 30s 100      # custom:  30s duration, 100 concurrency

set -euo pipefail
cd "$(dirname "$0")"

DURATION=${1:-10s}
CONCURRENCY=${2:-50}
WARMUP_REQUESTS=500

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

RESULTS_FILE="results.md"

header() { printf "\n${BOLD}${CYAN}=== %s ===${RESET}\n\n" "$1"; }
info()   { printf "${GREEN}%s${RESET}\n" "$1"; }
err()    { printf "${RED}%s${RESET}\n" "$1" >&2; }

# ── Preflight checks ────────────────────────────────────────────────────────

for cmd in docker openssl node hey; do
    if ! command -v "$cmd" &>/dev/null; then
        err "Required command not found: $cmd"
        case "$cmd" in
            hey) err "Install with: go install github.com/rakyll/hey@latest  OR  brew install hey" ;;
        esac
        exit 1
    fi
done

# ── Setup keys ───────────────────────────────────────────────────────────────

header "Generating keys"
bash setup.sh

# ── Generate JWT ─────────────────────────────────────────────────────────────

header "Generating test JWT"

TOKEN=$(node -e "
const crypto = require('crypto');
const fs = require('fs');

const privateKey = fs.readFileSync('jwks/private.pem', 'utf8');

const header = { alg: 'RS256', typ: 'JWT', kid: 'bench-key-1' };
const now = Math.floor(Date.now() / 1000);
const payload = {
    iss: 'https://bench.example.com',
    sub: 'bench-user',
    iat: now,
    exp: now + 3600,
};

function b64url(obj) {
    return Buffer.from(JSON.stringify(obj))
        .toString('base64url');
}

const signingInput = b64url(header) + '.' + b64url(payload);
const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_v1_5,
});

console.log(signingInput + '.' + signature.toString('base64url'));
")

info "JWT generated (${#TOKEN} chars)"

# ── Start services ───────────────────────────────────────────────────────────

header "Starting services"

docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d --build --wait

# Quick health checks
for port in 3001 3002; do
    if ! curl -sf -o /dev/null -w '' "http://localhost:${port}/" -H "Authorization: Bearer ${TOKEN}" 2>/dev/null; then
        curl -sf -o /dev/null "http://localhost:${port}/" 2>/dev/null || true
    fi
done

info "Services ready"
info "  jwt-guard  → http://localhost:3001"
info "  envoy      → http://localhost:3002"

# ── Results file setup ──────────────────────────────────────────────────────

cat > "${RESULTS_FILE}" <<EOF
# Benchmark Results

**Date:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')
**Duration:** ${DURATION} | **Concurrency:** ${CONCURRENCY}
**Platform:** $(uname -s) $(uname -m)

EOF

# ── Benchmark helper ─────────────────────────────────────────────────────────

# Extract a metric from hey output; returns empty string on no match
extract() {
    echo "$1" | grep "$2" | head -1 | awk "{print \$$3}" || true
}

run_bench() {
    local name="$1"
    local url="$2"
    local token_header="$3"

    header "Benchmarking: ${name}"
    info "  ${DURATION} duration, ${CONCURRENCY} concurrency"
    echo ""

    local output
    output=$(hey -z "${DURATION}" \
        -c "${CONCURRENCY}" \
        -H "Authorization: ${token_header}" \
        -H "Accept: application/json" \
        "${url}" 2>&1)

    echo "${output}"

    # Extract key metrics (|| true prevents set -e from killing on no match)
    local rps avg p50 p95 p99 status_line
    rps=$(extract "${output}" 'Requests/sec:' 2)
    avg=$(extract "${output}" 'Average:' 2)
    p50=$(extract "${output}" '50%%' 3)
    p95=$(extract "${output}" '95%%' 3)
    p99=$(extract "${output}" '99%%' 3)
    status_line=$(echo "${output}" | grep '\[' | grep 'responses' | head -1 | sed 's/^[[:space:]]*//' || true)

    # Append to results file
    cat >> "${RESULTS_FILE}" <<EOF
## ${name}

| Metric | Value |
|---|---|
| Requests/sec | ${rps} |
| Avg latency | ${avg} |
| p50 latency | ${p50} |
| p95 latency | ${p95} |
| p99 latency | ${p99} |
| Status | ${status_line} |

<details>
<summary>Full output</summary>

\`\`\`
${output}
\`\`\`

</details>

EOF
}

# ── Warmup ───────────────────────────────────────────────────────────────────

header "Warming up (${WARMUP_REQUESTS} requests each)"
hey -n "${WARMUP_REQUESTS}" -c "${CONCURRENCY}" -H "Authorization: Bearer ${TOKEN}" http://localhost:3001/bench >/dev/null 2>&1
hey -n "${WARMUP_REQUESTS}" -c "${CONCURRENCY}" -H "Authorization: Bearer ${TOKEN}" http://localhost:3002/bench >/dev/null 2>&1
info "Warmup complete"

# ── Run benchmarks ───────────────────────────────────────────────────────────

run_bench "jwt-guard (valid token)"   "http://localhost:3001/bench" "Bearer ${TOKEN}"
run_bench "Envoy (valid token)"       "http://localhost:3002/bench" "Bearer ${TOKEN}"
run_bench "jwt-guard (invalid token)" "http://localhost:3001/bench" "Bearer invalid.token.here"
run_bench "Envoy (invalid token)"     "http://localhost:3002/bench" "Bearer invalid.token.here"

# ── Summary table ────────────────────────────────────────────────────────────

# Helper to pull a metric value from a named section in the results file
pull() {
    local section="$1" metric="$2"
    # Grab the section block, then find the metric line, then extract the value column
    grep -F -A 20 "## ${section}" "${RESULTS_FILE}" | grep -F "| ${metric} |" | head -1 | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $3); print $3}' || true
}

jg_valid_rps=$(pull "jwt-guard (valid token)" "Requests/sec")
en_valid_rps=$(pull "Envoy (valid token)" "Requests/sec")
jg_invalid_rps=$(pull "jwt-guard (invalid token)" "Requests/sec")
en_invalid_rps=$(pull "Envoy (invalid token)" "Requests/sec")

jg_valid_p50=$(pull "jwt-guard (valid token)" "p50 latency")
en_valid_p50=$(pull "Envoy (valid token)" "p50 latency")
jg_invalid_p50=$(pull "jwt-guard (invalid token)" "p50 latency")
en_invalid_p50=$(pull "Envoy (invalid token)" "p50 latency")

cat >> "${RESULTS_FILE}" <<EOF
## Summary

| Scenario | jwt-guard | Envoy |
|---|---|---|
| Valid token req/s | ${jg_valid_rps} | ${en_valid_rps} |
| Valid token p50 | ${jg_valid_p50} | ${en_valid_p50} |
| Invalid token req/s | ${jg_invalid_rps} | ${en_invalid_rps} |
| Invalid token p50 | ${jg_invalid_p50} | ${en_invalid_p50} |
EOF

# ── Cleanup ──────────────────────────────────────────────────────────────────

header "Cleanup"
docker compose down --remove-orphans
info "Results saved to bench/${RESULTS_FILE}"
info "Done"
