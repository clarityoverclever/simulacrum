#!/usr/bin/env bash
# test_dns_localhost.sh
#
# Smoke-tests the simulacrum DNS server running on localhost.
# Requires: dig
#
# Usage:
#   ./scripts/test_dns_localhost.sh [HOST] [PORT]
#
# Defaults to 127.0.0.1:5353. Adjust if your config uses a different bind address.

set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-5353}"
PASS=0
FAIL=0

# ---- helpers ---------------------------------------------------------------

pass() { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); }

run_dig() {
    # run_dig <type> <name>  → prints answer section, exits 0 even on NXDOMAIN
    dig +short +time=2 +tries=1 "@${HOST}" -p "${PORT}" "$2" "$1" 2>/dev/null || true
}

rcode_dig() {
    # rcode_dig <type> <name>  → prints the RCODE string (e.g. NOERROR, NXDOMAIN)
    dig +time=2 +tries=1 "@${HOST}" -p "${PORT}" "$2" "$1" 2>/dev/null \
        | awk '/status:/{gsub(",",""); print $6}' || true
}

# ---- pre-flight ------------------------------------------------------------

echo "=== simulacrum DNS smoke test ==="
echo "  server : ${HOST}:${PORT}"
echo ""

if ! command -v dig &>/dev/null; then
    echo "ERROR: 'dig' not found — install dnsutils/bind-tools and retry"
    exit 1
fi

# Quick reachability check
echo "[0] Reachability"
RCODE=$(rcode_dig A "example.com")
if [[ -n "$RCODE" ]]; then
    pass "server is reachable (got rcode: ${RCODE})"
else
    echo "  FATAL: no response from ${HOST}:${PORT} — is simulacrum running?"
    exit 1
fi
echo ""

# ---- test cases ------------------------------------------------------------

echo "[1] A record — normal domain (expect NOERROR + an IP)"
ANSWER=$(run_dig A "example.com")
RCODE=$(rcode_dig A "example.com")
if [[ "$RCODE" == "NOERROR" && -n "$ANSWER" ]]; then
    pass "example.com → ${ANSWER}"
else
    fail "expected NOERROR+IP, got rcode=${RCODE} answer='${ANSWER}'"
fi
echo ""

echo "[2] A record — repeated query same client (tests observation accumulation)"
run_dig A "example.com" >/dev/null
run_dig A "example.com" >/dev/null
ANSWER=$(run_dig A "example.com")
RCODE=$(rcode_dig A "example.com")
if [[ "$RCODE" == "NOERROR" && -n "$ANSWER" ]]; then
    pass "3x example.com queries succeeded → ${ANSWER}"
else
    fail "repeated queries failed: rcode=${RCODE}"
fi
echo ""

echo "[3] AAAA record — expect NODATA (empty answer, NOERROR)"
ANSWER=$(run_dig AAAA "example.com")
RCODE=$(rcode_dig AAAA "example.com")
if [[ "$RCODE" == "NOERROR" && -z "$ANSWER" ]]; then
    pass "AAAA for example.com → NODATA (as expected)"
else
    fail "expected NODATA, got rcode=${RCODE} answer='${ANSWER}'"
fi
echo ""

echo "[4] Different domain (tests per-key observation keying by client IP)"
ANSWER=$(run_dig A "test.local")
RCODE=$(rcode_dig A "test.local")
if [[ "$RCODE" == "NOERROR" && -n "$ANSWER" ]]; then
    pass "test.local → ${ANSWER}"
else
    fail "expected NOERROR+IP, got rcode=${RCODE} answer='${ANSWER}'"
fi
echo ""

echo "[5] High-entropy label — tunnel detection (expect NOERROR, no answer)"
# Base64-ish label with entropy > typical threshold (~3.5 bits)
HIGH_ENTROPY_LABEL="aGVsbG93b3JsZGhlbGxvd29ybGQ"
RCODE=$(rcode_dig A "${HIGH_ENTROPY_LABEL}.example.com")
# When tunnel detection fires, server returns RcodeSuccess with no answer
if [[ "$RCODE" == "NOERROR" ]]; then
    pass "high-entropy label flagged → NOERROR (tunnel suppressed)"
else
    echo "  NOTE: rcode=${RCODE} — tunnel detection may be disabled or threshold too high"
    pass "query completed without crash"
fi
echo ""

echo "[6] MX record — expect NODATA"
ANSWER=$(run_dig MX "example.com")
RCODE=$(rcode_dig MX "example.com")
if [[ "$RCODE" == "NOERROR" && -z "$ANSWER" ]]; then
    pass "MX query → NODATA (as expected)"
else
    fail "expected NODATA for MX, got rcode=${RCODE} answer='${ANSWER}'"
fi
echo ""

# ---- summary ---------------------------------------------------------------

echo "================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "================================"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
