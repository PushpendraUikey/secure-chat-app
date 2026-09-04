#!/bin/bash
set -euo pipefail

# Generates Mallory's OWN keypair and a SELF-signed certificate —
# deliberately NOT signed by the real CA, since Mallory has no access
# to ca.key.
#
# The CN is intentionally set to match the real server's CN, to show
# that even IDENTITY SPOOFING alone isn't enough — the signature check
# is what actually stops this, not the CN.

if [ $# -ne 1 ]; then
    echo "Usage: $0 <spoofed_server_cn>"
    echo "  e.g. $0 192.168.100.5   (same CN as the real server's cert)"
    exit 1
fi

SPOOFED_CN="$1"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[*] Generating Mallory's own private key..."
openssl genrsa -out fake.key 2048
chmod 600 fake.key

echo "[*] Self-signing a certificate claiming CN=$SPOOFED_CN (NOT CA-signed)..."
openssl req -x509 -new -nodes \
    -key fake.key \
    -sha256 -days 365 \
    -subj "/C=XX/O=Mallory Attacker/CN=$SPOOFED_CN" \
    -out fake.crt

echo "[*] Done. fake.crt/fake.key are Mallory's own, unrelated to the real CA."
echo ""
echo "[*] Confirming this cert is NOT trusted by the real CA (expected to FAIL):"
openssl verify -CAfile ../ca/ca.crt fake.crt || echo "    (failure above is expected and correct)"