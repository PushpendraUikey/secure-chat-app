#!/bin/bash
set -euo pipefail

# Sets up a self-signed Certificate Authority: a private key and a
# self-signed root certificate. This CA is what clients will trust
# — its public cert (ca.crt) needs to end up on every Client VM;
# its private key (ca.key) must NEVER get leaked to anyone.

CA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CA_DIR"

CA_KEY="ca.key"
CA_CERT="ca.crt"
CA_DAYS=1   # Validity period of the CA root certificate
CA_SUBJECT="/C=IN/O=CS6008 SecureChat/CN=SecureChat Root CA"

echo "[*] Generating CA private key (RSA 4096)..."
openssl genrsa -out "$CA_KEY" 4096
chmod 600 "$CA_KEY"   # private key: owner read/write only

echo "[*] Generating self-signed CA root certificate..."
openssl req -x509 -new -nodes \
    -key "$CA_KEY" \
    -sha256 \
    -days "$CA_DAYS" \
    -subj "$CA_SUBJECT" \
    -out "$CA_CERT"

echo "[*] CA setup complete."
echo "    Private key (KEEP ON SERVER VM ONLY): $CA_DIR/$CA_KEY"
echo "    Root certificate (COPY TO ALL CLIENT VMs): $CA_DIR/$CA_CERT"
echo ""
echo "[*] Verifying the generated certificate:"
openssl x509 -in "$CA_CERT" -noout -subject -dates