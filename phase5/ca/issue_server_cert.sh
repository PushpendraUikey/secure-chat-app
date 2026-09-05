#!/bin/bash
set -euo pipefail

# Generates a keypair for the chat server, creates a CSR, and has our
# CA (from setup_ca.sh) sign it into a server certificate.
#
# Usage: ./issue_server_cert.sh <server_cn>
#
# <server_cn> MUST be the exact value clients will validate against —
# per the assignment spec, this is typically the Server VM's IP address
# on your VirtualBox network (since these VMs have no real DNS), e.g.:
#   ./issue_server_cert.sh 192.168.100.5
# Both the server's own config and every client's expected_cn must use
# this SAME value, or certificate validation (§4.1c) will fail.

if [ $# -ne 1 ]; then
    echo "Usage: $0 <server_cn>"
    echo "  e.g. $0 192.168.100.5   (Server VM's IP on your NAT/internal network)"
    exit 1
fi

SERVER_CN="$1"

CA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CA_DIR"

CA_KEY="ca.key"
CA_CERT="ca.crt"

SERVER_KEY="server.key"
SERVER_CSR="server.csr"
SERVER_CERT="server.crt"
CERT_DAYS=1

if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CERT" ]; then
    echo "ERROR: CA not found. Run setup_ca.sh first."
    exit 1
fi

echo "[*] Generating server private key (RSA 2048)..."
openssl genrsa -out "$SERVER_KEY" 2048
chmod 600 "$SERVER_KEY"

echo "[*] Generating Certificate Signing Request for CN=$SERVER_CN..."
openssl req -new \
    -key "$SERVER_KEY" \
    -subj "/C=IN/O=CS6008 SecureChat/CN=$SERVER_CN" \
    -out "$SERVER_CSR"

# v3 extensions file: marks this as an end-entity server cert, not a CA,
# and scopes it to server authentication.
cat > server_ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

echo "[*] Signing CSR with our CA..."
openssl x509 -req \
    -in "$SERVER_CSR" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -days "$CERT_DAYS" \
    -sha256 \
    -extfile server_ext.cnf \
    -out "$SERVER_CERT"

echo "[*] Server certificate issued."
echo "    Server key + cert (Server VM only): $CA_DIR/$SERVER_KEY, $CA_DIR/$SERVER_CERT"
echo ""
echo "[*] Verifying the certificate chain:"
openssl verify -CAfile "$CA_CERT" "$SERVER_CERT"
echo ""
echo "[*] Certificate details:"
openssl x509 -in "$SERVER_CERT" -noout -subject -issuer -dates