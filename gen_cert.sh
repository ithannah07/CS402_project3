#!/bin/sh

set -eu

# Part 3 certificate generation script
#
# Overview:
#   Generates the certificate set required for mutual TLS:
#   1. a local certificate authority (CA)
#   2. a server certificate and private key
#   3. a client certificate and private key
#
# Inputs:
#   No command-line parameters are required. The script assumes it is run from
#   or relative to the project directory and writes all output files there.
#
# Outputs:
#   - ca.crt / ca.key
#   - server.crt / server.key
#   - client.crt / client.key

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

EXT_FILE="$(mktemp)"
cleanup() {
  # Remove temporary config, CSR, and serial files after generation completes.
  rm -f "$EXT_FILE" ca.csr server.csr client.csr ca.srl
}
trap cleanup EXIT

# Define certificate extensions for the leaf certificates.
# server_cert:
#   allows server authentication and adds SAN values for hostname validation
# client_cert:
#   allows client authentication for mutual TLS
cat > "$EXT_FILE" <<'EOF'
[server_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1

[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

# Create a self-signed local CA.
# Output:
#   ca.crt (public CA certificate), ca.key (private CA key)
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=CS402 Local CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Create the server private key and certificate signing request.
# Output:
#   server.key and server.csr
openssl req -new -newkey rsa:4096 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost"

# Sign the server certificate with the CA.
# Output:
#   server.crt signed by ca.crt, with SAN values for localhost and 127.0.0.1
openssl x509 -req -days 365 \
  -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -extfile "$EXT_FILE" -extensions server_cert

# Create the client private key and certificate signing request.
# Output:
#   client.key and client.csr
openssl req -new -newkey rsa:4096 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=tls-client"

# Sign the client certificate with the CA.
# Output:
#   client.crt signed by ca.crt for mutual TLS client authentication
openssl x509 -req -days 365 \
  -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -extfile "$EXT_FILE" -extensions client_cert
