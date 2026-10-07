#!/bin/bash
set -euo pipefail

CERT_DIR="certs"
mkdir -p "$CERT_DIR"

# 1. CA raíz
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" -subj "/CN=rtc2-ca"

# 2. Certificado del server
openssl genrsa -out "$CERT_DIR/server.key" 4096
openssl req -new -key "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" -subj "/CN=rtc2-server"
openssl x509 -req -days 365 -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.crt" -extfile <(echo "subjectAltName=DNS:localhost,IP:127.0.0.1")

# 3. Certificado de operador admin
openssl genrsa -out "$CERT_DIR/admin.key" 4096
openssl req -new -key "$CERT_DIR/admin.key" \
  -out "$CERT_DIR/admin.csr" -subj "/CN=admin"
openssl x509 -req -days 365 -in "$CERT_DIR/admin.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/admin.crt"

echo "Certificados generados en $CERT_DIR/"