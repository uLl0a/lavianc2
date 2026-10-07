#!/bin/bash
#
# Genera la jerarquía de certificados mTLS de rtc2:
#   - CA raíz (10 años)
#   - Certificado del team server (1 año), con SAN configurable
#   - Certificado de operador admin (1 año)
#
# Uso:
#   ./scripts/gen-certs.sh                          # solo localhost + 127.0.0.1
#   SERVER_IP=10.0.100.5 ./scripts/gen-certs.sh # añade esa IP al SAN
#   SERVER_SANS="DNS:c2.example.com,IP:10.0.0.5" ./scripts/gen-certs.sh
#
# IMPORTANTE:
#   - Este script NO toca certs/server_ecdh.{key,pub}. Ese par X25519 lo
#     gestiona el team server al arrancar, y regenerarlo invalida todos
#     los implantes ya compilados (el ServerPubKey va horneado en el binario).
#   - Regenerar el CA invalida cualquier certificado firmado previamente.
#     Si tienes operadores en producción, coordina la rotación.
#
set -euo pipefail

CERT_DIR="${CERT_DIR:-certs}"
mkdir -p "$CERT_DIR"

SERVER_IP="${SERVER_IP:-127.0.0.1}"

SERVER_SANS="${SERVER_SANS:-}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl no encontrado en PATH" >&2
  exit 1
fi

if [[ ! "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: SERVER_IP='$SERVER_IP' no parece una IPv4 válida" >&2
  exit 1
fi

if [[ -f "$CERT_DIR/ca.crt" || -f "$CERT_DIR/server.crt" ]]; then
  echo "AVISO: ya existen certificados en $CERT_DIR/"
  echo "       Se van a sobreescribir. Los certificados antiguos quedarán invalidados."
  echo
fi


SAN="DNS:localhost,IP:127.0.0.1,IP:${SERVER_IP}"
if [[ -n "$SERVER_SANS" ]]; then
  SAN="${SAN},${SERVER_SANS}"
fi

echo "SAN del server: $SAN"
echo


echo "[1/3] Generando CA raíz..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" \
  -subj "/CN=rtc2-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"


echo "[2/3] Generando certificado del server..."
openssl genrsa -out "$CERT_DIR/server.key" 4096 2>/dev/null
openssl req -new -key "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" \
  -subj "/CN=rtc2-server"

openssl x509 -req -days 365 \
  -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.crt" \
  -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n" "$SAN")

rm -f "$CERT_DIR/server.csr"


echo "[3/3] Generando certificado del operador admin..."
openssl genrsa -out "$CERT_DIR/admin.key" 4096 2>/dev/null
openssl req -new -key "$CERT_DIR/admin.key" \
  -out "$CERT_DIR/admin.csr" \
  -subj "/CN=admin"

openssl x509 -req -days 365 \
  -in "$CERT_DIR/admin.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/admin.crt" \
  -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n")

rm -f "$CERT_DIR/admin.csr"


echo
echo "=== Certificados generados en $CERT_DIR/ ==="
ls -la "$CERT_DIR"

echo
echo "=== SAN del certificado del server ==="
openssl x509 -in "$CERT_DIR/server.crt" -noout -ext subjectAltName

echo
echo "=== Subject del certificado del operador ==="
openssl x509 -in "$CERT_DIR/admin.crt" -noout -subject

echo
echo "=== Certificados del server ECDH (NO tocados por este script) ==="
if [[ -f "$CERT_DIR/server_ecdh.pub" ]]; then
  echo "  server_ecdh.key: presente"
  echo "  server_ecdh.pub: presente"
else
  echo "  (aún no generados — el team server los creará al arrancar)"
fi

echo
echo "OK."
