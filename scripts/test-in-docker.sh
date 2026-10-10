#!/bin/sh
# Ejecuta un comando del operator-cli / e2e-bacon DENTRO de la red 'c2net'
# del entorno de pruebas Docker, usando los certs locales. Así se opera el
# team server del contenedor sin exponer puertos al host.
#
# Uso:
#   ./scripts/test-in-docker.sh operator-cli operator list
#   ./scripts/test-in-docker.sh e2e-beacon list
#   ./scripts/test-in-docker.sh e2e-bacon register b1 short-haul
#
# Requiere: docker, y que el entorno esté levantado
#   (docker compose -f docker-compose.test.yml up -d).
set -e

BIN="$1"; shift
NET="lavianc2_c2net"
IMG="alpine:3.20"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

# binario a montar
case "$BIN" in
  operator-cli) SRC="$DIR/bin/operator-cli" ;;
  e2e-beacon)   SRC="$DIR/bin/e2e-beacon" ;;
  e2e-builtin)  SRC="$DIR/bin/e2e-builtin" ;;
  *) echo "binario desconocido: $BIN (usa operator-cli|e2e-beacon|e2e-builtin)"; exit 1 ;;
esac

if [ ! -f "$SRC" ]; then
  echo "no existe $SRC — compílalo primero (go build -o $SRC ./cmd/$BIN)"
  exit 1
fi

# El gRPC del teamserver escucha en teamserver:9443 dentro de c2net.
# Todos los tools (operator-cli y e2e-*) aceptan --server/--cert/--key/--ca.
# /tmp del host se monta para que --data pueda leer payloads.
exec docker run --rm --network "$NET" \
  -v "$SRC:/tool:ro" \
  -v "$DIR/certs:/certs:ro" \
  -v /tmp:/tmp:ro \
  -w /certs \
  "$IMG" \
  /tool --server teamserver:9443 --cert /certs/admin.crt --key /certs/admin.key --ca /certs/ca.crt "$@"
