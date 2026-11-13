#!/usr/bin/env bash
# Instala el agente de Prox Secure en un servidor Linux.
# Uso: sudo ./install.sh <server_url> <api_key>
set -euo pipefail

SERVER_URL="${1:?Falta server_url, ej: http://10.0.0.5:8000}"
API_KEY="${2:?Falta api_key del host (se genera al crear el host en el servidor)}"
INSTALL_DIR="/opt/prox-secure-agent"

if [[ $EUID -ne 0 ]]; then
  echo "Este script debe ejecutarse como root (sudo)." >&2
  exit 1
fi

id -u prox-secure &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin prox-secure

mkdir -p "$INSTALL_DIR"
cp "$(dirname "$0")/collector.py" "$INSTALL_DIR/"
cp "$(dirname "$0")/requirements.txt" "$INSTALL_DIR/"

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --no-cache-dir -r "$INSTALL_DIR/requirements.txt"

cat > "$INSTALL_DIR/.env" <<EOF
PROX_SECURE_SERVER_URL=${SERVER_URL}
PROX_SECURE_API_KEY=${API_KEY}
EOF
chmod 600 "$INSTALL_DIR/.env"

chown -R prox-secure:prox-secure "$INSTALL_DIR"

cp "$(dirname "$0")/prox-secure-agent.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now prox-secure-agent

echo "Agente instalado y corriendo. Ver logs: journalctl -u prox-secure-agent -f"
