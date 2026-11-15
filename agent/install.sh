#!/usr/bin/env bash
# Instala el agente de Prox Secure en un servidor Linux (Debian/Ubuntu).
# Uso: sudo ./install.sh <server_url> <api_key>
set -euo pipefail

SERVER_URL="${1:?Falta server_url, ej: http://10.0.0.5:8000}"
API_KEY="${2:?Falta api_key del host (se genera al crear el host en el servidor)}"
INSTALL_DIR="/opt/prox-secure-agent"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Este script debe ejecutarse como root (sudo)." >&2
  exit 1
fi

# Dependencias del sistema. Se instalan siempre (apt no reinstala lo que
# ya esta, es rapido) en vez de detectar que falta uno por uno -- asi se
# evita el problema clasico de Debian donde python3 esta pero el modulo
# venv/pip no, porque van en paquetes separados (python3-venv, python3-pip).
# "sudo" se incluye a proposito: en hosts tipo hipervisor (Proxmox VE y
# similares, donde todo se maneja como root directamente) suele no venir
# instalado, y sin el no existe "visudo" (lo necesitamos mas abajo para
# validar el sudoers acotado del agente).
echo "Instalando dependencias del sistema (python3, venv, pip, sudo, fail2ban)..."
apt-get update -y
apt-get install -y python3 python3-venv python3-pip sudo fail2ban

id -u prox-secure &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin prox-secure
# Grupo "adm": en Debian/Ubuntu es el dueno de lectura de /var/log/nginx,
# /var/log/apache2, etc. Sin esto, los logs que el agente autodetecta
# (ver discovery.py) existen pero no los puede leer.
usermod -aG adm prox-secure

mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR"/*.py "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/kill_process.sh" "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/kill_process.sh"

if [[ ! -f "$INSTALL_DIR/config.yaml" ]]; then
  cp "$SCRIPT_DIR/config.example.yaml" "$INSTALL_DIR/config.yaml"
  echo "Creado $INSTALL_DIR/config.yaml con valores de ejemplo."
  echo "Editalo para activar log_paths (logs de nginx/apache) y process_watch.service_users."
fi

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --no-cache-dir -r "$INSTALL_DIR/requirements.txt"

cat > "$INSTALL_DIR/.env" <<EOF
PROX_SECURE_SERVER_URL=${SERVER_URL}
PROX_SECURE_API_KEY=${API_KEY}
EOF
chmod 600 "$INSTALL_DIR/.env"

chown -R prox-secure:prox-secure "$INSTALL_DIR"

# fail2ban: jail dedicado para bloqueos manuales via panel
mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d
cp "$SCRIPT_DIR/fail2ban/filter.d/proxsecure.conf" /etc/fail2ban/filter.d/
cp "$SCRIPT_DIR/fail2ban/jail.d/proxsecure.conf" /etc/fail2ban/jail.d/
systemctl enable --now fail2ban
systemctl restart fail2ban

# sudo acotado: solo fail2ban-client (banip/unbanip) y el wrapper de kill
install -m 440 "$SCRIPT_DIR/sudoers/prox-secure-agent" /etc/sudoers.d/prox-secure-agent
visudo -c -f /etc/sudoers.d/prox-secure-agent

cp "$SCRIPT_DIR/prox-secure-agent.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable prox-secure-agent
# restart (no start): si install.sh se re-corre sobre un agente que ya
# estaba activo, "start" no hace nada y el proceso se queda sin el grupo
# "adm" recien agregado hasta el proximo reinicio manual.
systemctl restart prox-secure-agent

echo "Agente instalado y corriendo. Ver logs: journalctl -u prox-secure-agent -f"
