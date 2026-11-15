#!/usr/bin/env bash
# Genera install.sh embebiendo el contenido de todos los archivos del
# agente, para que install.sh sea autocontenido: alcanza con transferir
# ese UNICO archivo a un servidor nuevo, no hace falta mandar la carpeta
# agent/ entera (ni scp -r, ni armar un zip a mano).
#
# Esto es una herramienta de build, no se instala en el servidor. Correr
# este script despues de tocar cualquier archivo fuente del agente (los
# .py, requirements.txt, kill_process.sh, config.example.yaml, los
# archivos de fail2ban, el sudoers o el .service) y commitear el
# install.sh resultante -- el contenido embebido no se actualiza solo.
set -euo pipefail
cd "$(dirname "$0")"

OUT="install.sh"
_n=0

emit_file() {
  local src="$1" dest="$2" mode="${3:-}"
  _n=$((_n + 1))
  local delim="PROXSECURE_EMBED_${_n}_EOF"
  {
    echo "mkdir -p \"\$(dirname \"$dest\")\""
    echo "cat > \"$dest\" <<'${delim}'"
    cat "$src"
    echo "${delim}"
    if [[ -n "$mode" ]]; then
      echo "chmod $mode \"$dest\""
    fi
    echo
  } >> "$OUT"
}

cat > "$OUT" <<'HEAD_EOF'
#!/usr/bin/env bash
# Instala el agente de Prox Secure en un servidor Linux (Debian/Ubuntu).
# Autocontenido: alcanza con este archivo, no hace falta nada mas de este
# repo en el servidor. Generado por _build_install.sh -- no editar a mano
# los archivos embebidos de aca abajo, editar el fuente real en agent/ y
# volver a generar.
# Uso: sudo bash install.sh <server_url> <api_key>
set -euo pipefail

SERVER_URL="${1:?Falta server_url, ej: http://10.0.0.5:8000}"
API_KEY="${2:?Falta api_key del host (se genera al crear el host en el servidor)}"
INSTALL_DIR="/opt/prox-secure-agent"

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
# validar el sudoers acotado del agente) ni funciona el bloqueo/kill/
# otorgamiento de acceso a logs aprobado desde el dashboard (commands.py
# invoca "sudo" en tiempo real). "acl" trae setfacl, que usa
# grant_log_access.sh para dar lectura puntual sin tocar duenos/permisos.
echo "Instalando dependencias del sistema (python3, venv, pip, sudo, fail2ban, acl)..."
apt-get update -y
apt-get install -y python3 python3-venv python3-pip sudo fail2ban acl

id -u prox-secure &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin prox-secure
# Grupo "adm": en Debian/Ubuntu es el dueno de lectura de /var/log/nginx,
# /var/log/apache2, etc. Sin esto, los logs que el agente autodetecta
# (ver discovery.py) existen pero no los puede leer.
usermod -aG adm prox-secure

mkdir -p "$INSTALL_DIR"

echo "Escribiendo los archivos del agente en $INSTALL_DIR..."
HEAD_EOF

emit_file "commands.py"          '$INSTALL_DIR/commands.py'
emit_file "config.py"            '$INSTALL_DIR/config.py'
emit_file "discovery.py"         '$INSTALL_DIR/discovery.py'
emit_file "inventory.py"         '$INSTALL_DIR/inventory.py'
emit_file "log_tailer.py"        '$INSTALL_DIR/log_tailer.py'
emit_file "main.py"              '$INSTALL_DIR/main.py'
emit_file "metrics.py"           '$INSTALL_DIR/metrics.py'
emit_file "process_watch.py"     '$INSTALL_DIR/process_watch.py'
emit_file "requirements.txt"     '$INSTALL_DIR/requirements.txt'
emit_file "kill_process.sh"      '$INSTALL_DIR/kill_process.sh' 755
emit_file "grant_log_access.sh"  '$INSTALL_DIR/grant_log_access.sh' 755

cat >> "$OUT" <<'MID_EOF'
if [[ ! -f "$INSTALL_DIR/config.yaml" ]]; then
MID_EOF

emit_file "config.example.yaml"  '$INSTALL_DIR/config.yaml'

cat >> "$OUT" <<'MID2_EOF'
  echo "Creado $INSTALL_DIR/config.yaml con valores de ejemplo."
  echo "Editalo para activar log_paths/service_users a mano si el autodescubrimiento no alcanza."
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
MID2_EOF

emit_file "fail2ban/filter.d/proxsecure.conf" '/etc/fail2ban/filter.d/proxsecure.conf'
emit_file "fail2ban/jail.d/proxsecure.conf"   '/etc/fail2ban/jail.d/proxsecure.conf'

cat >> "$OUT" <<'MID3_EOF'
systemctl enable --now fail2ban
systemctl restart fail2ban

# sudo acotado: solo fail2ban-client (banip/unbanip) y el wrapper de kill
MID3_EOF

emit_file "sudoers/prox-secure-agent" '/etc/sudoers.d/prox-secure-agent' 440

cat >> "$OUT" <<'MID4_EOF'
visudo -c -f /etc/sudoers.d/prox-secure-agent
MID4_EOF

emit_file "prox-secure-agent.service" '/etc/systemd/system/prox-secure-agent.service'

cat >> "$OUT" <<'TAIL_EOF'
systemctl daemon-reload
systemctl enable prox-secure-agent
# restart (no start): si install.sh se re-corre sobre un agente que ya
# estaba activo, "start" no hace nada y el proceso se queda sin el grupo
# "adm" recien agregado hasta el proximo reinicio manual.
systemctl restart prox-secure-agent

echo "Agente instalado y corriendo. Ver logs: journalctl -u prox-secure-agent -f"
TAIL_EOF

chmod +x "$OUT"
echo "Generado $OUT ($(wc -l < "$OUT") lineas)."
