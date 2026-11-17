#!/usr/bin/env bash
# Instala (o quita) la actualizacion automatica de Shinji SOC: un
# temporizador de systemd que corre scripts/update.sh cada hora.
#
#   sudo bash scripts/install_auto_update.sh            instala y activa
#   sudo bash scripts/install_auto_update.sh --remove   la quita
#
# Ver lo que hizo:  journalctl -u shinji-soc-update
# Proxima corrida:  systemctl list-timers shinji-soc-update.timer
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UNIT=shinji-soc-update
SERVICE_FILE="/etc/systemd/system/$UNIT.service"
TIMER_FILE="/etc/systemd/system/$UNIT.timer"

if [ "$EUID" -ne 0 ]; then
  echo "Hay que correrlo como root (sudo)." >&2
  exit 1
fi
command -v systemctl >/dev/null 2>&1 || { echo "Necesita systemd (Linux)." >&2; exit 1; }

if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now "$UNIT.timer" 2>/dev/null || true
  rm -f "$SERVICE_FILE" "$TIMER_FILE"
  systemctl daemon-reload
  echo "Actualizacion automatica quitada."
  exit 0
fi

[ -d "$REPO/.git" ] || { echo "$REPO no es un clon de git: instala con git clone (docs/INSTALACION.md)." >&2; exit 1; }

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Shinji SOC: actualizar a la ultima version de GitHub
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
WorkingDirectory=$REPO
ExecStart=/usr/bin/env bash $REPO/scripts/update.sh
EOF

cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Shinji SOC: revisar actualizaciones cada hora

[Timer]
OnCalendar=hourly
# Hasta 5 minutos al azar, para no consultar GitHub justo en la hora en punto.
RandomizedDelaySec=300
# Si el equipo estaba apagado a la hora, corre al encender.
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "$UNIT.timer"
echo "Actualizacion automatica activada: revisa GitHub cada hora."
echo "  Proxima corrida: systemctl list-timers $UNIT.timer"
echo "  Registro:        journalctl -u $UNIT"
echo "  Probar ahora:    sudo systemctl start $UNIT.service"
