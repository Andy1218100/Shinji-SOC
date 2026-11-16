#!/usr/bin/env bash
# Quita el agente de Prox Secure de este host: todo lo que puso install.sh.
#
# Uso (como root):
#   prox-secure-uninstall              pide confirmacion
#   prox-secure-uninstall --dry-run    solo muestra lo que haria
#   prox-secure-uninstall --yes        sin preguntar
# (install.sh lo deja instalado como /usr/local/sbin/prox-secure-uninstall;
# tambien se puede copiar y correr con "sudo bash uninstall.sh".)
#
# Quita: el servicio, /opt/prox-secure-agent (incluida su API key), el
# sudoers del agente, el jail "proxsecure" de fail2ban (las IPs bloqueadas
# desde el panel quedan desbloqueadas), los permisos de lectura (ACL) que
# se dieron desde el panel con "Dar acceso", y el usuario prox-secure.
#
# No quita los paquetes que instalo install.sh (python3-venv, fail2ban,
# acl, sudo): pueden estar en uso por otras cosas. Tampoco toca el
# servidor: el host y su historial se borran desde el panel.
set -uo pipefail

INSTALL_DIR="/opt/prox-secure-agent"
SERVICE="prox-secure-agent"
AGENT_USER="prox-secure"
ACL_ROOTS=(/var/log /opt /srv /home)   # los mismos que permite grant_log_access.sh
SELF="/usr/local/sbin/prox-secure-uninstall"

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "Opcion desconocida: $arg (usa --dry-run, --yes o --help)" >&2; exit 2 ;;
  esac
done

if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  echo "Hay que correrlo como root (sudo)." >&2
  exit 1
fi

run() {
  # Muestra cada accion; en --dry-run no la ejecuta.
  echo "  + $*"
  if [ "$DRY_RUN" -eq 0 ]; then
    "$@" || echo "    (fallo, se sigue con el resto)" >&2
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

echo "Desinstalacion del agente de Prox Secure en $(hostname)"
[ "$DRY_RUN" -eq 1 ] && echo "(simulacion: no se cambia nada)"
echo

# --- lo que hay instalado
found=0
[ -d "$INSTALL_DIR" ] && { echo "- agente en $INSTALL_DIR"; found=1; }
[ -f "/etc/systemd/system/$SERVICE.service" ] && { echo "- servicio $SERVICE"; found=1; }
[ -f /etc/sudoers.d/prox-secure-agent ] && { echo "- sudoers /etc/sudoers.d/prox-secure-agent"; found=1; }
[ -f /etc/fail2ban/jail.d/proxsecure.conf ] && { echo "- jail proxsecure de fail2ban"; found=1; }
id -u "$AGENT_USER" >/dev/null 2>&1 && { echo "- usuario $AGENT_USER"; found=1; }

banned=""
if have fail2ban-client && fail2ban-client status proxsecure >/dev/null 2>&1; then
  banned=$(fail2ban-client status proxsecure 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p')
  [ -n "$banned" ] && echo "  IPs bloqueadas desde el panel que quedaran desbloqueadas: $banned"
fi

# ACLs que dio "Dar acceso" (grant_log_access.sh). Se buscan antes de
# borrar el usuario: despues getfacl solo mostraria su numero.
acl_files=()
acl_default=()
if have getfacl && id -u "$AGENT_USER" >/dev/null 2>&1; then
  roots=()
  for r in "${ACL_ROOTS[@]}"; do [ -e "$r" ] && roots+=("$r"); done
  if [ "${#roots[@]}" -gt 0 ]; then
    echo "  Buscando permisos de lectura del agente en ${roots[*]} (puede tardar en carpetas grandes)..."
    while IFS=$'\t' read -r kind path; do
      case "$path" in "$INSTALL_DIR"|"$INSTALL_DIR"/*) continue ;; esac  # se borra entera
      if [ "$kind" = "d" ]; then acl_default+=("$path"); else acl_files+=("$path"); fi
    done < <(getfacl -R -s -p "${roots[@]}" 2>/dev/null | awk -v u="$AGENT_USER" '
      /^# file: / { file = substr($0, 9); next }
      $0 ~ "^user:" u ":"         { print "a\t" file }
      $0 ~ "^default:user:" u ":" { print "d\t" file }')
  fi
  total=$(( ${#acl_files[@]} + ${#acl_default[@]} ))
  [ "$total" -gt 0 ] && { echo "- $total permisos de lectura (ACL) del agente"; found=1; }
fi

if [ "$found" -eq 0 ]; then
  echo "No hay nada del agente instalado en este host."
  [ -f "$SELF" ] && [ "$DRY_RUN" -eq 0 ] && rm -f "$SELF"
  exit 0
fi

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
  echo
  read -r -p "Escribe QUITAR para desinstalar el agente: " answer
  [ "$answer" = "QUITAR" ] || { echo "Cancelado."; exit 1; }
fi
echo

echo "1/6 Servicio"
if have systemctl && [ -f "/etc/systemd/system/$SERVICE.service" ]; then
  run systemctl disable --now "$SERVICE"
  run rm -f "/etc/systemd/system/$SERVICE.service"
  run systemctl daemon-reload
else
  echo "  (no esta)"
fi

echo "2/6 Jail proxsecure de fail2ban"
if [ -f /etc/fail2ban/jail.d/proxsecure.conf ] || [ -f /etc/fail2ban/filter.d/proxsecure.conf ]; then
  run rm -f /etc/fail2ban/jail.d/proxsecure.conf /etc/fail2ban/filter.d/proxsecure.conf /var/log/prox-secure-fail2ban.log
  # Reiniciar saca el jail y sus bloqueos; el resto de los jails sigue igual.
  if have systemctl && systemctl is-active --quiet fail2ban; then
    run systemctl restart fail2ban
  fi
else
  echo "  (no esta)"
fi

echo "3/6 Permisos de lectura (ACL)"
if [ "${#acl_files[@]}" -eq 0 ] && [ "${#acl_default[@]}" -eq 0 ]; then
  echo "  (ninguno)"
fi
for p in "${acl_files[@]}"; do run setfacl -x "u:$AGENT_USER" "$p"; done
for p in "${acl_default[@]}"; do run setfacl -x "d:u:$AGENT_USER" "$p"; done

echo "4/6 Sudoers"
if [ -f /etc/sudoers.d/prox-secure-agent ]; then
  run rm -f /etc/sudoers.d/prox-secure-agent
else
  echo "  (no esta)"
fi

echo "5/6 Usuario $AGENT_USER"
if id -u "$AGENT_USER" >/dev/null 2>&1; then
  # Por si quedo algun proceso suyo (el servicio ya se detuvo).
  have pkill && run pkill -u "$AGENT_USER"
  run userdel "$AGENT_USER"
  getent group "$AGENT_USER" >/dev/null 2>&1 && run groupdel "$AGENT_USER"
else
  echo "  (no esta)"
fi

echo "6/6 Archivos del agente"
if [ -d "$INSTALL_DIR" ]; then
  run rm -rf "$INSTALL_DIR"
else
  echo "  (no estan)"
fi

echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "Simulacion terminada: no se cambio nada."
else
  [ -f "$SELF" ] && rm -f "$SELF"
  echo "Agente quitado de $(hostname)."
  echo "Los paquetes (python3-venv, fail2ban, acl, sudo) quedan instalados."
  echo "Para borrar tambien el host y su historial del panel: Monitoreo > el host > Eliminar (pide MFA)."
fi
