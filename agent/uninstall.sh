#!/usr/bin/env bash
# Quita el agente de Shinji SOC de este host: todo lo que puso install.sh.
# Tambien quita un agente instalado con el nombre anterior del proyecto
# (Prox Secure: /opt/prox-secure-agent, usuario prox-secure).
#
# Uso (como root):
#   shinji-soc-uninstall              pide confirmacion
#   shinji-soc-uninstall --dry-run    solo muestra lo que haria
#   shinji-soc-uninstall --yes        sin preguntar
# (install.sh lo deja instalado como /usr/local/sbin/shinji-soc-uninstall;
# tambien se puede copiar y correr con "sudo bash uninstall.sh".)
#
# Quita: el servicio, la carpeta del agente en /opt (incluida su API key),
# el sudoers del agente, su jail de fail2ban (las IPs bloqueadas desde el
# panel quedan desbloqueadas), los permisos de lectura (ACL) que se dieron
# desde el panel con "Dar acceso", y el usuario del agente.
#
# No quita los paquetes que instalo install.sh (python3-venv, fail2ban,
# acl, sudo): pueden estar en uso por otras cosas. Tampoco toca el
# servidor: el host y su historial se borran desde el panel.
set -uo pipefail

ACL_ROOTS=(/var/log /opt /srv /home)   # los mismos que permite grant_log_access.sh

# Cada instalacion: nombre|carpeta|servicio|usuario|sudoers|jail|log de fail2ban|comando
INSTALLS=(
  "Shinji SOC|/opt/shinji-soc-agent|shinji-soc-agent|shinji-soc|/etc/sudoers.d/shinji-soc-agent|shinjisoc|/var/log/shinji-soc-fail2ban.log|/usr/local/sbin/shinji-soc-uninstall"
  "Prox Secure (nombre anterior)|/opt/prox-secure-agent|prox-secure-agent|prox-secure|/etc/sudoers.d/prox-secure-agent|proxsecure|/var/log/prox-secure-fail2ban.log|/usr/local/sbin/prox-secure-uninstall"
)

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
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

echo "Desinstalacion del agente de Shinji SOC en $(hostname)"
[ "$DRY_RUN" -eq 1 ] && echo "(simulacion: no se cambia nada)"

# Rutas donde "Dar acceso" (grant_log_access.sh) dio lectura a $user, sin
# las que quedan dentro de otra de la lista (se quitan juntas, con -R).
# Primero, la lista que guarda grant_log_access.sh. Los agentes anteriores
# no la tienen: entonces se busca, pero no archivo por archivo en todo el
# arbol (con carpetas de cientos de miles de archivos tardaba demasiado),
# sino en las carpetas (Dar acceso sobre una carpeta deja una ACL en ella)
# y en los archivos con nombre de log (Dar acceso sobre un archivo suelto:
# discovery.py solo ofrece logs).
acl_paths() {
  local user="$1" dir="$2" roots=() r
  if [ -f "$dir/granted_paths" ]; then
    while IFS= read -r r; do [ -e "$r" ] && printf '%s\n' "$r"; done < "$dir/granted_paths"
    return
  fi
  for r in "${ACL_ROOTS[@]}"; do [ -e "$r" ] && roots+=("$r"); done
  [ "${#roots[@]}" -eq 0 ] && return
  echo "  Buscando permisos de lectura de $user en ${roots[*]} (con carpetas muy grandes puede tardar unos minutos)..." >&2
  {
    find "${roots[@]}" -xdev -type d -print0 2>/dev/null
    find "${roots[@]}" -xdev -type f \( -name '*.log' -o -name '*.log.*' -o -name '*.logs' \
      -o -path '*/log/*' -o -path '*/logs/*' \) -print0 2>/dev/null
  } | xargs -0 -r getfacl -s -p 2>/dev/null | awk -v u="$user" '
      /^# file: / { file = substr($0, 9); next }
      $0 ~ "^(default:)?user:" u ":" { if (!(file in seen)) { seen[file] = 1; print file } }' \
    | grep -v -e "^$dir\$" -e "^$dir/" \
    | LC_ALL=C sort | awk '{ if (top != "" && index($0, top "/") == 1) next; print; top = $0 }'
}

# --- que hay instalado de cada nombre
found_any=0
declare -A ACL_PATHS FOUND
for entry in "${INSTALLS[@]}"; do
  IFS='|' read -r label dir service user sudoers jail f2blog self <<<"$entry"
  found=0
  lines=()
  [ -d "$dir" ] && { lines+=("agente en $dir"); found=1; }
  [ -f "/etc/systemd/system/$service.service" ] && { lines+=("servicio $service"); found=1; }
  [ -f "$sudoers" ] && { lines+=("sudoers $sudoers"); found=1; }
  [ -f "/etc/fail2ban/jail.d/$jail.conf" ] && { lines+=("jail $jail de fail2ban"); found=1; }
  id -u "$user" >/dev/null 2>&1 && { lines+=("usuario $user"); found=1; }

  # Permisos de lectura (ACL) que dio "Dar acceso". Se buscan antes de
  # borrar el usuario: despues getfacl solo mostraria su numero.
  paths=""
  if have getfacl && id -u "$user" >/dev/null 2>&1; then
    paths=$(acl_paths "$user" "$dir")
    total=$(printf '%s' "$paths" | grep -c . || true)
    [ "$total" -gt 0 ] && { lines+=("permisos de lectura (ACL) de $user en $total rutas"); found=1; }
  fi
  ACL_PATHS[$user]="$paths"
  FOUND[$user]=$found

  if [ "$found" -eq 1 ]; then
    found_any=1
    echo
    echo "$label:"
    for l in "${lines[@]}"; do echo "- $l"; done
    if have fail2ban-client && fail2ban-client status "$jail" >/dev/null 2>&1; then
      banned=$(fail2ban-client status "$jail" 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p')
      [ -n "$banned" ] && echo "  IPs bloqueadas desde el panel que quedaran desbloqueadas: $banned"
    fi
  fi
done

if [ "$found_any" -eq 0 ]; then
  echo
  echo "No hay nada del agente instalado en este host."
  if [ "$DRY_RUN" -eq 0 ]; then
    for entry in "${INSTALLS[@]}"; do
      IFS='|' read -r _ _ _ _ _ _ _ self <<<"$entry"
      [ -f "$self" ] && rm -f "$self"
    done
  fi
  exit 0
fi

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
  echo
  read -r -p "Escribe QUITAR para desinstalar el agente: " answer
  [ "$answer" = "QUITAR" ] || { echo "Cancelado."; exit 1; }
fi

restart_f2b=0
for entry in "${INSTALLS[@]}"; do
  IFS='|' read -r label dir service user sudoers jail f2blog self <<<"$entry"
  [ "${FOUND[$user]}" -eq 1 ] || continue
  echo
  echo "== $label"

  echo "1/6 Servicio"
  if [ -f "/etc/systemd/system/$service.service" ]; then
    have systemctl && run systemctl disable --now "$service"
    run rm -f "/etc/systemd/system/$service.service"
    have systemctl && run systemctl daemon-reload
  else
    echo "  (no esta)"
  fi

  echo "2/6 Jail $jail de fail2ban"
  if [ -f "/etc/fail2ban/jail.d/$jail.conf" ] || [ -f "/etc/fail2ban/filter.d/$jail.conf" ]; then
    run rm -f "/etc/fail2ban/jail.d/$jail.conf" "/etc/fail2ban/filter.d/$jail.conf" "$f2blog"
    restart_f2b=1
  else
    echo "  (no esta)"
  fi

  echo "3/6 Permisos de lectura (ACL)"
  [ -z "${ACL_PATHS[$user]}" ] && echo "  (ninguno)"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    if [ -d "$p" ]; then
      # La carpeta y todo lo de adentro de una vez: la entrada de acceso
      # (archivos y carpetas) y la entrada por defecto (solo carpetas).
      run setfacl -R -x "u:$user" "$p"
      run find "$p" -xdev -type d -exec setfacl -x "d:u:$user" {} +
    else
      run setfacl -x "u:$user" "$p"
    fi
  done <<<"${ACL_PATHS[$user]}"

  echo "4/6 Sudoers"
  if [ -f "$sudoers" ]; then
    run rm -f "$sudoers"
  else
    echo "  (no esta)"
  fi

  echo "5/6 Usuario $user"
  if id -u "$user" >/dev/null 2>&1; then
    # Por si quedo algun proceso suyo (el servicio ya se detuvo).
    have pkill && run pkill -u "$user"
    run userdel "$user"
    getent group "$user" >/dev/null 2>&1 && run groupdel "$user"
  else
    echo "  (no esta)"
  fi

  echo "6/6 Archivos del agente"
  if [ -d "$dir" ]; then
    run rm -rf "$dir"
  else
    echo "  (no estan)"
  fi
done

# Reiniciar fail2ban saca los jails borrados y sus bloqueos; el resto de
# los jails sigue igual.
if [ "$restart_f2b" -eq 1 ] && have systemctl && systemctl is-active --quiet fail2ban; then
  echo
  run systemctl restart fail2ban
fi

echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "Simulacion terminada: no se cambio nada."
else
  for entry in "${INSTALLS[@]}"; do
    IFS='|' read -r _ _ _ _ _ _ _ self <<<"$entry"
    [ -f "$self" ] && rm -f "$self"
  done
  echo "Agente quitado de $(hostname)."
  echo "Los paquetes (python3-venv, fail2ban, acl, sudo) quedan instalados."
  echo "Para borrar tambien el host y su historial del panel: Monitoreo > el host > Eliminar (pide MFA)."
fi
