#!/usr/bin/env bash
# Da a prox-secure permiso de LECTURA (via ACL -- nunca toca duenos ni
# permisos existentes, nunca agrega escritura) sobre una carpeta o
# archivo que discovery.py encontro pero no pudo abrir/leer. Pensado
# para correr via sudo (ver sudoers/prox-secure-agent).
#
# Solo opera dentro de las mismas rutas donde discovery.py busca logs
# (ver LOG_SCAN_ROOTS en discovery.py) -- y nunca sobre /root: el riesgo
# de dar lectura recursiva al home de root (claves SSH, etc.) no vale la
# pena por un log que casi seguro no esta ahi. Si el log que falta
# resulta estar en /root, hay que revisarlo a mano por ssh.
set -euo pipefail

TARGET="${1:?uso: grant_log_access.sh <ruta absoluta>}"

if [[ "$TARGET" != /* ]]; then
  echo "la ruta debe ser absoluta" >&2
  exit 1
fi

if [[ ! -e "$TARGET" ]]; then
  echo "la ruta no existe: $TARGET" >&2
  exit 1
fi

RESOLVED=$(realpath -e "$TARGET")

ALLOWED_PREFIXES=("/var/log" "/opt" "/srv" "/home")
allowed=0
for prefix in "${ALLOWED_PREFIXES[@]}"; do
  if [[ "$RESOLVED" == "$prefix" || "$RESOLVED" == "$prefix"/* ]]; then
    allowed=1
    break
  fi
done
if [[ "$allowed" -ne 1 ]]; then
  echo "ruta fuera de lo permitido ($RESOLVED) -- solo /var/log, /opt, /srv o /home (nunca /root)" >&2
  exit 2
fi

if ! command -v setfacl &>/dev/null; then
  echo "setfacl no esta instalado (paquete 'acl')" >&2
  exit 3
fi

if [[ -d "$RESOLVED" ]]; then
  # rX en vez de rx: la X mayuscula solo da ejecucion (necesaria para
  # poder "entrar") a lo que ya es un directorio, nunca a un archivo
  # suelto -- no vuelve ejecutable nada que no lo fuera.
  setfacl -R -m u:prox-secure:rX "$RESOLVED"
  # ACL por defecto: para que los logs que esa app cree DESPUES de hoy
  # (rotacion diaria, nuevas instancias, etc.) hereden el mismo permiso
  # sin tener que repetir esto cada vez.
  setfacl -R -d -m u:prox-secure:rX "$RESOLVED"
else
  setfacl -m u:prox-secure:r "$RESOLVED"
fi

echo "acceso de lectura otorgado a prox-secure sobre $RESOLVED"
