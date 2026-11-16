#!/bin/sh
# Respaldo periodico de la base (corre en el contenedor "backup" de
# docker-compose.yml, con la misma imagen que la base: su pg_dump es de la
# misma version). Formato custom (-Fc), el que recomienda TimescaleDB:
# https://docs.timescale.com/self-hosted/latest/backup-and-restore/logical-backup
#
# Lee BACKUP_INTERVAL_HOURS y BACKUP_KEEP del .env en cada vuelta, asi un
# cambio desde la pagina de Configuracion aplica sin reiniciar. Si existe
# /backups/.request (lo deja el boton "Respaldar ahora"), respalda ya.
#
# Los respaldos contienen hashes de contrasenas, secretos MFA y API keys de
# los hosts: quedan con permisos 600 y conviene copiarlos fuera del servidor.
set -u

BACKUP_DIR=/backups
ENV_FILE=/config/.env
STATUS="$BACKUP_DIR/.status"
umask 077
mkdir -p "$BACKUP_DIR"

env_value() {
  # Valor de una clave del .env (sin comillas), o el defecto.
  v=$(grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '"'"'")
  echo "${v:-$2}"
}

write_status() {
  {
    echo "last_attempt=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "result=$1"
    echo "message=$2"
  } > "$STATUS.tmp" && mv "$STATUS.tmp" "$STATUS"
}

do_backup() {
  ts=$(date -u +%Y%m%d-%H%M%S)
  part="$BACKUP_DIR/.proxsecure-$ts.dump.part"
  final="$BACKUP_DIR/proxsecure-$ts.dump"
  if PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h db -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f "$part" 2> "$BACKUP_DIR/.last_stderr"; then
    mv "$part" "$final"
    chmod 600 "$final"
    write_status ok "$(basename "$final") ($(du -h "$final" | cut -f1))"
    echo "Respaldo creado: $final"
  else
    rm -f "$part"
    write_status error "$(tail -n 3 "$BACKUP_DIR/.last_stderr" | tr '\n' ' ' | cut -c1-300)"
    echo "Fallo el respaldo: $(cat "$BACKUP_DIR/.last_stderr")" >&2
  fi
  # Retencion: los BACKUP_KEEP mas nuevos.
  keep=$(env_value BACKUP_KEEP 14)
  ls -1t "$BACKUP_DIR"/proxsecure-*.dump 2>/dev/null | tail -n +"$((keep + 1))" | while read -r old; do
    rm -f "$old" && echo "Borrado por retencion: $old"
  done
}

: "${POSTGRES_USER:=proxsecure}" "${POSTGRES_PASSWORD:=proxsecure}" "${POSTGRES_DB:=proxsecure}"
echo "Respaldos en $BACKUP_DIR (intervalo $(env_value BACKUP_INTERVAL_HOURS 24) h, se conservan $(env_value BACKUP_KEEP 14))"

while true; do
  interval=$(env_value BACKUP_INTERVAL_HOURS 24)
  recent=$(find "$BACKUP_DIR" -maxdepth 1 -name 'proxsecure-*.dump' -mmin -"$((interval * 60))" 2>/dev/null | head -n1)
  if [ -f "$BACKUP_DIR/.request" ] || [ -z "$recent" ]; then
    rm -f "$BACKUP_DIR/.request"
    do_backup
  fi
  sleep 30
done
