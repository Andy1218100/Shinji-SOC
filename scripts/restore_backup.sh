#!/usr/bin/env bash
# Restaura un respaldo de ./backups sobre la base de Shinji SOC.
#
# Uso (desde la carpeta del proyecto):
#   bash scripts/restore_backup.sh backups/shinjisoc-AAAAMMDD-HHMMSS.dump
#
# Pasos (los que indica TimescaleDB para pg_restore, sin -j:
# https://docs.timescale.com/self-hosted/latest/backup-and-restore/logical-backup):
#   1. respaldo de seguridad del estado actual (backups/pre-restore-*.dump)
#   2. detiene server y backup
#   3. recrea la base, CREATE EXTENSION timescaledb, timescaledb_pre_restore()
#   4. pg_restore, timescaledb_post_restore(), ANALYZE
#   5. vuelve a levantar server y backup
# Restaurar en una version de TimescaleDB distinta a la del respaldo puede
# fallar: la imagen es timescale/timescaledb:latest-pg16.
set -euo pipefail

cd "$(dirname "$0")/.."

dump="${1:-}"
if [ -z "$dump" ] || [ ! -f "$dump" ]; then
  echo "Uso: bash scripts/restore_backup.sh backups/shinjisoc-AAAAMMDD-HHMMSS.dump" >&2
  ls -1t backups/shinjisoc-*.dump backups/proxsecure-*.dump 2>/dev/null | head -n 5 | sed 's/^/  disponible: /' >&2
  exit 1
fi

if [ -f .env ]; then set -a; . ./.env; set +a; fi
db="${POSTGRES_DB:-shinjisoc}"
user="${POSTGRES_USER:-shinjisoc}"
psql_db() { docker compose exec -T db psql -v ON_ERROR_STOP=1 -U "$user" -d "$1" -q "${@:2}"; }

echo "Esto REEMPLAZA toda la base '$db' por el contenido de $dump."
echo "Antes se guarda un respaldo de seguridad del estado actual."
read -r -p "Escribe RESTAURAR para continuar: " answer
[ "$answer" = "RESTAURAR" ] || { echo "Cancelado."; exit 1; }

safety="backups/pre-restore-$(date -u +%Y%m%d-%H%M%S).dump"
echo "1/5 Respaldo de seguridad -> $safety"
docker compose exec -T db pg_dump -U "$user" -d "$db" -Fc > "$safety"
chmod 600 "$safety"

echo "2/5 Deteniendo server y backup"
docker compose stop server backup

echo "3/5 Recreando la base"
psql_db postgres -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE);" -c "CREATE DATABASE \"$db\" OWNER \"$user\";"
psql_db "$db" -c "CREATE EXTENSION IF NOT EXISTS timescaledb;" -c "SELECT timescaledb_pre_restore();"

echo "4/5 Restaurando (puede tardar)"
docker compose exec -T db pg_restore -U "$user" -d "$db" --no-owner < "$dump" || {
  echo "pg_restore informo errores (ver arriba). La base puede estar incompleta;" >&2
  echo "el respaldo de seguridad del estado anterior es $safety." >&2
}
psql_db "$db" -c "SELECT timescaledb_post_restore();" -c "ANALYZE;"

echo "5/5 Levantando server y backup"
docker compose start server backup
echo "Listo. Si algo salio mal, restaura $safety con este mismo script."
