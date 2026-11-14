#!/usr/bin/env bash
# Descarga/actualiza la base GeoLite2-City de MaxMind.
# Requiere MAXMIND_ACCOUNT_ID y MAXMIND_LICENSE_KEY en .env (cuenta
# gratuita en https://www.maxmind.com/en/geolite2/signup).
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [ -z "${MAXMIND_LICENSE_KEY:-}" ] || [ -z "${MAXMIND_ACCOUNT_ID:-}" ]; then
  echo "Falta MAXMIND_ACCOUNT_ID y/o MAXMIND_LICENSE_KEY en .env. Crea una cuenta gratuita en:" >&2
  echo "  https://www.maxmind.com/en/geolite2/signup" >&2
  echo "generas una license key en tu cuenta -> 'Manage License Keys', y tu" >&2
  echo "Account ID esta arriba a la izquierda de cualquier pagina de tu cuenta." >&2
  exit 1
fi

mkdir -p server/data
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

# MaxMind retiro el endpoint viejo (solo license_key por query param) y
# ahora requiere Account ID + license key como HTTP Basic Auth.
curl -sSL \
  -u "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" \
  "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz" \
  -o "$tmp_dir/geolite2-city.tar.gz"

tar -xzf "$tmp_dir/geolite2-city.tar.gz" -C "$tmp_dir"
mmdb_path=$(find "$tmp_dir" -name "GeoLite2-City.mmdb" | head -n1)

if [ -z "$mmdb_path" ]; then
  echo "No se encontro GeoLite2-City.mmdb en la descarga." >&2
  exit 1
fi

cp "$mmdb_path" server/data/GeoLite2-City.mmdb
echo "GeoLite2-City.mmdb actualizado en server/data/"
