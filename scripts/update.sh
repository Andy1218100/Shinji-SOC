#!/usr/bin/env bash
# Actualiza Shinji SOC a la ultima version de GitHub (la rama actual).
#
#   sudo bash scripts/update.sh          actualiza si hay una version nueva
#   sudo bash scripts/update.sh --check  solo dice si hay una version nueva
#   sudo bash scripts/update.sh --retry  reintenta una version que fallo
#
# Lo corre cada hora el temporizador que instala
# scripts/install_auto_update.sh; tambien se puede correr a mano.
#
# Que hace:
#   1. Trae los commits nuevos (git fetch). Si no hay, termina.
#   2. No toca nada si hay archivos versionados modificados a mano o si el
#      historial local y el de GitHub se separaron: eso lo resuelve una
#      persona (el .env y docker-compose.override.yml no cuentan: no se
#      versionan).
#   3. Si solo cambio documentacion, avanza los archivos y no reinicia nada.
#   4. Si cambio codigo: respalda la base (backups/shinjisoc-*-antes-de-
#      actualizar.dump), avanza, reconstruye los contenedores y comprueba
#      que el panel responda. Si no responde, vuelve a la version anterior
#      (el codigo; la base queda como esta y el respaldo sirve si hace falta).
#   5. Si cambio el agente, lo avisa: los agentes se reinstalan a mano
#      (docs/AGENTE.md).
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
HEALTH_TIMEOUT="${SHINJI_SOC_HEALTH_TIMEOUT:-180}"   # segundos que se espera a que el panel responda
KEEP_PRE_UPDATE=5    # respaldos previos a actualizar que se conservan
FAILED_FILE="$REPO/backups/.actualizacion-fallida"   # version que fallo (no se versiona)

CHECK_ONLY=0
case "${1:-}" in
  --check) CHECK_ONLY=1 ;;
  --retry|"") ;;
  -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
  *) echo "Opcion desconocida: $1 (usa --check o --help)" >&2; exit 2 ;;
esac

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
fail() { log "ERROR: $*" >&2; exit 1; }
# Como root sobre un repo clonado por otro usuario, git se niega a operar
# ("dubious ownership") salvo que se le indique que la carpeta es segura.
g() { git -c safe.directory="$REPO" "$@"; }

# Una sola actualizacion a la vez (por si el temporizador y una persona
# coinciden).
if command -v flock >/dev/null 2>&1; then
  exec 9>"/tmp/shinji-soc-update.lock"
  flock -n 9 || { log "Ya hay una actualizacion en curso."; exit 0; }
fi

command -v git >/dev/null 2>&1 || fail "falta git"
command -v docker >/dev/null 2>&1 || fail "falta docker"
[ -d .git ] || fail "$REPO no es un clon de git: instala con git clone (docs/INSTALACION.md)"

branch=$(g rev-parse --abbrev-ref HEAD) || fail "no se pudo leer la rama actual"
[ "$branch" != "HEAD" ] || fail "el repositorio no esta en una rama (HEAD suelto)"
g fetch --quiet origin "$branch" || fail "no se pudo consultar GitHub (git fetch)"

current=$(g rev-parse HEAD)
latest=$(g rev-parse "origin/$branch")
if [ "$current" = "$latest" ]; then
  log "Ya esta en la ultima version (${current:0:7})."
  exit 0
fi
# Una version que ya fallo y se revirtio no se reintenta cada hora: se
# espera a que haya otra (o se corre a mano con --retry).
if [ "${1:-}" != "--retry" ] && [ -f "$FAILED_FILE" ] && [ "$(cat "$FAILED_FILE")" = "$latest" ]; then
  log "La version ${latest:0:7} ya fallo antes y se revirtio; no se reintenta hasta que haya una nueva (o: update.sh --retry)."
  exit 0
fi
g merge-base --is-ancestor HEAD "origin/$branch" \
  || fail "el historial local y el de GitHub se separaron (commits locales o reescritura); no se actualiza solo"

changed=$(g diff --name-only HEAD "origin/$branch")
code_changed=$(printf '%s\n' "$changed" | grep -v -E '(\.md$|^docs/|^LICENSE$|^\.gitignore$|^\.gitattributes$)' || true)
agent_changed=$(printf '%s\n' "$changed" | grep -E '^agent/' || true)
log "Version nueva: ${current:0:7} -> ${latest:0:7} ($(printf '%s\n' "$changed" | grep -c .) archivos)."
g log --oneline "HEAD..origin/$branch" | sed 's/^/    /'

if [ "$CHECK_ONLY" -eq 1 ]; then
  [ -n "$code_changed" ] && log "Incluye cambios de codigo: la actualizacion reconstruye los contenedores." \
    || log "Solo cambia documentacion."
  exit 0
fi

[ -z "$(g status --porcelain --untracked-files=no)" ] \
  || fail "hay archivos versionados modificados a mano (git status); no se actualiza solo"

if [ -z "$code_changed" ]; then
  g merge --quiet --ff-only "origin/$branch" || fail "no se pudo avanzar (git merge --ff-only)"
  log "Solo cambio documentacion: actualizada sin reiniciar nada."
  exit 0
fi

# --- respaldo de la base antes de cambiar el codigo
mkdir -p backups
dump="backups/shinjisoc-$(date +%Y%m%d-%H%M%S)-antes-de-actualizar.dump"
if docker compose ps --status running --services 2>/dev/null | grep -qx db; then
  log "Respaldando la base en $dump..."
  if docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > "$dump.part" && [ -s "$dump.part" ]; then
    mv "$dump.part" "$dump"
  else
    rm -f "$dump.part"
    fail "no se pudo respaldar la base; no se actualiza"
  fi
  # Solo se conservan los ultimos respaldos previos a actualizar.
  ls -1t backups/shinjisoc-*-antes-de-actualizar.dump 2>/dev/null | tail -n +"$((KEEP_PRE_UPDATE + 1))" | xargs -r rm -f
else
  log "La base no esta corriendo: se actualiza sin respaldo previo."
fi

panel_ok() {
  docker compose exec -T server python -c \
    "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=5).status == 200 else 1)" \
    >/dev/null 2>&1
}

deploy() {
  docker compose up -d --build --remove-orphans || return 1
  local waited=0
  until panel_ok; do
    [ "$waited" -ge "$HEALTH_TIMEOUT" ] && return 1
    sleep 5
    waited=$((waited + 5))
  done
}

g merge --quiet --ff-only "origin/$branch" || fail "no se pudo avanzar (git merge --ff-only)"
log "Reconstruyendo y reiniciando los contenedores..."
if deploy; then
  docker image prune -f >/dev/null 2>&1 || true   # imagenes viejas que dejan las reconstrucciones
  rm -f "$FAILED_FILE"
  log "Actualizado a ${latest:0:7}; el panel responde."
  if [ -n "$agent_changed" ]; then
    log "AVISO: cambio el agente. Reinstalalo en cada servidor vigilado (docs/AGENTE.md, \"Reinstalar\")."
  fi
  exit 0
fi

log "El panel no respondio en ${HEALTH_TIMEOUT} s con la version nueva: vuelvo a ${current:0:7}." >&2
g reset --quiet --hard "$current"
echo "$latest" > "$FAILED_FILE"
if deploy; then
  fail "actualizacion revertida; el panel volvio a la version anterior. Revisa: docker compose logs server"
fi
fail "la version anterior tampoco responde. Revisa: docker compose logs server (respaldo de la base: $dump)"
