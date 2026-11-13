#!/usr/bin/env bash
# Mata un proceso SOLO si su cmdline actual todavia contiene la cadena
# esperada, para evitar matar un PID reciclado que ya no es el proceso
# que disparo la alerta. Pensado para correr via sudo (ver sudoers/).
set -euo pipefail

PID="${1:?uso: kill_process.sh <pid> <substring_esperado>}"
EXPECTED="${2:-}"

if [[ ! -r "/proc/$PID/cmdline" ]]; then
  echo "pid $PID ya no existe" >&2
  exit 1
fi

CMDLINE=$(tr '\0' ' ' < "/proc/$PID/cmdline")

if [[ -n "$EXPECTED" && "$CMDLINE" != *"$EXPECTED"* ]]; then
  echo "cmdline actual ('$CMDLINE') no coincide con lo esperado, aborto por seguridad" >&2
  exit 2
fi

kill -9 "$PID"
echo "pid $PID terminado (cmdline: $CMDLINE)"
