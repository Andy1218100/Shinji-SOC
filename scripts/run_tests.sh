#!/usr/bin/env bash
# Corre todos los tests: los del servidor dentro de su contenedor y los del
# agente con el Python de este equipo. Solo usan unittest (biblioteca
# estandar): no hay que instalar nada.
#
#   bash scripts/run_tests.sh
set -uo pipefail
cd "$(dirname "$0")/.."

status=0

echo "== Servidor (contenedor server) =="
docker compose exec -T server python -m unittest discover -s tests -t . || status=1

echo
echo "== Agente =="
# En Windows "python3" puede ser el atajo de la Microsoft Store, que existe
# pero no ejecuta nada: se usa el primero que realmente corre.
py=""
for candidate in python3 python; do
  if "$candidate" -c "import sys" >/dev/null 2>&1; then py="$candidate"; break; fi
done
if [ -z "$py" ]; then
  echo "No hay un Python que funcione para los tests del agente." >&2
  status=1
else
  "$py" -I -m unittest discover -s agent/tests || status=1
fi

echo
[ "$status" -eq 0 ] && echo "Todos los tests pasaron." || echo "Hay tests que fallaron (ver arriba)."
exit "$status"
