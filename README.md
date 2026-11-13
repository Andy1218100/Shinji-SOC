# Prox Secure

Sistema propio de monitoreo y analisis de servidores (estilo Zabbix), con
IA local (Ollama) y conexion opcional a Claude para analisis mas profundo.

## Componentes

- `server/`: API + dashboard (FastAPI, Python). Recibe metricas, evalua
  reglas de alerta, guarda todo en PostgreSQL/TimescaleDB y expone un
  endpoint de IA para preguntar sobre el estado de los hosts.
- `agent/`: agente liviano (Python + psutil) que se instala en cada
  servidor Linux a monitorear y envia metricas al servidor central.
- `docker-compose.yml`: levanta base de datos, Ollama y el servidor.

## Requisitos

- Docker Desktop (con el motor corriendo).
- Python 3.12 (para desarrollo local fuera de contenedores, opcional).

## Levantar el stack localmente (Windows/Linux, via Docker)

```bash
cp .env.example .env
# editar .env: contrasenas, ADMIN_API_KEY, y si quieres Claude, ANTHROPIC_API_KEY
docker compose up -d
docker compose exec ollama ollama pull llama3.1:8b
```

El dashboard queda en http://localhost:8000

## Registrar un host a monitorear

```bash
curl -X POST http://localhost:8000/api/v1/hosts \
  -H "X-Admin-Key: TU_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "web-01", "hostname": "web-01.midominio.com", "ip_address": "10.0.0.5"}'
```

La respuesta incluye `api_key`: es la que usa el agente de ese host para
autenticarse al enviar metricas.

## Instalar el agente en un servidor Linux remoto

```bash
scp -r agent usuario@servidor:/tmp/prox-secure-agent
ssh usuario@servidor
cd /tmp/prox-secure-agent
sudo ./install.sh http://TU_SERVIDOR:8000 LA_API_KEY_DEL_HOST
```

Esto crea un usuario de sistema, un virtualenv y un servicio systemd
(`prox-secure-agent`) que corre el recolector en loop.

## Reglas de alerta

```bash
curl -X POST http://localhost:8000/api/v1/alert-rules \
  -H "X-Admin-Key: TU_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "CPU alta", "metric_field": "cpu_percent", "operator": ">", "threshold": 90, "severity": "critical"}'
```

Un rule sin `host_id` aplica a todos los hosts. El servidor evalua las
reglas cada `ALERT_EVAL_INTERVAL_SECONDS` (30s por defecto) y, al disparar
una alerta, pide al backend de IA configurado (Ollama por defecto) un
resumen de causa probable y accion recomendada.

## IA: Ollama local vs Claude

Por defecto todo pasa por Ollama (`AI_BACKEND=ollama`, modelo en
`OLLAMA_MODEL`). Si configuras `ANTHROPIC_API_KEY`, puedes pedir una
respuesta puntual con Claude pasando `"backend": "claude"` en
`POST /api/v1/ai/ask`, o cambiar `AI_BACKEND=claude` para que tambien se
use en la explicacion automatica de alertas.

## Desarrollo local sin Docker (opcional)

```bash
cd server
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Requiere que `db` y `ollama` sigan corriendo via `docker compose up db ollama`.

## Despliegue en Linux

El mismo `docker-compose.yml` corre igual en un servidor Linux con Docker
instalado: `git clone`, `.env`, `docker compose up -d`. El agente se
instala por separado en cada host a monitorear (ver arriba).
