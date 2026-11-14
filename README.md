# Prox Secure

Sistema propio de monitoreo y SOC (centro de operaciones de seguridad)
para servidores propios, con IA local (Ollama) y conexion opcional a
Claude para analisis mas profundo.

## Que hace

**Monitoreo** (estilo Zabbix): metricas de CPU/mem/disco/red por host,
reglas de alerta con umbral, explicacion automatica por IA.

**SOC**: ademas de metricas, el agente puede leer los logs de acceso del
servidor web y vigilar procesos de cuentas de servicio (www-data, nginx,
etc.). El servidor corre un motor de deteccion **heuristico** (reglas +
conteos, no un modelo de ML entrenado) que marca:
- escaneo de rutas sensibles (`/wp-admin`, `.env`, `.git`, etc.) y oleadas
  de 404 de una misma IP;
- fuerza bruta / flood (demasiadas requests de una IP en poco tiempo);
- procesos sospechosos bajo cuentas de servicio (ej. `www-data` lanzando
  `bash`/`wget`/`python` = posible webshell).

Cada deteccion genera un evento con una explicacion en lenguaje natural
(IA) y una accion sugerida (bloquear IP o matar el proceso), geolocalizada
en un mapa interactivo (con clusters y metricas: total, criticos,
origenes mas activos) si configuras GeoIP. **Nada se bloquea solo**: el
administrador aprueba cada accion desde `/security` y ahi se ejecuta.

**Vulnerabilidades de software**: el agente reporta una vez al dia el
inventario de paquetes instalados (`dpkg`). El servidor lo cruza contra
[OSV.dev](https://osv.dev) (base de datos de CVEs real, gratis, sin
cuenta) y, por cada vulnerabilidad real que encuentra, pide a la IA una
recomendacion de 2-3 frases (que version instalar, o como mitigar si
todavia no hay parche) **a partir de los datos que ya trajo de OSV** --
la IA nunca decide por su cuenta si algo es vulnerable. Se ve en
`/vulnerabilities`.

**Acceso**: cuentas individuales (usuario + contrasena + MFA por TOTP),
con rol admin o solo lectura. Nada de clave compartida. Gestion de
usuarios en `/users`. Ver la seccion "Acceso" mas abajo.

## Limitaciones reales (leer antes de confiar en esto en produccion)

- El "aprendizaje" es acumular listas y contar eventos en ventanas de
  tiempo, no un modelo entrenado. Con trafico legitimo raro puede haber
  falsos positivos (y falsos negativos frente a ataques mas sofisticados).
- El parser de logs solo entiende el formato "combined" de nginx/apache.
  Otro formato no se va a parsear (se ignora esa linea).
- La vigilancia de procesos es una lista fija de binarios "sospechosos"
  (`bash`, `wget`, `python`, etc.). Una app que legitimamente hace
  `shell_exec` va a generar falsos positivos; por eso requiere aprobacion
  manual, no bloquea/mata solo.
- El bloqueo usa fail2ban con un jail dedicado (`proxsecure`) que no tiene
  deteccion propia, solo recibe bloqueos manuales desde el panel. Requiere
  fail2ban instalado en el host (lo instala `install.sh`).
- Login con usuario + contrasena + MFA (TOTP), cuentas con rol admin o
  solo lectura -- ver la seccion de abajo. No hay recuperacion de
  contrasena por email (no hay servicio de correo en el proyecto): si
  alguien se queda afuera, un admin le resetea la contrasena desde
  `/users`. Tampoco hay log de auditoria de quien aprobo que accion.
  Igual que siempre: pensado para uso propio en red interna, no para
  exponer el dashboard a internet sin un proxy con HTTPS adelante (y en
  ese caso, poner `SESSION_COOKIE_SECURE=true`).
- El mapa de ataques necesita que configures una license key de MaxMind
  (gratis); sin eso, los eventos se ven en la lista pero sin punto en el
  mapa.
- El escaneo de vulnerabilidades necesita que el agente reporte primero
  su version de Debian (`/etc/os-release`); sin eso, ese host se
  salta el escaneo a proposito en vez de arriesgar comparar versiones
  contra el ecosistema equivocado de OSV.dev (Debian:11 vs Debian:12,
  por ejemplo) y generar falsos positivos/negativos.
- La recomendacion de IA a veces inventa un numero de version que no
  le dimos, aun con la instruccion explicita de no hacerlo (es un
  modelo de 3B, no es perfecto). El campo `fixed_version` es el dato
  real que vino de OSV.dev; si el texto de la IA menciona otra version,
  confiar en `fixed_version`, no en la prosa.
- No hay sistema de migraciones (Alembic ni similar): `create_all` solo
  crea tablas nuevas, nunca agrega columnas a una tabla existente. Si
  actualizas desde una base de datos vieja y algo tira
  `UndefinedColumnError`, hay que alterar la tabla a mano o recrear el
  volumen de Postgres.

## Componentes

- `server/`: API + dashboard (FastAPI, Python). Recibe metricas, logs e
  inventario de paquetes, evalua reglas de alerta y el motor IDS, cruza
  el inventario contra OSV.dev una vez al dia, guarda todo en
  PostgreSQL/TimescaleDB, resuelve GeoIP y expone un endpoint de IA para
  preguntar sobre el estado de los hosts.
- `agent/`: agente Python (un solo proceso, varias tareas async) que se
  instala en cada servidor Linux: se autodescubre al arrancar (SO,
  hardware, servicios, puertos) para personalizar que vigila, envia
  metricas, lee logs de acceso, vigila procesos de cuentas de servicio,
  reporta el inventario de paquetes (`dpkg`) y ejecuta (via sudo acotado)
  los bloqueos/kills que
  el administrador aprueba.
- `docker-compose.yml`: levanta base de datos, Ollama y el servidor.

## Requisitos

- Docker Desktop (con el motor corriendo).
- Python 3.12 (para desarrollo local fuera de contenedores, opcional).

## Levantar el stack localmente (Windows/Linux, via Docker)

```bash
cp .env.example .env
# editar .env: contrasenas, SESSION_SECRET_KEY (openssl rand -hex 32), y si quieres Claude, ANTHROPIC_API_KEY
docker compose up -d
docker compose exec ollama ollama pull qwen2.5:3b
docker compose exec server python create_first_admin.py tu_usuario
```

El ultimo comando te da un usuario y una contrasena temporal (se
muestran una sola vez). Entra a http://localhost:8000/login con eso: el
primer login te va a pedir una contrasena nueva y enrolar MFA (ver
abajo). El dashboard queda en http://localhost:8000 (monitoreo),
http://localhost:8000/security (SOC) y http://localhost:8000/users
(gestion de cuentas).

> **Nota sobre el modelo de IA**: usamos `qwen2.5:3b` por defecto, no un
> modelo mas grande como `llama3.1:8b`. En esta maquina, sin GPU,
> `llama3.1:8b` tardo **~9 minutos** en responder una sola pregunta via
> Ollama (medido con `ollama ps`/tiempo real) e inutiliza cualquier
> alerta en tiempo real. `qwen2.5:3b` responde en pocos segundos. Si tu
> servidor tiene GPU, podes cambiar `OLLAMA_MODEL` por uno mas grande.

### Mapa de ataques (opcional, GeoIP)

```bash
# 1. Cuenta gratuita + license key: https://www.maxmind.com/en/geolite2/signup
# 2. Agregar MAXMIND_ACCOUNT_ID=... y MAXMIND_LICENSE_KEY=... en .env
#    (el Account ID aparece arriba a la izquierda en tu cuenta de MaxMind)
./scripts/update_geoip_db.sh
docker compose restart server
```

El mapa (`/security`) se actualiza solo en tiempo real via Server-Sent
Events (sin polling): apenas el IDS crea un evento nuevo, el dashboard lo
recibe al instante. Los origenes de ataque se dibujan como puntos
agrupados (clusters); si el host atacado tambien tiene una IP publica
geolocalizable (campo `ip_address` al registrarlo), se dibuja ademas un
arco animado desde el origen hasta ese host. Sin GeoIP configurado, o con
hosts en IP privada, los eventos siguen apareciendo en la lista, solo que
sin punto ni arco en el mapa -- nunca se inventa una ubicacion.

## Acceso: usuarios, contrasenas y MFA

No hay mas clave compartida: cada persona tiene su propia cuenta
(usuario + contrasena + MFA por TOTP -- Google Authenticator, Authy,
etc., codigo de 6 digitos). Dos roles: `admin` (ve todo, aprueba/bloquea,
gestiona usuarios) y `viewer` (ve todo, no puede actuar).

**Primer usuario**: `docker compose exec server python create_first_admin.py tu_usuario`
(ver arriba). Es el unico momento donde hace falta tocar la terminal --
todo lo demas se gestiona desde `/users` una vez que ese primer admin
entro.

Desde `/users`, un admin puede desactivar, reactivar, resetear la
contrasena o **eliminar** una cuenta de forma permanente. No se puede
eliminar la propia cuenta ni una cuenta que ya creo a otras (hay que
desactivarla en ese caso, para no dejar el registro `created_by` roto).

**Crear mas cuentas**: un admin logueado va a `/users`, pone el nombre y
el rol, y el sistema genera una contrasena temporal que se muestra **una
sola vez** (copiarla y pasarla por un canal seguro). Esa persona entra
con esa contrasena, y el primer login la obliga a elegir una contrasena
propia y enrolar su MFA (se le muestra el QR a ella, nunca al admin que
creo la cuenta).

**Sesiones**: cookie firmada (`itsdangerous`), `HttpOnly` + `SameSite=Lax`,
24h por defecto (`SESSION_MAX_AGE_SECONDS`). 5 intentos fallidos
(contrasena o codigo MFA) bloquean la cuenta 5 minutos
(`LOGIN_MAX_ATTEMPTS` / `LOGIN_LOCKOUT_SECONDS`).

**Scripts/automatizacion**: ya no existe una API key fija para esto. Para
llamar la API desde un script, logueate con curl guardando las cookies y
usalas en las siguientes llamadas:

```bash
# 1. login (devuelve pending_token; si la cuenta ya tiene MFA, stage="mfa")
curl -c cookies.txt -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "tu_usuario", "password": "tu_contrasena"}'

# 2. completar con el codigo de tu app de autenticacion
curl -c cookies.txt -b cookies.txt -X POST http://localhost:8000/api/v1/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{"pending_token": "EL_PENDING_TOKEN", "code": "123456"}'

# 3. de ahi en adelante, reusar cookies.txt
curl -b cookies.txt http://localhost:8000/api/v1/hosts
```

## Registrar un host a monitorear

```bash
curl -X POST http://localhost:8000/api/v1/hosts \
  -b cookies.txt \
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

Esto crea un usuario de sistema sin privilegios (en el grupo `adm`, para
poder leer logs del sistema), instala fail2ban, un virtualenv, el
sudoers acotado (`/etc/sudoers.d/prox-secure-agent`, solo permite
`fail2ban-client set * banip/unbanip *` y el wrapper `kill_process.sh`)
y un servicio systemd (`prox-secure-agent`) con el agente completo
(descubrimiento + metricas + logs + procesos + inventario + comandos).

### Descubrimiento automatico (personalizado por host)

Lo primero que hace el agente al arrancar es describir el sistema:
sistema operativo, hardware, servicios corriendo (nginx, postgres,
redis, etc.), puertos en escucha, y a partir de eso **detecta solo**
que logs de servidor web y que cuentas de servicio tiene sentido vigilar
*en ese host en particular* -- no hace falta editar `log_paths` ni
`process_watch.service_users` a mano para cada maquina. El servidor
arma ademas un informe en lenguaje natural con la IA local, visible en
la pagina del host (`/hosts/<id>`).

Si un setup no es estandar (logs en otro lado, otra cuenta de servicio),
se puede seguir fijando `log_paths`/`process_watch.service_users` a mano
en `/opt/prox-secure-agent/config.yaml` (ver `agent/config.example.yaml`)
-- lo que se defina ahi gana siempre sobre lo autodetectado. Despues de
cualquier cambio: `systemctl restart prox-secure-agent`.

## Eventos de seguridad: ver, aprobar, bloquear

```bash
# ver eventos abiertos (requiere login, ver seccion de Acceso arriba)
curl -b cookies.txt http://localhost:8000/api/v1/security-events?status=open

# aprobar la accion sugerida (bloquear IP o matar el proceso) -- requiere rol admin
curl -b cookies.txt -X POST http://localhost:8000/api/v1/security-events/EVENT_ID/approve

# descartar sin actuar
curl -b cookies.txt -X POST http://localhost:8000/api/v1/security-events/EVENT_ID/dismiss
```

Al aprobar, el servidor deja un "comando" en cola para ese host; el
agente lo recoge en su siguiente ciclo (cada
`command_poll_interval_seconds`, 10s por defecto) y lo ejecuta. Lo mismo
desde el dashboard en `/security`.

## Reglas de alerta

```bash
curl -b cookies.txt -X POST http://localhost:8000/api/v1/alert-rules \
  -H "Content-Type: application/json" \
  -d '{"name": "CPU alta", "metric_field": "cpu_percent", "operator": ">", "threshold": 90, "severity": "critical"}'
```

Un rule sin `host_id` aplica a todos los hosts. El servidor evalua las
reglas cada `ALERT_EVAL_INTERVAL_SECONDS` (30s por defecto) y, al disparar
una alerta, pide al backend de IA configurado (Ollama por defecto) un
resumen de causa probable y accion recomendada.

## Vulnerabilidades de software

```bash
# estado del inventario por host
curl -b cookies.txt http://localhost:8000/api/v1/inventory/status

# vulnerabilidades encontradas
curl -b cookies.txt http://localhost:8000/api/v1/vulnerabilities

# marcar como revisada (no hay "arreglar" automatico, es informativo) -- requiere rol admin
curl -b cookies.txt -X POST http://localhost:8000/api/v1/vulnerabilities/FINDING_ID/acknowledge
```

El agente manda el inventario de paquetes cada `inventory_interval_seconds`
(1 dia por defecto, `agent/config.example.yaml`). El servidor escanea
todos los hosts cada `VULN_SCAN_INTERVAL_SECONDS` (tambien 1 dia) contra
OSV.dev. El primer escaneo util necesita que el agente ya haya mandado
al menos un inventario -- no hay nada que ver en `/vulnerabilities`
hasta entonces.

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
