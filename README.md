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
inventario de paquetes instalados (`dpkg`), con el paquete fuente de
Debian de cada binario. OSV indexa por fuente: consultando por binario,
`libssl3t64` devuelve 0 avisos y `openssl` 294, y `libc6` (glibc) no
se revisaba. Los agentes anteriores a este cambio siguen funcionando,
pero con esa cobertura parcial hasta que se reinstalen. El servidor lo cruza contra
[OSV.dev](https://osv.dev) (base de datos de CVEs real, gratis, sin
cuenta) y, por cada paquete afectado, pide a la IA una recomendacion de
2-3 frases (actualizar, o como mitigar si todavia no hay parche) **a
partir de los datos que ya trajo de OSV** -- la IA nunca decide por su
cuenta si algo es vulnerable. Es una recomendacion por paquete, no por
CVE: en un host real habia 716 CVEs en 97 paquetes (108 solo en
`imagemagick`), y con un modelo chico en CPU (~20s por respuesta) una
por CVE eran horas. Se ve en `/vulnerabilities`, una fila por paquete
con sus CVEs desplegables.

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
- La recomendacion de IA puede inventar un numero de version o un CVE
  que no le dimos (es un modelo de 3B). El servidor rechaza la respuesta
  si cita CVEs o versiones que no estan en los datos de OSV y la pide de
  nuevo; si vuelve a fallar, guarda un texto fijo (marcado "generada sin
  IA") y lo reintenta en el escaneo siguiente. El chequeo mira
  identificadores, no el sentido del texto: el campo `fixed_version`
  sigue siendo el dato real que vino de OSV.dev.
- Muchos hallazgos no son explotables en la practica. OSV copia lo que
  marca el tracker de seguridad de Debian, y Debian deja como
  "vulnerable" en todas sus releases, sin version corregida, los CVEs que
  clasifica como `unimportant`. Por ejemplo, todos los de `binutils`,
  porque ese paquete "not covered by security support"
  (https://security-tracker.debian.org/tracker/CVE-2017-13716). Por eso
  un CVE de binutils 2.29 aparece contra 2.44. En un Proxmox real, 174
  de 591 hallazgos eran `unimportant` y 417 todavia no tenian urgencia
  asignada. Prox Secure guarda esa urgencia: los paquetes con todos sus
  CVEs `unimportant` van a una seccion colapsada en `/vulnerabilities` y
  reciben un texto fijo, sin IA. Los paquetes compilados por Proxmox
  (version con `pve`, como `frr 10.6.1-1+pve3`) se marcan aparte,
  porque OSV los compara contra el paquete de Debian, que es otra version.
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

Desde el dashboard: en `/` (Monitoreo), boton **"+ Nuevo host"** (solo
admin). Al crearlo se muestra, una sola vez, el comando exacto para
instalar el agente (con la URL del servidor y la API key ya completas) --
ver la seccion siguiente para lo que hace falta hacer en el servidor
real.

O por API, si preferis scriptearlo:

```bash
curl -X POST http://localhost:8000/api/v1/hosts \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"name": "web-01", "hostname": "web-01.midominio.com", "ip_address": "10.0.0.5"}'
```

La respuesta incluye `api_key`: es la que usa el agente de ese host para
autenticarse (header `X-API-Key`) al mandar metricas, logs, inventario e
informe de sistema. No se vuelve a mostrar -- si se pierde, hay que
reinstalar el agente con una key nueva (`reset` no existe para hosts,
a diferencia de usuarios).

## Instalar el agente en un servidor Linux remoto

`agent/install.sh` es autocontenido: trae adentro el codigo del agente
entero (generado por `agent/_build_install.sh`), asi que alcanza con
copiar ese UN archivo al servidor -- no hace falta `scp -r` la carpeta
`agent/` completa ni armar un zip a mano.

```bash
scp agent/install.sh usuario@servidor:/tmp/install.sh
ssh usuario@servidor
sudo bash /tmp/install.sh http://TU_SERVIDOR:8000 LA_API_KEY_DEL_HOST
```

(si preferis evitar el scp, tambien sirve pegar el contenido de
`install.sh` a mano en el servidor, por ejemplo con `nano`/`vi`, o
bajarlo por `curl`/`wget` si lo subiste a algun lado vos mismo -- es un
archivo de texto comun, sin dependencias externas)

El script se vale solo: instala `python3`/`python3-venv`/`python3-pip`,
`sudo` y `fail2ban` via `apt` si no estan (no hace falta preparar nada a
mano en el servidor), crea un usuario de sistema sin privilegios (en el
grupo `adm`, para poder leer logs del sistema), escribe el codigo del
agente en `/opt/prox-secure-agent`, arma el virtualenv con sus
dependencias, el sudoers acotado (`/etc/sudoers.d/prox-secure-agent`,
solo permite `fail2ban-client set * banip/unbanip *` y el wrapper
`kill_process.sh`) y un servicio systemd (`prox-secure-agent`) con el
agente completo (descubrimiento + metricas + logs + procesos +
inventario + comandos). Necesita ejecutarse con `bash` (`sudo bash
install.sh ...`), no con `sh`/`dash` -- usa `$EUID`, que esos shells no
soportan.

**Si tocas el codigo del agente** (cualquier archivo en `agent/`), hay
que regenerar `install.sh` antes de commitear -- el contenido embebido
no se actualiza solo:

```bash
cd agent && bash _build_install.sh
```

### Descubrimiento automatico (personalizado por host)

Lo primero que hace el agente al arrancar es describir el sistema:
sistema operativo, hardware, servicios corriendo (nginx, postgres,
redis, etc.), puertos en escucha, y a partir de eso **detecta solo**
que logs y que cuentas de servicio tiene sentido vigilar *en ese host
en particular* -- no hace falta editar `log_paths` ni
`process_watch.service_users` a mano para cada maquina. El servidor
arma ademas un informe en lenguaje natural con la IA local, visible en
la pagina del host (`/hosts/<id>`).

- **Logs**: ademas de los paths fijos conocidos de nginx/apache, el
  agente busca cualquier archivo cuyo nombre tenga `.log`/`.logs`, o que
  viva dentro de una carpeta llamada `log`/`logs`, en `/var/log`, `/opt`,
  `/srv`, `/home` y `/root` (nunca en toda la raiz del sistema). Esto
  encuentra logs de aplicaciones no estandar (paneles como AMP, apps
  caseras, etc.) ademas de los de nginx/apache. Que un archivo aparezca
  ahi no significa que el IDS vaya a sacarle algo util -- las lineas que
  no tengan formato "combined" de acceso HTTP se ignoran solas, sin
  error, asi que el costo de vigilar uno que no sirve es nomas un poco
  de I/O de mas.

  El escaneo ignora a proposito arboles que son ruido garantizado y
  pueden ser enormes: storage de imagenes de Docker/Podman
  (`containers/storage`), `.cache`, `node_modules`, `.git`,
  `__pycache__`. Esto no es cosmetico: en un servidor real con varias
  imagenes de contenedores bajadas, el storage de Podman por si solo
  tenia miles de carpetas (cada capa de cada imagen duplica un
  filesystem entero, con su propio `/var/log` adentro) y agotaba el
  presupuesto de busqueda antes de llegar a los logs reales de la app.
  Entre las carpetas que no son ruido conocido, prioriza primero las
  que tengan "log" en el nombre.

  El presupuesto de busqueda es por carpeta raiz (`/var/log`, `/opt`,
  `/srv`, `/home`, `/root`), no uno solo compartido entre las cinco --
  si una sola tuviera contenido real enorme (medido en un servidor real:
  `/home` con mas de 112.000 carpetas, instalaciones completas de
  varios servidores de juego) no debe poder dejar a las demas sin
  presupuesto. `os.walk` recorre del orden de 50.000 carpetas/segundo,
  asi que hasta un arbol de ese tamano se recorre en un par de segundos
  -- costo unico al arrancar el agente o 1 vez al dia, no en un loop
  caliente.

  Encontrar un archivo y poder leerlo son dos cosas distintas: si una
  app guarda sus logs en una carpeta con permisos cerrados (0700, solo
  el dueno) el agente no la puede ni abrir. El informe del host
  (`/hosts/<id>`) separa esto en dos listas especificas -- "logs
  encontrados pero sin permiso" y "carpetas que no se pudieron ni
  abrir" -- en vez de fallar en silencio.

  Cada item de esas dos listas tiene un boton "Dar acceso" (solo
  visible para admin). Pide el codigo MFA del admin para confirmar
  (igual que eliminar un host) y, si es correcto, crea un comando que
  el agente ejecuta via `sudo` con `setfacl` (`grant_log_access.sh`):
  le da a `prox-secure` permiso de **lectura puntual** (ACL `r`/`rX`,
  mas ACL default si es carpeta) sobre esa ruta especifica, sin tocar
  duenos ni los permisos Unix existentes y sin agregar escritura ni
  ejecucion de binarios. El servidor valida que la ruta pedida sea una
  de las que el ultimo informe de ESE host reporto como bloqueada (no
  cualquier ruta arbitraria), y el script del agente ademas solo acepta
  rutas bajo `/var/log`, `/opt`, `/srv` o `/home` -- `/root` esta
  excluido siempre, incluso si se lo pide a mano via API. Apenas el
  agente termina el otorgamiento reenvia el informe de sistema al toque
  (no espera al ciclo diario), asi en segundos se ve el log que antes
  estaba bloqueado pasar a la lista de "Logs que vigila".

  Si se prefiere hacerlo a mano en vez de usar el boton: agregar
  `prox-secure` al grupo dueno de esos archivos, o usar `setfacl`
  directamente si el directorio es de un solo usuario.
- **Cuentas de servicio**: cualquier cuenta de sistema (por convencion
  Debian/Ubuntu: UID menor a 1000, o shell `nologin`/`false`) que tenga
  un proceso corriendo en este momento -- no una lista fija de nombres
  conocidos. Se excluyen `root` (ejecutar lo que sea no es una anomalia
  para el superusuario) y la propia cuenta del agente.

Si un setup no es estandar (logs en otro lado que el autodescubrimiento
no encontro, o una cuenta que no cumple esas condiciones), se puede
seguir fijando `log_paths`/`process_watch.service_users` a mano en
`/opt/prox-secure-agent/config.yaml` (ver `agent/config.example.yaml`)
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
OSV.dev, y una vez al arrancar el servidor (para forzar un escaneo:
`docker compose restart server`). El primer escaneo util necesita que el
agente ya haya mandado al menos un inventario -- no hay nada que ver en
`/vulnerabilities` hasta entonces.

Un CVE que OSV deja de reportar para la version instalada (porque se
actualizo o desinstalo el paquete) pasa solo a `resolved` en el
siguiente escaneo; si vuelve a aparecer, vuelve a `open`. La "version
corregida" es la de la release Debian del host (OSV publica un fix
distinto por release: el de Debian 12 no sirve en un Debian 13). Los
paquetes de repos de terceros (`pve-*`/`proxmox-*` en Proxmox, por
ejemplo) no estan en el ecosistema Debian de OSV y no se revisan.

En `/vulnerabilities`:
- **Escanear ahora** (admin) le pide al agente el inventario actual con
  el comando `send_inventory`, y el servidor escanea apenas lo recibe. Sirve
  despues de un `apt upgrade`. Cada inventario que llega dispara un escaneo
  de ese host.
- **Con solucion disponible** son los paquetes con version corregida. Son
  los unicos que cuentan en el aviso del menu lateral.
- **Sin solucion todavia** es un aviso: Debian no publico parche, asi que
  no hay nada que actualizar hoy.
- **Sin importancia o no aplican** reune los `unimportant` y los CVEs del
  kernel de Debian cuando solo estan sus cabeceras (`linux-libc-dev`): en
  Proxmox el kernel en uso es `proxmox-kernel`, que OSV no cubre.
- **Resueltas** muestra lo que dejo de aplicar, con el motivo ("actualizado
  a X" o "paquete desinstalado") y la fecha.

## IA: Ollama local vs Claude

Por defecto todo pasa por Ollama (`AI_BACKEND=ollama`, modelo en
`OLLAMA_MODEL`). Si configuras `ANTHROPIC_API_KEY`, puedes pedir una
respuesta puntual con Claude pasando `"backend": "claude"` en
`POST /api/v1/ai/ask`, o cambiar `AI_BACKEND=claude` para que tambien se
use en la explicacion automatica de alertas.

Toda respuesta de Ollama pasa por una validacion antes de guardarse o
mostrarse:
- **Tope de tokens:** se rechaza la respuesta si llega a `num_predict`
  (512) sin terminar.
- **Alfabetos:** se rechaza si trae texto en otros alfabetos.

Si una respuesta se rechaza, se reintenta una vez con el prompt
recalculado desde cero. Esto existe porque, probado en una PC con
Windows y Docker Desktop, el modelo a veces devolvio basura (mezcla de
alfabetos y fragmentos de codigo) que no dependia del prompt. La causa
de fondo no esta identificada. Una parte se debia a la cache de prompts
en RAM de llama-server, que reutilizaba estados corruptos; por eso
`docker-compose.yml` la desactiva con `LLAMA_ARG_CACHE_RAM=0`.

Ollama en CPU usa todos los nucleos mientras genera, y el escaneo de
vulnerabilidades puede pedirle decenas de respuestas seguidas. En una PC
de escritorio eso son minutos de CPU al 100%. Para limitar los nucleos
solo en esa maquina, crea un `docker-compose.override.yml` (ya esta en
`.gitignore`; Compose lo carga solo) y despues corre
`docker compose up -d ollama`:

```yaml
services:
  ollama:
    cpus: "4"
```

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
