# Referencia técnica de Shinji SOC

Cómo funciona cada parte, qué límites tiene y cómo usar la API. Para instalar, ver el [manual de instalación](INSTALACION.md); para el inicio de sesión, el [manual de MFA](MFA.md).

- [Componentes](#componentes)
- [Detección de intrusos](#detección-de-intrusos)
- [Eventos de seguridad y bloqueos](#eventos-de-seguridad-y-bloqueos)
- [Descubrimiento automático del agente](#descubrimiento-automático-del-agente)
- [Vulnerabilidades de software](#vulnerabilidades-de-software)
- [Reglas de alerta](#reglas-de-alerta)
- [Mapa de ataques](#mapa-de-ataques)
- [IA: Ollama local o Claude](#ia-ollama-local-o-claude)
- [Auditoría de la IA local con Claude Code (MCP)](#auditoría-de-la-ia-local-con-claude-code-mcp)
- [Configuración desde el panel](#configuración-desde-el-panel)
- [Notificaciones](#notificaciones)
- [Retención de datos](#retención-de-datos)
- [Respaldos](#respaldos)
- [Cuentas, sesiones y MFA](#cuentas-sesiones-y-mfa)
- [Usar la API desde scripts](#usar-la-api-desde-scripts)
- [Actualizar versiones](#actualizar-versiones)
- [Desarrollo](#desarrollo)
- [Tests](#tests)
- [Simulación de ataques](#simulación-de-ataques)
- [Limitaciones conocidas](#limitaciones-conocidas)

## Componentes

| Carpeta | Qué es |
|---|---|
| `server/` | Panel y API (FastAPI, Python 3.12). Recibe métricas, logs, inventario e informes; evalúa reglas de alerta y el motor de detección; cruza el inventario contra OSV.dev; guarda todo en PostgreSQL/TimescaleDB. |
| `agent/` | Agente Python para cada servidor vigilado: un proceso con varias tareas (métricas, logs, inicios de sesión, procesos, inventario, comandos). `install.sh` lo trae embebido. |
| `caddy/` | HTTPS delante del panel. |
| `scripts/` | Respaldos, restauración, descarga de GeoIP y tests. |
| `tools/mcp_audit/` | Servidor MCP para auditar la IA local con Claude Code. |

Servicios de `docker-compose.yml`: `db` (TimescaleDB), `ollama` (IA local), `server`, `caddy` y `backup`. Postgres (5432) y Ollama (11434) solo escuchan en `127.0.0.1`.

## Detección de intrusos

El motor es **heurístico**: reglas y conteos en ventanas de tiempo, no un modelo de aprendizaje automático. Marca:

| Evento | Criterio (valor por defecto) | Severidad |
|---|---|---|
| Escaneo de rutas | Pedido a una ruta sensible (`/.env`, `/.git`, `/wp-admin`…) o 15 respuestas 404 de una IP en 60 s | advertencia |
| Flood / fuerza bruta HTTP | 50 peticiones de una IP en 60 s | crítica |
| Fuerza bruta SSH | 5 inicios de sesión fallidos de una IP en 10 minutos | crítica si prueba `root` o triplica el umbral |
| Fuerza bruta en la web de Proxmox | El mismo criterio que SSH | igual que SSH |
| Inicio de sesión después de fallos | Un ingreso exitoso desde una IP que venía fallando (posible contraseña adivinada) | crítica |
| Proceso sospechoso | Una cuenta de servicio (`www-data`, `nginx`…) lanza `bash`, `wget`, `python`… (posible webshell) | según las señales |

Los umbrales se ajustan en **Configuración > Detección de intrusos**.

- **Logs web:** el agente lee los logs de acceso en formato *combined* de nginx/apache. Las líneas con otro formato se ignoran sin error.
- **Inicios de sesión:** salen del journal de systemd (`journalctl`), o de `/var/log/auth.log` si existe. Proxmox VE 8 en adelante no trae rsyslog ni `auth.log`. El agente manda solo los datos ya extraídos (cuándo, servicio, resultado, usuario, IP), nunca las líneas del log.

## Eventos de seguridad y bloqueos

Cada detección genera un evento con una explicación de la IA y una acción sugerida: bloquear la IP o terminar el proceso. **Nada se bloquea solo:** un admin aprueba cada acción en **Seguridad**. Al aprobar, el servidor deja un comando en cola; el agente lo recoge en su siguiente consulta (cada 10 s) y lo ejecuta.

El bloqueo usa fail2ban con un jail propio (`shinjisoc`) que no detecta nada por su cuenta: solo recibe los bloqueos aprobados en el panel. El agente corre como un usuario sin privilegios; su `sudoers` solo le permite `fail2ban-client set * banip/unbanip *`, terminar procesos con `kill_process.sh` y dar lectura a logs con `grant_log_access.sh`.

## Descubrimiento automático del agente

Al arrancar (y una vez al día), el agente describe el sistema: SO, hardware, servicios, puertos en escucha. A partir de eso decide qué vigilar en ese servidor, sin editar su configuración a mano. Con esos datos, la IA local escribe un informe que se ve en la página del servidor.

- **Logs:** además de las rutas conocidas de nginx/apache, busca archivos `.log` o dentro de carpetas `log`/`logs` en `/var/log`, `/opt`, `/srv`, `/home` y `/root`. Ignora árboles que solo traen ruido y pueden ser enormes (almacenamiento de imágenes de Docker/Podman, `.cache`, `node_modules`, `.git`). Cada carpeta raíz tiene su propio presupuesto de búsqueda, para que una carpeta enorme no deje sin revisar a las demás.
- **Logs sin permiso:** el informe separa "logs encontrados pero sin permiso" y "carpetas que no se pudieron abrir". El botón **Dar acceso** (admin, pide MFA) da al usuario del agente permiso de **solo lectura** (ACL) sobre esa ruta, sin tocar dueños ni permisos. El servidor solo acepta rutas que el último informe de ese servidor reportó como bloqueadas, y el agente solo bajo `/var/log`, `/opt`, `/srv` o `/home` (nunca `/root`).
- **Cuentas de servicio:** cualquier cuenta de sistema (UID menor a 1000, o shell `nologin`/`false`) con un proceso corriendo, salvo `root` y el propio agente.

Para fijar rutas o cuentas a mano, edita `/opt/shinji-soc-agent/config.yaml` (ver `agent/config.example.yaml`) y reinicia el servicio: lo que se fija ahí gana sobre lo detectado.

## Vulnerabilidades de software

El agente manda una vez al día el inventario de paquetes (`dpkg`), con el paquete fuente de Debian de cada binario. El servidor lo cruza contra [OSV.dev](https://osv.dev) (base de datos de vulnerabilidades, gratuita y sin cuenta) con el ecosistema de la versión de Debian del servidor. Después pide a la IA una recomendación de 2 o 3 frases por paquete, **a partir de los datos de OSV**: la IA nunca decide por su cuenta si algo es vulnerable.

- **Por paquete, no por CVE:** en un servidor real había 716 CVEs en 97 paquetes; con un modelo chico en CPU, una respuesta por CVE eran horas.
- **Por fuente, no por binario:** OSV indexa por paquete fuente. Consultando por binario, `libssl3t64` devolvía 0 avisos y `openssl` 294.
- **Dos fases:** primero los datos (consultas en paralelo; en un Proxmox con ~1500 paquetes, de más de 25 minutos a 6 segundos), después la IA, sin demorar los datos.

En **Vulnerabilidades**, una pestaña por servidor:

- **Escanear ahora** pide al agente el inventario actual y escanea apenas llega. Sirve después de un `apt upgrade`.
- **Con solución disponible:** paquetes con versión corregida. Son los únicos que suman en el aviso del menú lateral.
- **Sin solución todavía:** Debian no publicó parche; es solo un aviso.
- **Sin importancia o no aplican:** los que Debian marca `unimportant` y las cabeceras del kernel de Debian (`linux-libc-dev`) en Proxmox, que usa otro kernel.
- **Resueltas:** lo que dejó de aplicar, con el motivo ("actualizado a X" o "paquete desinstalado").

Muchos hallazgos no son explotables en la práctica: Debian deja como vulnerables, sin versión corregida, los CVEs que clasifica `unimportant` (por ejemplo, todos los de `binutils`, que [no tiene soporte de seguridad](https://security-tracker.debian.org/tracker/CVE-2017-13716)). Los paquetes compilados por Proxmox (versión con `pve`) se marcan aparte, porque OSV los compara contra el paquete de Debian. Los paquetes de repositorios de terceros no están en OSV y no se revisan.

## Reglas de alerta

Umbrales sobre las métricas (CPU, memoria, disco, red). Una regla sin servidor aplica a todos. El servidor las evalúa cada 30 s y, al dispararse una alerta, pide a la IA la causa probable y qué hacer.

```bash
curl -b cookies.txt -X POST https://localhost/api/v1/alert-rules \
  -H "Content-Type: application/json" \
  -d '{"name": "CPU alta", "metric_field": "cpu_percent", "operator": ">", "threshold": 90, "severity": "critical"}'
```

## Mapa de ataques

En **Seguridad**, cada evento con una IP de origen pública aparece en el mapa, agrupado en clusters. Si el servidor atacado tiene una IP pública geolocalizable (campo IP al crearlo), se dibuja además un arco del origen al servidor. El mapa muestra los últimos 10 minutos; la tabla de eventos conserva todo el historial. Las IPs privadas o reservadas nunca tienen ubicación: no se inventa ninguna.

La geolocalización usa la base gratuita GeoLite2 de MaxMind, en el propio servidor (sin consultas externas). Los mapas base son de Esri (World Dark Gray Canvas).

## IA: Ollama local o Claude

Por defecto todo pasa por Ollama, en el propio servidor (`AI_BACKEND=ollama`, modelo `qwen2.5:3b`). Con una API key de Anthropic se puede usar Claude como motor.

Cada respuesta de Ollama se valida antes de guardarse:

- se rechaza si llega al tope de 512 tokens sin terminar;
- se rechaza si trae texto en otros alfabetos;
- se rechaza si cita CVEs o versiones que no están en los datos de OSV.

Si una respuesta se rechaza, se pide de nuevo una vez. Si vuelve a fallar, se guarda un texto fijo marcado "generada sin IA", que se reintenta en el escaneo siguiente.

La caché de prompts en RAM de llama-server está desactivada (`LLAMA_ARG_CACHE_RAM=0` en `docker-compose.yml`): en las pruebas, entradas corruptas de esa caché hacían que el modelo devolviera basura para un mismo prompt hasta reiniciar Ollama.

## Auditoría de la IA local con Claude Code (MCP)

`tools/mcp_audit/server.py` es un servidor MCP que corre en el equipo del administrador, el que tiene Claude Code con su suscripción: no necesita API key de Anthropic. Solo usa la biblioteca estándar de Python.

1. **Informe:** `obtener_informe` trae un lote de textos de la IA local sin auditar (`vulnerabilidades`, `eventos` o `informes`) con los datos para juzgarlos. Lo arma el código, no la IA.
2. **Auditoría:** Claude los revisa con los criterios que trae la herramienta.
3. **Correcciones:** `enviar_auditoria` guarda un veredicto por item. Las correcciones reemplazan el texto y se marcan "corregida por Claude"; el servidor rechaza las que citen versiones o CVEs que no están en los datos.
4. **Reglas:** Claude puede dejar reglas cortas (hasta 50 activas) que la IA local agrega a sus prompts. Así mejora sin reentrenar el modelo.

**Datos minimizados**, pensando en la Ley 21.719 de Chile (no es una opinión legal):

- los servidores van como H1, H2…, sin nombres ni IPs;
- las IPs de origen van como seudónimos estables (`IP-3fa9c1`, HMAC con una clave del servidor);
- de la fuerza bruta SSH solo va cuántos usuarios se probaron y si fue `root`, nunca los nombres;
- no van user-agents, y las líneas de comando y rutas van sin IPs, correos ni nombres de `/home`.

Al guardar una corrección, los alias vuelven a ser el nombre y la IP reales.

**Activar:**

1. Genera el token en **Configuración > Inteligencia artificial > Auditoría con Claude Code**.
2. Registra el servidor MCP en Claude Code (lee el token del `.env` del proyecto):

   ```bash
   claude mcp add --scope user shinji-soc-audit -- python "/ruta/a/shinji-soc/tools/mcp_audit/server.py"
   ```

   Si el panel no está en `http://localhost:8000`, define `SHINJI_SOC_URL`.

3. En Claude Code, pide por ejemplo "audita las recomendaciones de Shinji SOC con shinji-soc-audit". Cada lote consume parte del límite de tu suscripción.

## Configuración desde el panel

**Configuración** (solo super admin) edita lo que antes había que cambiar en el `.env`: IA, auditoría, MaxMind, notificaciones, umbrales de detección, intervalos, retención, respaldos y sesiones.

- **Escritura:** reescribe el mismo `.env`, montado en el contenedor como `/config/.env`, conservando comentarios y orden, y aplica cada valor sin reiniciar.
- **Seguridad:** guardar pide el código MFA. Las claves nunca vuelven al navegador: solo si están configuradas y sus últimos 4 caracteres.
- **Solo en el `.env`:** `POSTGRES_*`, `DATABASE_URL` y `OLLAMA_HOST`. Mal puestos dejan la plataforma sin base de datos o sin IA, y no se podrían arreglar desde la propia página.

## Notificaciones

Por Telegram, ntfy o correo (SMTP); un canal sin datos no se usa. Avisan:

- eventos de seguridad desde la severidad elegida (por defecto, solo críticos);
- alertas de métricas;
- vulnerabilidades nuevas con solución publicada (un mensaje por escaneo);
- respaldos atrasados (como máximo una vez al día).

Se manda como máximo un aviso por tipo de evento y servidor cada 10 minutos. Los mensajes salen a servicios externos, así que por defecto no incluyen la IP de origen. En el ntfy.sh público, cualquiera que sepa el nombre del tema lee los mensajes.

## Retención de datos

Una purga diaria borra lo que crece sin límite (la primera, 10 minutos después de arrancar). Se ajusta en **Configuración > Retención de datos**, que muestra el tamaño de cada tabla y tiene el botón **Aplicar ahora**.

| Datos | Por defecto |
|---|---|
| Métricas de los servidores | 30 días (los gráficos llegan hasta 30) |
| Peticiones HTTP e intentos de inicio de sesión | 7 días |
| Eventos de seguridad cerrados | 365 días (los abiertos no se borran) |
| Alertas, comandos y vulnerabilidades resueltas | 90 días |

Las métricas de más de 7 días se comprimen con el columnstore de TimescaleDB y se borran por bloques con `drop_chunks`.

## Respaldos

El contenedor `backup` hace `pg_dump -Fc` cada `BACKUP_INTERVAL_HOURS` (24) en `backups/` y conserva los últimos `BACKUP_KEEP` (14). Usa la misma imagen que la base, así que su `pg_dump` es de la misma versión: es el [método que indica TimescaleDB](https://docs.timescale.com/self-hosted/latest/backup-and-restore/logical-backup).

`scripts/restore_backup.sh` pide confirmación, guarda un respaldo del estado actual (`pre-restore-*.dump`), recrea la base con `timescaledb_pre_restore()`, `pg_restore` y `timescaledb_post_restore()`, y vuelve a levantar todo. Un respaldo se restaura con la misma versión de TimescaleDB con la que se hizo.

## Cuentas, sesiones y MFA

- Contraseñas con argon2id; MFA por TOTP (RFC 6238, 6 dígitos, 30 s, se acepta el código anterior y el siguiente).
- 10 códigos de respaldo de un solo uso por cuenta, guardados con argon2. Solo reemplazan al código en el inicio de sesión.
- Sesión en una cookie firmada (`itsdangerous`), `HttpOnly` y `SameSite=Lax`, de 24 h por defecto; `Secure` con "Cookies solo por HTTPS".
- 5 intentos fallidos (contraseña, código o código de respaldo) bloquean la cuenta 5 minutos.
- Resetear el acceso de una cuenta genera una contraseña temporal y una clave MFA nueva.
- No hay recuperación de contraseña por correo: un admin resetea el acceso desde **Usuarios**.

## Usar la API desde scripts

No hay una API key fija para personas: se inicia sesión con usuario, contraseña y código, y se reusa la cookie.

```bash
# 1. Usuario y contraseña: devuelve pending_token (stage "mfa")
curl -c cookies.txt -X POST https://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "tu_usuario", "password": "tu_contrasena"}'

# 2. Código de la app
curl -c cookies.txt -b cookies.txt -X POST https://localhost/api/v1/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{"pending_token": "EL_PENDING_TOKEN", "code": "123456"}'

# 3. Desde ahí, con la cookie
curl -b cookies.txt https://localhost/api/v1/hosts
curl -b cookies.txt "https://localhost/api/v1/security-events?status=open"
curl -b cookies.txt https://localhost/api/v1/vulnerabilities
```

Con la CA interna de Caddy, agrega `--cacert caddy/shinji-soc-ca.crt` a cada `curl`. Los agentes se autentican aparte, con la API key de cada servidor en la cabecera `X-API-Key`.

## Actualizar versiones

Las imágenes tienen versión fija: `ollama/ollama:0.40.16`, `timescale/timescaledb:2.32.0-pg16` y `caddy:2.11.9-alpine`. Con `latest`, cualquier `docker compose pull` cambiaba el motor de la IA o de la base sin aviso. Actualiza de a una:

**Ollama:** cambia el tag en `docker-compose.yml`, corre `docker compose pull ollama && docker compose up -d ollama` y revisa que no aparezcan "Respuesta de IA invalida" en `docker compose logs server`. Si empeora, vuelve al tag anterior.

**TimescaleDB:**

1. Haz un respaldo.
2. Cambia el tag en los servicios `db` y `backup`, con la misma versión en los dos.
3. Corre `docker compose pull db backup && docker compose up -d db backup`.
4. Actualiza la extensión, que no se actualiza sola:

   ```bash
   docker compose exec db psql -U shinjisoc -d shinjisoc -c "ALTER EXTENSION timescaledb UPDATE;"
   ```

   (con el usuario y la base de tu `.env`).

No hay sistema de migraciones de esquema: al arrancar se crean las tablas nuevas y se agregan las columnas nuevas conocidas. Antes de actualizar, haz un respaldo.

## Desarrollo

`docker-compose.yml` es el modo producción: el código va dentro de la imagen. Para desarrollar, con el código montado y recarga automática al editar:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Para no escribir los dos `-f`, copia el contenido de `docker-compose.dev.yml` a `docker-compose.override.yml` (no se versiona; Compose lo carga solo).

**Si cambias el agente** (cualquier archivo de `agent/`), regenera `install.sh` antes de hacer commit, porque el contenido embebido no se actualiza solo:

```bash
cd agent && bash _build_install.sh
```

## Tests

```bash
bash scripts/run_tests.sh
```

Usan `unittest` (biblioteca estándar). Los del servidor corren dentro de su contenedor y los del agente con el Python del equipo. Cubren sobre todo errores que aparecieron contra servidores reales: versiones de otra release de Debian, paquetes fuente y binarios, datos inventados por la IA, minimización de datos para la auditoría, escritura del `.env`, roles, códigos de respaldo, parseo de inicios de sesión SSH y Proxmox, e importación de todos los módulos. Los flujos que necesitan la base de datos completa (escaneo de punta a punta) se probaron a mano.

## Simulación de ataques

Para probar el mapa y la detección sin un ataque real, `server/scripts/simulate_attack.py` crea un servidor ficticio ("Simulacion de ataques") y le manda, por la API del agente, escaneos web y fuerza bruta SSH/Proxmox desde IPs públicas de otros países elegidas al azar en la base GeoLite2. No sale tráfico hacia esas IPs ni se toca ningún servidor real.

```bash
docker compose exec -d server sh -c "python -m scripts.simulate_attack >> /tmp/attack-sim.log 2>&1"
docker compose exec server python -m scripts.simulate_attack --stop
docker compose exec server python -m scripts.simulate_attack --clean
```

`--stop` detiene el bucle y `--clean` además borra el servidor ficticio y sus datos. Cada oleada pide resúmenes a la IA, así que Ollama trabaja más mientras corre.

## Limitaciones conocidas

- La detección cuenta eventos en ventanas de tiempo: puede haber falsos positivos con tráfico legítimo raro, y no detecta ataques más sofisticados.
- Los logs web tienen que estar en formato *combined*.
- La vigilancia de procesos usa una lista fija de binarios sospechosos: una aplicación que lanza procesos legítimamente puede generar falsos positivos. Por eso nada se ejecuta sin aprobación.
- El escaneo de vulnerabilidades necesita saber la versión de Debian del servidor; sin ella, ese servidor no se escanea, para no comparar contra la release equivocada.
- La IA local es un modelo de 3B parámetros: sus textos se validan, pero pueden ser imprecisos. Los datos (CVE, versiones) siempre vienen de OSV.
- No hay registro de auditoría de quién aprobó cada acción.
- Pensado para infraestructura propia. Si el panel se expone a internet, que sea por HTTPS, con "Cookies solo por HTTPS" activado y el puerto 8000 cerrado.
