# Manual de instalación de Shinji SOC

Esta guía lleva de cero a una instalación funcionando: el servidor con el panel, la publicación por HTTPS con Cloudflare Tunnel, la cuenta de administración con MFA, los agentes en los servidores que quieres vigilar y la actualización automática.

- [1. Cómo está armado](#1-cómo-está-armado)
- [2. Requisitos](#2-requisitos)
- [3. Instalar el servidor](#3-instalar-el-servidor)
- [4. Primer ingreso: la cuenta super admin](#4-primer-ingreso-la-cuenta-super-admin)
- [5. Publicar el panel con Cloudflare Tunnel](#5-publicar-el-panel-con-cloudflare-tunnel)
- [6. Agregar servidores (agentes)](#6-agregar-servidores-agentes)
- [7. Cerrar el acceso sin cifrar](#7-cerrar-el-acceso-sin-cifrar)
- [8. Actualización automática](#8-actualización-automática)
- [9. Configuración opcional](#9-configuración-opcional)
- [10. Respaldos](#10-respaldos)
- [11. Quitar un servidor o desinstalar todo](#11-quitar-un-servidor-o-desinstalar-todo)
- [12. Solución de problemas](#12-solución-de-problemas)
- [13. Actualizar desde versiones anteriores](#13-actualizar-desde-versiones-anteriores)

---

## 1. Cómo está armado

```
 Servidores vigilados          Cloudflare                Servidor de Shinji SOC (Docker)
 ┌──────────────────┐  HTTPS   ┌────────────────┐ túnel  ┌───────────────────────────────────┐
 │ agente           │ ───────► │ panel.         │ ◄───── │ cloudflared  túnel saliente       │
 │ (systemd, Python)│          │ tudominio.com  │        │ server       panel + API          │
 └──────────────────┘          └────────────────┘        │ db           PostgreSQL+TimescaleDB│
 ┌──────────────────┐                ▲                   │ ollama       IA local             │
 │ agente           │ ───────────────┘                   │ backup       respaldos            │
 └──────────────────┘                                    └───────────────────────────────────┘
        Tu navegador ──── https://panel.tudominio.com ────┘
```

- **El servidor** corre en Docker: el panel web, la base de datos, la IA local y los respaldos.
- **Cloudflare Tunnel** publica el panel en tu dominio con HTTPS y un certificado público. El contenedor `cloudflared` abre una conexión **saliente** hacia Cloudflare: no hace falta abrir puertos en el router ni en el firewall.
- **El agente** se instala en cada servidor Linux que quieres vigilar. Manda métricas, logs de acceso, inicios de sesión SSH y el inventario de paquetes a `https://panel.tudominio.com`, y ejecuta los bloqueos que apruebas en el panel.

Cloudflare es opcional: el panel también funciona solo en tu red, por `http://IP:8000` (sin cifrar).

## 2. Requisitos

### Servidor de Shinji SOC

| | Mínimo | Comentario |
|---|---|---|
| Sistema | Linux con Docker Engine, Docker Compose v2 y git | Para Proxmox VE: en una VM, no en el host (ver abajo). También funciona con Docker Desktop en Windows o macOS, pero la actualización automática necesita Linux. |
| Memoria | 6 GB libres para Docker | Medido: Ollama ocupa 3,4 GiB con el modelo `qwen2.5:3b` cargado; el resto de los contenedores, unos 250 MiB. |
| Disco | 20 GB | Medido: imágenes 11,5 GB (Ollama 8,5 GB), modelo 1,9 GB, base GeoIP 50 MB, más la base de datos y los respaldos. |
| CPU | 4 núcleos | La IA corre en CPU; no hace falta GPU. |

**Con Proxmox VE**, instala Shinji SOC dentro de una VM: la documentación de Proxmox indica que correr contenedores dentro de una VM "remains a recommended practice" ([Proxmox VE: Linux Container](https://pve.proxmox.com/wiki/Linux_Container)).

### Para publicar con Cloudflare Tunnel

- Una cuenta de Cloudflare (gratuita).
- Un dominio agregado a Cloudflare.

### Servidores que vas a vigilar

- Debian, Ubuntu o derivados, con `systemd`. Probado en Proxmox VE 8 (Debian 13).
- Acceso como `root`.
- Salida a internet hacia tu dominio (o acceso por la red al puerto 8000, si no usas Cloudflare).

Detalle en la [guía del agente](AGENTE.md#requisitos).

## 3. Instalar el servidor

**1. Descarga el código.** Hazlo con `git clone` (no descargando un zip): la actualización automática usa git.

```bash
git clone https://github.com/Andy1218100/Shinji-SOC.git
```

```bash
cd Shinji-SOC
```

**2. Crea el archivo de configuración**

```bash
cp .env.example .env
```

Edita `.env` y cambia como mínimo:

- `POSTGRES_PASSWORD`: una contraseña larga para la base de datos.
- `SESSION_SECRET_KEY`: la clave que firma las sesiones.

Para generar valores al azar:

```bash
openssl rand -hex 32
```

> **Elige la contraseña de la base antes del primer arranque.** Postgres la lee una sola vez, cuando crea la base; cambiarla después en el `.env` no la cambia en la base (ver [Cambié la contraseña de la base de datos](#cambié-la-contraseña-de-la-base-de-datos-en-el-env)). No uses `$` en ella: Docker Compose lo interpreta como una variable.

Todo lo demás se puede dejar como está y ajustar después desde el panel, en **Configuración**.

> **Importante:** el `.env` contiene contraseñas y claves. No lo subas a ningún repositorio (ya está en `.gitignore`).

**3. Levanta los contenedores**

```bash
docker compose up -d --build
```

La primera vez tarda varios minutos: descarga unos 11 GB de imágenes.

**4. Descarga el modelo de IA**

```bash
docker compose exec ollama ollama pull qwen2.5:3b
```

Son 1,9 GB. Sin el modelo, el panel funciona igual, pero los eventos y las vulnerabilidades no tienen explicación de la IA.

> **Por qué este modelo:** en una PC sin GPU, `llama3.1:8b` tardó unos 9 minutos en una sola respuesta, y `qwen2.5:3b` responde en segundos. Si tu servidor tiene GPU, puedes elegir un modelo más grande en Configuración > Inteligencia artificial.

**5. Comprueba que todo esté corriendo**

```bash
docker compose ps
```

`db`, `ollama`, `server` y `backup` tienen que aparecer como `Up`, y `db` como `healthy`.

## 4. Primer ingreso: la cuenta super admin

**1. Busca el código de instalación.** El servidor lo escribe en su log al arrancar, mientras no exista ninguna cuenta:

```bash
docker compose logs server | grep "Codigo de instalacion"
```

Este código existe para que nadie más pueda crear la cuenta de administración si el panel queda expuesto antes de que lo hagas tú. Después de 10 intentos fallidos se genera uno nuevo.

**2. Abre el panel.** Sin usuarios, te lleva solo al asistente de primera instalación.

- Desde el mismo servidor, o desde tu red: `http://IP_DEL_SERVIDOR:8000`.
- Si el servidor es remoto y solo tienes SSH, abre un túnel desde tu equipo y entra a `http://localhost:8000`:

  ```bash
  ssh -N -L 8000:127.0.0.1:8000 usuario@servidor
  ```

- O publica primero el panel con Cloudflare Tunnel (sección 5) y entra por tu dominio.

![Asistente de primera instalación](img/instalacion-setup.png)

**3. Crea la cuenta:** el código, un nombre de usuario y una contraseña de al menos 10 caracteres.

**4. Activa el MFA:** escanea el código QR con tu app de autenticación (Google Authenticator, Microsoft Authenticator, Authy, 2FAS, Aegis…) y escribe el código de 6 dígitos que muestra. La cuenta se crea recién en ese momento.

**5. Guarda los códigos de respaldo** que aparecen al final. La cuenta super admin no se puede resetear desde el panel: si pierdes el teléfono, esos códigos son la única forma de volver a entrar.

El paso a paso con capturas está en el [manual de MFA](MFA.md).

**Sin navegador a mano**, la cuenta también se puede crear por terminal. Da una contraseña temporal; el primer ingreso pide cambiarla y activar el MFA:

```bash
docker compose exec server python create_first_admin.py tu_usuario
```

### Roles

| Rol | Qué puede hacer |
|---|---|
| `superadmin` | Todo. Es el único que entra a Configuración y el único que crea cuentas admin. Hay uno solo y no se puede desactivar desde el panel. |
| `admin` | Ve todo, aprueba bloqueos, agrega y elimina servidores, y gestiona las cuentas de solo lectura. |
| `viewer` | Solo lectura. |

Las demás cuentas se crean en **Usuarios**: el sistema genera una contraseña temporal que se muestra una sola vez, y esa persona activa su propio MFA en su primer ingreso.

## 5. Publicar el panel con Cloudflare Tunnel

El proyecto trae el contenedor `cloudflared` listo; solo le falta el token de tu túnel.

**1. Crea el túnel en Cloudflare.** En el panel de Cloudflare: **Networking > Tunnels > Create a tunnel**, ponle un nombre (por ejemplo `shinji-soc`) y elige **Create Tunnel**. Cloudflare muestra un comando de instalación: no hace falta correrlo. Copia de ese comando solo el **token**, la cadena larga que empieza con `eyJ`.

**2. Activa el túnel en el `.env`:**

```
COMPOSE_PROFILES=cloudflare
CLOUDFLARE_TUNNEL_TOKEN=eyJ...el token completo...
```

```bash
docker compose up -d
```

En el panel de Cloudflare, el túnel tiene que pasar a estado conectado; elige **Continue**.

**3. Publica el panel.** En el túnel, pestaña **Routes > Add route > Published application**:

- **Subdomain:** por ejemplo `panel`.
- **Domain:** tu dominio.
- **Service URL:** `http://server:8000`

  Es `server`, el nombre del contenedor del panel, y no `localhost`: `cloudflared` corre en su propio contenedor y llega al panel por la red interna de Docker.

Elige **Add route**. El panel queda en `https://panel.tudominio.com`, con un certificado público ([documentación de Cloudflare](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel/)).

> **Si agregas Cloudflare Access** (una pantalla de inicio de sesión de Cloudflare delante del panel), los agentes y el servidor MCP no pueden pasar por ella: deja fuera de Access las rutas `/api/v1/` que usan, o no lo actives. El panel ya pide usuario, contraseña y MFA.

## 6. Agregar servidores (agentes)

La [guía del agente](AGENTE.md) tiene todo el detalle. En resumen:

**1. Crea el servidor en el panel:** **Monitoreo > + Nuevo host**. El panel muestra una sola vez el comando de instalación con la API key.

**2. En el servidor que vas a vigilar**, como root, descarga el instalador y córrelo con la dirección pública del panel:

```bash
curl -fsSL https://raw.githubusercontent.com/Andy1218100/Shinji-SOC/main/agent/install.sh -o /tmp/install.sh
```

```bash
sudo bash /tmp/install.sh https://panel.tudominio.com LA_API_KEY
```

Con Cloudflare Tunnel no hace falta ningún certificado extra. Sin Cloudflare, usa `http://IP_DEL_SERVIDOR:8000`.

**3. Comprueba:** `systemctl status shinji-soc-agent`. En el panel, el servidor aparece en **Monitoreo** con métricas en menos de un minuto.

## 7. Cerrar el acceso sin cifrar

Cuando el panel y todos los agentes ya entren por tu dominio:

1. En el `.env`, pon `SERVER_BIND=127.0.0.1`. El puerto 8000 sin cifrar queda solo para el propio servidor; `cloudflared` sigue llegando al panel por la red interna de Docker.
2. Aplica el cambio:

   ```bash
   docker compose up -d server
   ```

   En Docker Desktop, la primera vez puede fallar con "ports are not available", porque el puerto del contenedor anterior todavía no se liberó. Volver a correrlo lo resuelve.

3. En **Configuración > Sesiones y acceso**, activa **Cookies solo por HTTPS**. Desde ese momento solo se puede iniciar sesión por `https://`.

## 8. Actualización automática

`scripts/update.sh` actualiza Shinji SOC a la última versión publicada en GitHub. Para que lo haga solo, cada hora:

```bash
sudo bash scripts/install_auto_update.sh
```

Instala un temporizador de systemd (`shinji-soc-update.timer`). En cada corrida:

1. Consulta GitHub. Si no hay nada nuevo, termina.
2. Si solo cambió documentación, actualiza los archivos y no reinicia nada.
3. Si cambió código:
   - respalda la base en `backups/shinjisoc-AAAAMMDD-HHMMSS-antes-de-actualizar.dump` (conserva los últimos 5);
   - actualiza, reconstruye los contenedores y comprueba que el panel responda;
   - si no responde en 3 minutos, vuelve a la versión anterior y no reintenta esa versión hasta que salga otra.
4. Si cambió el agente, lo avisa en el registro: los agentes se reinstalan a mano ([guía del agente](AGENTE.md#reinstalar-actualizar-o-cambiar-la-dirección-del-panel)).

No toca nada si encuentra archivos del proyecto modificados a mano: el `.env` y `docker-compose.override.yml` no cuentan, porque no son parte del repositorio.

**Comandos útiles:**

| Para | Comando |
|---|---|
| Ver qué hizo | `journalctl -u shinji-soc-update` |
| Ver cuándo corre | `systemctl list-timers shinji-soc-update.timer` |
| Actualizar ahora | `sudo systemctl start shinji-soc-update.service` |
| Ver si hay una versión nueva, sin instalarla | `sudo bash scripts/update.sh --check` |
| Reintentar una versión que falló | `sudo bash scripts/update.sh --retry` |
| Quitar la actualización automática | `sudo bash scripts/install_auto_update.sh --remove` |

Sin el temporizador, `sudo bash scripts/update.sh` hace lo mismo a mano.

> La actualización automática instala lo que se publique en la rama `main` del repositorio, sin revisión de por medio. Si prefieres revisar cada cambio antes, no instales el temporizador y usa `update.sh --check` y `update.sh` a mano.

## 9. Configuración opcional

Todo esto se hace desde **Configuración** (solo super admin); guardar pide tu código MFA. Los detalles de cada función están en la [referencia técnica](REFERENCIA.md).

- **Mapa de ataques (GeoIP):** crea una cuenta gratuita en [MaxMind](https://www.maxmind.com/en/geolite2/signup), genera una License Key, guarda el Account ID y la License Key, y usa el botón **Descargar base GeoIP**. Sin esto, los ataques aparecen en la lista pero no en el mapa.
- **Notificaciones:** Telegram, ntfy o correo (SMTP), con un botón de prueba. Por defecto solo avisan lo crítico y no incluyen la IP de origen.
- **IA con Claude:** cambia el motor a Claude y pega una API key de Anthropic. Por defecto todo pasa por la IA local y no sale ningún dato del servidor.
- **Auditoría de la IA local con Claude:** genera el token de auditoría y registra `tools/mcp_audit/server.py` en Claude Code o Claude Desktop (ver la [guía del servidor MCP](MCP.md)).
- **Limitar la CPU de la IA:** en un equipo con pocos núcleos, Ollama puede dejarlos todos al 100 % durante un escaneo. Crea un `docker-compose.override.yml` (no se versiona; Compose lo carga solo) y corre `docker compose up -d ollama`:

  ```yaml
  services:
    ollama:
      cpus: "4"
  ```

## 10. Respaldos

El contenedor `backup` respalda la base cada 24 horas en la carpeta `backups/` y conserva los últimos 14. En **Configuración > Respaldos** se ve su estado, se ajustan el intervalo y la cantidad, y está el botón **Respaldar ahora**.

> **Los respaldos contienen los hashes de las contraseñas, los secretos del MFA y las API keys de los agentes.** Cópialos fuera de este servidor, a un lugar seguro. Un respaldo en el mismo disco no sirve si se pierde el disco.

Para restaurar uno (pide confirmación y guarda antes una copia del estado actual):

```bash
bash scripts/restore_backup.sh backups/shinjisoc-AAAAMMDD-HHMMSS.dump
```

## 11. Quitar un servidor o desinstalar todo

**Quitar el agente de un servidor** (detalle en la [guía del agente](AGENTE.md#desinstalar)). En ese servidor, como root:

```bash
shinji-soc-uninstall --dry-run
```

```bash
shinji-soc-uninstall
```

Después borra el servidor del panel: **Monitoreo >** el servidor **> Eliminar** (pide MFA).

**Desinstalar el servidor de Shinji SOC:**

```bash
sudo bash scripts/install_auto_update.sh --remove
```

```bash
docker compose down
```

Eso detiene y quita los contenedores, pero conserva los datos. Para borrar también la base de datos y el modelo de IA (no se puede deshacer):

```bash
docker compose down -v
```

En Cloudflare, borra el túnel desde **Networking > Tunnels**.

## 12. Solución de problemas

**El dominio muestra un error 502 de Cloudflare.** El túnel funciona, pero no llega al panel. Revisa que el **Service URL** de la ruta sea `http://server:8000` y que el panel esté corriendo (`docker compose ps`).

**El túnel no se conecta.** Revisa el log: `docker compose logs cloudflared`. Comprueba que `COMPOSE_PROFILES=cloudflare` esté en el `.env` (sin eso, el contenedor no arranca) y que el token esté completo.

**Los agentes reciben 403 desde Cloudflare.** Si la respuesta es una página de Cloudflare (no del panel), alguna regla de seguridad de Cloudflare está bloqueando a clientes que no son navegadores (Access, reglas del WAF o protección contra bots). Exceptúa las rutas `/api/v1/` para el dominio del panel.

**Los eventos de Seguridad no aparecen en vivo.** La página igual se recarga sola cada 30 segundos.

### Cambié la contraseña de la base de datos en el `.env`

Postgres solo lee `POSTGRES_PASSWORD` la primera vez, cuando crea la base vacía; desde ahí la contraseña queda guardada en la propia base. Si la cambias después en el `.env`, el servidor manda la nueva, la base sigue esperando la anterior, y el log del servidor muestra `password authentication failed`. Hay dos formas de resolverlo:

**A. Instalación nueva, sin datos que conservar.** Borra solo el volumen de la base, para que se cree de nuevo con la contraseña nueva (el modelo de IA no se toca):

```bash
docker compose down
```

```bash
docker volume ls | grep db_data
```

Borra el volumen con el nombre que aparezca (por ejemplo `shinji-soc_db_data`). Esto borra la base y no se puede deshacer:

```bash
docker volume rm shinji-soc_db_data
```

```bash
docker compose up -d
```

La base queda vacía, así que el servidor vuelve a mostrar el código de instalación para crear la cuenta super admin.

**B. Ya tienes datos y quieres conservarlos.** Cambia la contraseña dentro de Postgres para que coincida con la del `.env`. Abre la consola de la base (desde adentro del contenedor no pide contraseña):

```bash
docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

Dentro de `psql`, escribe `\password shinjisoc` (o el usuario de tu `.env`; si también lo cambiaste, el usuario original). Pide la contraseña nueva dos veces y no queda en el historial de la terminal; escribe la misma del `.env` y sal con `\q`. Después aplica el `.env` a los contenedores:

```bash
docker compose up -d
```

En los dos casos, comprueba con `docker compose logs server | tail -5`: no tiene que aparecer `password authentication failed` ni "No se pudo conectar a la base de datos".

### Otros problemas

**El servidor no arranca: "Name or service not known" al conectar a la base.** Pasaba en versiones anteriores cuando la contraseña de la base tenía un `@`. Actualiza (`git pull` y `docker compose up -d --build`).

**No puedo iniciar sesión: "Cuenta bloqueada temporalmente".** Después de 5 intentos fallidos (contraseña o código), la cuenta se bloquea 5 minutos.

**El código del MFA siempre es inválido.** Casi siempre es la hora del teléfono: los códigos dependen del reloj. Activa la hora automática en el teléfono. Si perdiste el teléfono, ver el [manual de MFA](MFA.md#perdí-o-cambié-el-teléfono).

**Activé "Cookies solo por HTTPS" y ya no puedo entrar.** Se está entrando por `http://`. Entra por `https://panel.tudominio.com`, o pon `SESSION_COOKIE_SECURE=false` en el `.env` y corre `docker compose up -d server`.

**La actualización automática no actualiza.** Mira `journalctl -u shinji-soc-update`. Los motivos más comunes: archivos del proyecto modificados a mano (`git status` los muestra; `git checkout -- archivo` los devuelve a la versión del repositorio) o una versión que falló y quedó marcada (se reintenta con `update.sh --retry`).

**"ports are not available" al levantar un contenedor.** Otro programa usa ese puerto, o Docker Desktop todavía no liberó el del contenedor anterior. Vuelve a correr el comando.

**Docker Desktop no arranca después de un corte de luz (Windows).** Si el log (`%LOCALAPPDATA%\Docker\log\host\com.docker.backend.exe.log`) dice `initializing Secrets Engine ... engine.sock`, cierra Docker Desktop, renombra la carpeta `%LOCALAPPDATA%\docker-secrets-engine` (por ejemplo a `docker-secrets-engine.bak`) y vuelve a abrirlo.

**La IA no da explicaciones o tarda mucho.** Comprueba que el modelo esté descargado (`docker compose exec ollama ollama list`) y revisa `docker compose logs server`: las respuestas que se rechazan quedan registradas como "Respuesta de IA invalida".

**Ver los logs de cualquier servicio:**

```bash
docker compose logs -f server
```

## 13. Actualizar desde versiones anteriores

**Si tu instalación usaba Caddy** (HTTPS integrado, ya quitado del proyecto): al actualizar, `docker compose up -d --remove-orphans` (o el script de actualización) quita su contenedor. Publica el panel con Cloudflare Tunnel (sección 5) y reinstala los agentes con la dirección nueva, sin el certificado de la CA ([guía del agente](AGENTE.md#reinstalar-actualizar-o-cambiar-la-dirección-del-panel)). Los volúmenes de Caddy quedan en Docker; para borrarlos, busca sus nombres con `docker volume ls | grep caddy` y bórralos con `docker volume rm`.

**Si tu instalación se llamaba Prox Secure:**

- **Servidor:** actualiza como siempre. La base, sus usuarios y los respaldos `proxsecure-*.dump` se conservan y se siguen listando y restaurando. Las sesiones abiertas se cierran una vez (cambió el nombre de la cookie). En las apps de autenticación, la cuenta sigue apareciendo como "Prox Secure" y sus códigos siguen sirviendo.
- **Agentes:** el agente anterior usa otro servicio, usuario y carpeta (`prox-secure-agent`, `/opt/prox-secure-agent`), y el instalador nuevo se niega a instalar mientras siga ahí. Quítalo con el `uninstall.sh` nuevo, que reconoce los dos nombres, e instala el nuevo con la misma API key:

  ```bash
  sudo grep API_KEY /opt/prox-secure-agent/.env
  ```

  ```bash
  curl -fsSL https://raw.githubusercontent.com/Andy1218100/Shinji-SOC/main/agent/uninstall.sh -o /tmp/uninstall.sh
  ```

  ```bash
  sudo bash /tmp/uninstall.sh --yes
  ```

  Después instala el agente nuevo (sección 6) con esa API key, y vuelve a usar **Dar acceso** en los logs que lo tenían: el usuario del agente cambió (`shinji-soc`).
