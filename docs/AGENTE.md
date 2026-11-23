# Guía del agente: instalar y desinstalar

El agente es el programa que se instala en cada servidor Linux que quieres vigilar. Manda al panel de Shinji SOC las métricas, los logs de acceso, los inicios de sesión y el inventario de paquetes, y ejecuta los bloqueos que apruebas en el panel. Siempre es el agente el que se conecta al panel, nunca al revés.

- [Requisitos](#requisitos)
- [Instalar](#instalar)
- [Comprobar que funciona](#comprobar-que-funciona)
- [Qué deja instalado y qué manda](#qué-deja-instalado-y-qué-manda)
- [Ajustes después de instalar](#ajustes-después-de-instalar)
- [Reinstalar, actualizar o cambiar la dirección del panel](#reinstalar-actualizar-o-cambiar-la-dirección-del-panel)
- [Desinstalar](#desinstalar)
- [Problemas frecuentes](#problemas-frecuentes)

## Requisitos

- **Sistema:** Debian, Ubuntu o derivados, con `apt` y `systemd`. Probado en Proxmox VE 8 (Debian 13).
- **Acceso:** `root` o `sudo`.
- **Red:** el servidor tiene que poder llegar al panel: por internet a tu dominio, si lo publicaste con Cloudflare Tunnel, o por la red al puerto 8000.
- **Del panel:** una cuenta con rol admin, para crear el servidor y obtener su API key.

No hace falta preparar nada más: el instalador agrega lo que falte (`python3`, `python3-venv`, `python3-pip`, `sudo`, `fail2ban` y `acl`).

## Instalar

### 1. Crea el servidor en el panel

En **Monitoreo**, botón **+ Nuevo host**. Completa:

- **Nombre:** cómo se va a ver en el panel.
- **Hostname:** el nombre del servidor.
- **IP** (opcional): su IP pública. Sirve para dibujar en el mapa los arcos de los ataques hacia ese servidor.

Al guardarlo, el panel muestra **una sola vez** el comando de instalación, con la dirección del panel y la **API key** de ese servidor. Cópialo. Si lo pierdes, borra el servidor del panel y créalo de nuevo.

### 2. Lleva el instalador al servidor

`install.sh` es un solo archivo que trae el agente completo adentro. Elige una forma:

**Desde GitHub**, en el servidor que vas a vigilar:

```bash
curl -fsSL https://raw.githubusercontent.com/Andy1218100/Shinji-SOC/main/agent/install.sh -o /tmp/install.sh
```

Así obtienes la última versión publicada. Si tu panel es de una versión anterior, usa la otra forma, para que el agente y el panel sean de la misma versión.

**Desde tu copia del repositorio**, en el equipo donde clonaste Shinji SOC:

```bash
scp agent/install.sh root@servidor:/tmp/install.sh
```

### 3. Ejecuta el instalador

En el servidor que vas a vigilar, como root. Es el comando que mostró el panel, con la dirección pública del panel:

```bash
sudo bash /tmp/install.sh https://panel.tudominio.com LA_API_KEY
```

Sin Cloudflare Tunnel, usa la dirección del panel en tu red: `http://IP_DEL_SERVIDOR:8000`.

**Panel con un certificado propio** (HTTPS con una CA que no es pública, por ejemplo detrás de tu propio proxy): agrega al final la ruta del certificado raíz de esa CA, copiado antes al servidor. Con Cloudflare Tunnel no hace falta.

```bash
sudo bash /tmp/install.sh https://panel.interno LA_API_KEY /tmp/ca.crt
```

Tiene que ser `bash` (no `sh`). El instalador tarda uno o dos minutos: instala las dependencias, crea el usuario del agente y deja el servicio corriendo. Al final indica si fail2ban quedó activo; sin fail2ban, los bloqueos de IP desde el panel no funcionan.

## Comprobar que funciona

En el servidor:

```bash
systemctl status shinji-soc-agent
```

```bash
journalctl -u shinji-soc-agent -f
```

En el panel:

- en **Monitoreo**, el servidor aparece con métricas en menos de un minuto;
- su página muestra el informe del sistema (servicios, puertos, logs encontrados) en cuanto la IA lo termina;
- en **Vulnerabilidades** aparece su pestaña después del primer escaneo, que corre apenas llega el inventario de paquetes.

## Qué deja instalado y qué manda

### Archivos y permisos

| Qué | Dónde |
|---|---|
| Código del agente, su configuración y su API key | `/opt/shinji-soc-agent` |
| Servicio | `shinji-soc-agent` (systemd) |
| Usuario sin privilegios que lo ejecuta | `shinji-soc`, en el grupo `adm` para poder leer logs |
| Permisos acotados con `sudo` | `/etc/sudoers.d/shinji-soc-agent` |
| Jail de fail2ban para los bloqueos aprobados en el panel | `/etc/fail2ban/jail.d/shinjisoc.conf` |
| Comando para desinstalarlo | `/usr/local/sbin/shinji-soc-uninstall` |

El agente no corre como root. Con `sudo` solo puede hacer cinco cosas: bloquear y desbloquear IPs en su jail de fail2ban, terminar un proceso, dar permiso de lectura a un log y listar las conexiones con `ss -tunapH` (ese comando exacto, que solo lee). Terminar un proceso y dar lectura pasan por scripts propios que validan lo que reciben: `kill_process.sh` solo termina el proceso si su línea de comando sigue siendo la del evento (para no matar un PID reutilizado) y `grant_log_access.sh` solo acepta rutas bajo `/var/log`, `/opt`, `/srv` y `/home`.

### Qué datos manda al panel

- **Métricas:** CPU, memoria, disco y red, cada 15 segundos.
- **Accesos web:** de cada línea de los logs de acceso de nginx/apache, la IP, el método, la ruta, el código de respuesta y el user-agent.
- **Inicios de sesión** de SSH y de la web de Proxmox: cuándo, servicio, resultado, usuario e IP. Nunca las líneas del log.
- **Procesos** de cuentas de servicio que lanzan programas sospechosos: usuario, PID y línea de comando.
- **Inventario de paquetes** (`dpkg`), una vez al día.
- **Conexiones:** los puertos en escucha y las conexiones TCP salientes a IPs públicas (dirección, puerto, cuenta y proceso), cada minuto si hay cambios. No captura paquetes ni contenido ([cómo se usa](REFERENCIA.md#conexiones-del-host)).
- **Informe del sistema:** SO, hardware, servicios, puertos en escucha y logs encontrados, al arrancar y una vez al día.

Todo va al panel por la dirección que le diste al instalar, autenticado con la API key de ese servidor. El agente no manda nada a ningún otro lado.

## Ajustes después de instalar

### Logs que el agente no puede leer

El agente busca solo los logs de cada servidor. Si alguno está en una carpeta cerrada, la página del servidor lo muestra en "Logs encontrados pero sin permiso", con un botón **Dar acceso** (rol admin, pide tu código MFA). Ese botón da al usuario `shinji-soc` permiso de **solo lectura** sobre esa ruta, sin cambiar dueños ni permisos existentes. Solo funciona bajo `/var/log`, `/opt`, `/srv` o `/home` (nunca `/root`).

### Fijar logs o cuentas a mano

Si el descubrimiento automático no encuentra un log, o quieres vigilar una cuenta de servicio concreta, edita `/opt/shinji-soc-agent/config.yaml` (los ejemplos están en `agent/config.example.yaml` del repositorio) y reinicia el servicio:

```bash
sudo systemctl restart shinji-soc-agent
```

Lo que fijes ahí gana sobre lo que el agente detecta solo.

## Reinstalar, actualizar o cambiar la dirección del panel

El instalador se puede volver a correr sobre una instalación existente: reemplaza el código y la dirección del panel y la API key por las que le pases, y conserva tu `config.yaml`.

**Reinstalar o actualizar con la misma dirección y la misma API key.** Descarga el `install.sh` nuevo (paso 2) y corre:

```bash
sudo bash -c '. /opt/shinji-soc-agent/.env && bash /tmp/install.sh "$SHINJI_SOC_SERVER_URL" "$SHINJI_SOC_API_KEY" "${SHINJI_SOC_CA_FILE:-}"'
```

El tercer argumento conserva el certificado propio, si el agente tenía uno; si no tenía, va vacío y no cambia nada.

**Cambiar la dirección del panel** (por ejemplo, si lo mudaste a otro servidor o lo publicaste con Cloudflare Tunnel), conservando la API key:

```bash
sudo bash -c '. /opt/shinji-soc-agent/.env && bash /tmp/install.sh https://panel.tudominio.com "$SHINJI_SOC_API_KEY"'
```

Sin tercer argumento, el agente deja de usar el certificado propio que tuviera y confía en los certificados públicos, que es lo que necesita con Cloudflare Tunnel. Si el panel nuevo usa un certificado propio, agrega la ruta de su CA como tercer argumento.

Si instalaste el panel de cero (base de datos nueva), las API keys anteriores ya no existen: crea el servidor de nuevo en el panel e instala con la API key nueva.

## Desinstalar

### 1. Quita el agente del servidor

En el servidor, como root. Primero en modo simulación, que muestra lo que haría sin cambiar nada:

```bash
sudo shinji-soc-uninstall --dry-run
```

```bash
sudo shinji-soc-uninstall
```

Pide escribir `QUITAR` para confirmar. Con `--yes` no pregunta:

```bash
sudo shinji-soc-uninstall --yes
```

Quita todo lo que puso el instalador:

- el servicio y la carpeta `/opt/shinji-soc-agent`, incluida la API key;
- el sudoers del agente;
- el jail de fail2ban. Las IPs bloqueadas desde el panel quedan desbloqueadas; los demás jails no se tocan;
- los permisos de lectura dados con **Dar acceso**. Los permisos de otros usuarios no se tocan;
- el usuario `shinji-soc`.

No quita los paquetes del sistema (`python3-venv`, `fail2ban`, `acl`, `sudo`), porque pueden estar en uso por otras cosas. Volver a correrlo no hace nada.

**Si el comando `shinji-soc-uninstall` no existe** (por ejemplo, porque se borró a mano), usa el script del repositorio:

```bash
curl -fsSL https://raw.githubusercontent.com/Andy1218100/Shinji-SOC/main/agent/uninstall.sh -o /tmp/uninstall.sh
```

```bash
sudo bash /tmp/uninstall.sh
```

**Agentes con el nombre anterior del proyecto** (Prox Secure, en `/opt/prox-secure-agent`): ese mismo `uninstall.sh` los reconoce y los quita igual. El instalador nuevo no instala mientras quede uno.

### 2. Borra el servidor del panel

El servidor y su historial (métricas, eventos, vulnerabilidades) siguen en el panel hasta que los borras: **Monitoreo >** el servidor **> Eliminar** (rol admin, pide tu código MFA). No se puede deshacer.

Si solo quieres dejar de vigilarlo por un tiempo, basta con desinstalar el agente: el historial se conserva y lo puedes volver a instalar más tarde con una API key nueva.

## Problemas frecuentes

**El instalador dice "Hay un agente instalado con el nombre anterior".** Queda un agente de Prox Secure. Quítalo con `uninstall.sh` (ver [Desinstalar](#desinstalar)) y vuelve a correr el instalador.

**El agente no se conecta: "certificate verify failed".** El agente tiene configurado un certificado propio (de una instalación anterior, por ejemplo con Caddy) y el panel ahora usa otro. Si el panel está detrás de Cloudflare Tunnel, reinstala con la dirección nueva y sin tercer argumento (ver [Cambiar la dirección del panel](#reinstalar-actualizar-o-cambiar-la-dirección-del-panel)).

**El agente recibe 403 desde Cloudflare.** Si la respuesta es una página de Cloudflare y no del panel, alguna regla de seguridad de Cloudflare (Access, WAF o protección contra bots) bloquea a clientes que no son navegadores. Exceptúa las rutas `/api/v1/` del dominio del panel.

**Para probar la conexión desde el servidor vigilado:**

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://panel.tudominio.com/login
```

Tiene que mostrar `200`. Sin Cloudflare, prueba con `http://IP_DEL_SERVIDOR:8000/login`.

**En `journalctl` aparecen errores 401.** La API key no existe en el panel: el servidor se borró del panel, o el panel se instaló de cero. Créalo de nuevo e instala con la API key nueva.

**"fail2ban no quedo activo".** Revisa la configuración de fail2ban con `fail2ban-client -t` y su log con `tail -n 30 /var/log/fail2ban.log`. Sin fail2ban, el agente funciona, pero los bloqueos de IP aprobados en el panel no se aplican.

**No aparecen eventos de ataques web.** El agente solo entiende los logs de acceso en formato *combined* de nginx/apache. Mira en la página del servidor qué logs vigila y si alguno figura sin permiso.
