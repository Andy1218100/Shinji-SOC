# WAF (firewall de aplicaciones web)

El WAF es opcional. Se pone **entre el túnel de Cloudflare y cada aplicación web** del servidor, revisa cada petición con las reglas [OWASP CRS](https://coreruleset.org/) y puede cortar los ataques (inyección SQL, XSS, inclusión de archivos, ejecución de comandos, escáneres) antes de que lleguen a la aplicación. Lo que detecta aparece en el panel, en **Seguridad**, como "Ataque web (WAF)".

```
Cloudflare → cloudflared → WAF (127.0.0.1:PUERTO) → aplicación (por ejemplo AMP)
```

Usa los paquetes de Debian: `nginx`, `libnginx-mod-http-modsecurity` (ModSecurity 3) y `modsecurity-crs`. En Debian 13 la prueba se hizo con ModSecurity 3.0.14 y CRS 3.3.7; Debian 12 trae CRS 3.3.4 ([packages.debian.org](https://packages.debian.org/bookworm/modsecurity-crs)). Son versiones más antiguas que la última de CRS, pero se actualizan con el sistema (`apt upgrade`).

## Requisitos

- Debian o Proxmox VE, con acceso root. Se probó en Debian 13. En Ubuntu necesita los mismos paquetes; no está probado.
- El agente de Shinji SOC instalado y actualizado: deja el comando `shinji-soc-waf` y es el que manda lo detectado al panel. Sin el agente, el script es `agent/waf.sh` del repositorio (`sudo bash waf.sh ...`), pero nada llega al panel.
- `cloudflared` en el mismo servidor. Si corre en otra máquina o en un contenedor, mira [cloudflared en un contenedor](#cloudflared-en-un-contenedor-o-en-otra-máquina).

## Instalar

```bash
sudo shinji-soc-waf instalar
```

Instala los paquetes y deja el WAF en modo **solo detección**: registra lo que bloquearía, pero no bloquea nada. Si nginx no estaba instalado, quita su sitio de ejemplo del puerto 80. Si ya lo usabas, tus sitios no cambian: el WAF solo se activa en los sitios que agregues con el comando siguiente.

## Proteger una aplicación

```bash
sudo shinji-soc-waf agregar NOMBRE PUERTO DESTINO
```

- `NOMBRE`: corto, en minúsculas (por ejemplo `amp`).
- `PUERTO`: un puerto libre para el WAF (por ejemplo `8081`).
- `DESTINO`: dónde está la aplicación hoy (por ejemplo `http://127.0.0.1:8080`, lo que hoy figura como servicio en Cloudflare).

Ejemplo:

```bash
sudo shinji-soc-waf agregar amp 8081 http://127.0.0.1:8080
```

Después, en Cloudflare, abre tu túnel, pestaña **Routes**, edita la *Published application* de esa aplicación y cambia **Service URL** a `http://127.0.0.1:8081`. Desde ese momento las visitas pasan por el WAF.

El WAF:

- Toma la IP real del visitante de la cabecera `CF-Connecting-IP`, solo cuando la petición viene de `cloudflared`.
- Escribe un log de acceso con esa IP (`/var/log/nginx/shinji-waf-NOMBRE.access.log`). El agente lo encuentra solo, así que también funcionan la detección de escaneos y la de fuerza bruta web para aplicaciones que no escriben su propio log, como AMP.
- Pasa WebSockets y conexiones largas (hasta una hora sin datos).
- No revisa las respuestas, para no retrasar descargas ni eventos en vivo.

## Comprobar que funciona

Desde cualquier equipo, con una petición de ataque falsa a tu dominio:

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://app.tudominio.com/?id=1%27%20UNION%20SELECT%20password%20FROM%20users--"
```

En modo solo detección responde lo mismo que siempre (por ejemplo `200`). En menos de un minuto aparece en **Seguridad** un evento "Ataque web (WAF)" con tu IP, el tipo de ataque (`sqli`) y los números de las reglas. En modo bloqueo, la respuesta es `403`.

En el servidor:

```bash
sudo shinji-soc-waf estado
```

## Pasar a modo bloqueo

Deja el WAF unos días en solo detección y revisa los eventos. Si solo aparecen ataques reales y no peticiones normales de tus aplicaciones:

```bash
sudo shinji-soc-waf modo bloqueo
```

Para volver atrás: `sudo shinji-soc-waf modo deteccion`. El cambio es inmediato (recarga nginx sin cortar conexiones).

## Falsos positivos

Las reglas CRS a veces marcan peticiones normales: formularios que aceptan código o HTML, editores, APIs con JSON complejo. En el evento del panel figuran los números de las reglas (por ejemplo `942100`). Para excluir una, edita `/etc/shinji-soc-waf/exclusiones.conf`:

```
# Quitar una regla en todo el sitio
SecRuleRemoveById 942100

# Que una regla no revise un campo concreto
SecRuleUpdateTargetById 942100 "!ARGS:mensaje"
```

Y recarga con `sudo shinji-soc-waf modo deteccion` (o `bloqueo`, el que estés usando).

## Qué manda el agente

Por cada petición que supera el umbral de CRS: hora, IP, método, ruta, host, código de respuesta, si se bloqueó, el puntaje y hasta 8 reglas (número, descripción, tipo de ataque y el fragmento que coincidió, hasta 200 caracteres). **Nunca** manda las cabeceras (llevan cookies de sesión) ni los cuerpos.

En el panel, las peticiones de una misma IP se juntan en un solo evento mientras siga abierto. Si el evento incluye inyección SQL, ejecución de comandos, inclusión de archivos o XSS, es **crítico**; si no, advertencia. La acción sugerida es bloquear la IP con fail2ban (requiere aprobación), salvo que sea una IP de Cloudflare.

En el servidor, el registro completo queda en `/var/log/shinji-soc-waf/audit.log`: una línea JSON por petición sospechosa, legible solo por root, `www-data` y el grupo `adm`. Rota cada día y guarda 7 días. No guarda el cuerpo de las peticiones, pero sí sus cabeceras y, a veces, la respuesta de la aplicación.

## cloudflared en un contenedor o en otra máquina

Por defecto el WAF escucha en `127.0.0.1`, que un `cloudflared` dentro de Docker no alcanza. Para escuchar en todas las direcciones y aceptar la IP real desde la red de Docker:

```bash
sudo ESCUCHAR=0.0.0.0 CONFIAR="127.0.0.1 ::1 172.16.0.0/12" shinji-soc-waf agregar amp 8081 http://127.0.0.1:8080
```

En Cloudflare, la **Service URL** pasa a ser `http://IP_DEL_SERVIDOR:8081`. Con `0.0.0.0` el puerto queda abierto en la red: ciérralo en el firewall para todo lo que no sea `cloudflared`. `CONFIAR` tiene que incluir solo las direcciones desde donde llega `cloudflared`: quien pueda conectarse desde ellas puede inventar la cabecera `CF-Connecting-IP`.

## Quitar

Un sitio (antes, en Cloudflare, vuelve a poner la Service URL de la aplicación):

```bash
sudo shinji-soc-waf quitar amp
```

Todo el WAF:

```bash
sudo shinji-soc-waf desinstalar
```

Borra la configuración de Shinji SOC y deja nginx, los paquetes y los registros. Para borrar también los paquetes: `sudo apt-get remove nginx libnginx-mod-http-modsecurity modsecurity-crs`. Desinstalar el agente no quita el WAF, para no cortar los sitios que protege.
