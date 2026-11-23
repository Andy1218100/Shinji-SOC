---
name: conectar-shinji-soc-mcp
description: Asistente paso a paso para conectar Claude (Claude Code o Claude Desktop) al servidor MCP de auditoría de un panel Shinji SOC. Pregunta con casillas de opciones dónde se usa Claude, cómo se llega al panel y el token de auditoría; comprueba la conexión y registra el servidor MCP. Usar cuando alguien quiera conectar, configurar, instalar o reparar la auditoría de Shinji SOC con Claude, el servidor MCP shinji-soc-audit, o diga que no le conecta.
---

# Conectar Claude al servidor MCP de Shinji SOC

Guías a una persona que puede no saber nada técnico para que Claude quede conectado al servidor MCP de auditoría de su panel Shinji SOC. Hablas en español, con frases cortas y sin jerga; si una palabra técnica es inevitable (token, terminal), la explicas en una línea.

## Qué hay que lograr

El servidor MCP es un archivo, `server.py`, que corre **en el equipo de la persona** (lo abre Claude) y se conecta al panel por HTTPS con un **token de auditoría**. Para registrarlo hacen falta cinco datos:

1. Dónde usa Claude: **Claude Code** o **Claude Desktop**.
2. La **dirección del panel** (`SHINJI_SOC_URL`), la misma que abre en el navegador.
3. El **token de auditoría** (`SHINJI_SOC_AUDIT_TOKEN`).
4. La ruta de **Python 3.10 o más nuevo**.
5. La ruta de **`server.py`**.

Opcional: `SHINJI_SOC_CA_FILE`, solo si el panel usa un certificado propio (no público). Con Cloudflare Tunnel no hace falta.

## Reglas

- **Pregunta con la herramienta de preguntas con opciones** (en Claude Code, `AskUserQuestion`): hasta 4 preguntas por vez, 2 a 4 opciones cada una, y la opción recomendada primero con "(Recomendado)". Para datos que hay que escribir (dirección, token), la persona elige "Other" y lo escribe; díselo en la pregunta. Si no tienes esa herramienta, pregunta en texto con opciones numeradas.
- **Nunca repitas el token completo** en tus mensajes: si tienes que referirte a él, muestra solo los últimos 4 caracteres (`…a1b2`).
- **Pide permiso antes de**: descargar un archivo, modificar un archivo de configuración existente, o borrar un registro anterior. Di qué vas a hacer y espera un sí.
- **No toques el servidor del panel.** Todo lo que haces es en el equipo de la persona. Si algo hay que cambiar en el panel o en su servidor, explícale el paso y espera a que lo haga.
- **Comprueba antes de registrar** (paso 4): no registres nada que no haya respondido bien.
- Si en este entorno **no puedes ejecutar comandos** en el equipo de la persona (por ejemplo, en la app de Claude en el navegador), haz las mismas preguntas y entrega los comandos o el JSON listos para copiar, con instrucciones de dónde pegarlos.

## Paso 1: preguntas iniciales

Saluda en una línea ("Te ayudo a conectar Claude con tu panel Shinji SOC; son unos minutos") y haz estas preguntas en una sola llamada:

1. **"¿Dónde vas a usar la auditoría de Shinji SOC?"** (encabezado: "Claude")
   - "Claude Code (Recomendado)": la terminal de Claude en este equipo.
   - "Claude Desktop": la aplicación de escritorio de Claude.
2. **"¿Cómo abres tu panel Shinji SOC en el navegador?"** (encabezado: "Panel")
   - "Con un dominio https (Recomendado)": por ejemplo `https://panel.midominio.com`, publicado con Cloudflare Tunnel.
   - "Con una IP de mi red": por ejemplo `http://192.168.1.50:8000`.
   - "Solo tengo acceso por SSH": el panel no está publicado; entro al servidor por SSH.
   - "Claude corre en el mismo servidor": esta terminal está en el servidor del panel.
3. **"¿Ya tienes el token de auditoría del panel?"** (encabezado: "Token")
   - "Sí, lo tengo"
   - "No, explícame cómo sacarlo"
4. **"¿Cómo prefieres darme el token?"** (encabezado: "Privacidad")
   - "Lo pego aquí (Recomendado)": tú haces todo; el token queda escrito en esta conversación y en la configuración de Claude.
   - "Lo escribo yo": te doy el comando con un espacio para el token y lo corres tú en tu terminal.

## Paso 2: datos que faltan

Según las respuestas:

- **Dirección del panel.** Pregunta "¿Cuál es la dirección de tu panel?" con opciones de ejemplo según la respuesta 2 y la indicación de escribir la suya en "Other". Normalízala: sin barra final, con `https://` o `http://`. Si escribió un dominio sin esquema, usa `https://`.
- **"Solo tengo acceso por SSH".** Pide el usuario y el servidor SSH (`usuario@servidor`). La dirección será `http://localhost:8000`, a través de un túnel SSH que la persona tiene que dejar abierto mientras use la auditoría. Dale el comando y espera a que diga que lo abrió:

  ```
  ssh -N -L 8000:127.0.0.1:8000 usuario@servidor
  ```

  Si el puerto 8000 de su equipo está ocupado, usa otro (por ejemplo `8765:127.0.0.1:8000` y la dirección `http://localhost:8765`).
- **"Claude corre en el mismo servidor".** La dirección es `http://localhost:8000`. Si estás dentro de la carpeta del proyecto, `server.py` lee el token solo del `.env` de esa carpeta: puedes leer el `.env` para confirmar que `AUDIT_API_TOKEN` tiene valor (sin mostrarlo) y saltarte la pregunta del token.
- **"No, explícame cómo sacarlo".** Explica, y espera a que la persona confirme que lo tiene:
  1. En el panel: **Configuración > Inteligencia artificial > Auditoría con Claude Code > Generar nuevo** (pide su código de la app de autenticación). Solo la cuenta super admin entra a Configuración.
  2. El panel no muestra el token completo. Se lee en el servidor del panel, dentro de la carpeta del proyecto: `grep AUDIT_API_TOKEN .env`
- **Token**, si eligió pegarlo: pregúntalo ("Pega tu token de auditoría en 'Other'"). Si eligió escribirlo él, usa el texto `EL_TOKEN` en los comandos y recuérdale reemplazarlo.

## Paso 3: preparar el equipo

Solo si puedes ejecutar comandos en el equipo de la persona. Detecta el sistema operativo y:

1. **Python 3.10 o más nuevo.**
   - Windows: `py -0p` (lista los Python instalados con su ruta) o `where python`. Usa la **ruta completa** de `python.exe`: el `python` de la Microsoft Store a veces es un atajo que no ejecuta nada.
   - macOS / Linux: `command -v python3`.
   - Confirma la versión con `<ruta> --version`. Si no hay Python 3.10+, explica cómo instalarlo (python.org en Windows y macOS; `sudo apt install python3` en Debian/Ubuntu) y espera.
2. **`server.py`.** Búscalo en este orden:
   - en la carpeta actual, si es el repositorio de Shinji SOC: `tools/mcp_audit/server.py`;
   - en `~/.shinji-soc-mcp/server.py`, si ya se descargó antes.

   Si no está, pide permiso y descárgalo a `~/.shinji-soc-mcp/server.py` (en Windows, `%USERPROFILE%\.shinji-soc-mcp\server.py`):

   ```
   https://raw.githubusercontent.com/Andy1218100/Shinji-SOC/main/tools/mcp_audit/server.py
   ```

   Es un solo archivo que solo usa la biblioteca estándar de Python: no hay que instalar paquetes. Usa su ruta absoluta de aquí en adelante.
3. **Claude Code**: comprueba que el comando `claude` exista (`claude --version`).

## Paso 4: probar la conexión

Antes de registrar nada, prueba el camino real: el propio `server.py` con los datos de la persona. Le mandas una consulta MCP y lees la respuesta.

macOS / Linux / Git Bash:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"obtener_informe","arguments":{"tipo":"informes","limite":1}}}' \
  | SHINJI_SOC_URL='LA_DIRECCION' SHINJI_SOC_AUDIT_TOKEN='EL_TOKEN' 'RUTA_PYTHON' 'RUTA_SERVER_PY'
```

Windows PowerShell:

```powershell
$env:SHINJI_SOC_URL='LA_DIRECCION'; $env:SHINJI_SOC_AUDIT_TOKEN='EL_TOKEN'
'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"obtener_informe","arguments":{"tipo":"informes","limite":1}}}' | & 'RUTA_PYTHON' 'RUTA_SERVER_PY'
Remove-Item Env:SHINJI_SOC_URL, Env:SHINJI_SOC_AUDIT_TOKEN
```

La respuesta es una línea JSON con `"isError"` y un texto. Interprétala así y explícalo con palabras simples:

| Respuesta | Qué significa | Qué hacer |
|---|---|---|
| `"isError": false` | Funciona. | Sigue al paso 5. Si el texto trae `"pendientes_total": 0`, es normal: no hay textos por auditar ahora. |
| `respondio 401: Token de auditoria invalido` | El token no coincide con el del panel. | Que lo copie de nuevo del `.env` del servidor. |
| `respondio 403: Auditoria externa desactivada` | El panel no tiene token de auditoría. | Que lo genere en Configuración (paso 2). |
| `respondio 403: error code: 1010` | Cloudflare bloquea la identificación de una copia vieja de `server.py` (anterior a la versión 1.1.0). | Descargar `server.py` de nuevo (paso 3) y repetir la prueba. |
| `respondio 403` con HTML de Cloudflare ("Just a moment", "Attention Required") | Una regla de Cloudflare (Access, WAF o protección contra bots) bloquea a clientes que no son navegadores. | En Cloudflare, exceptuar la ruta `/api/v1/` del dominio del panel, o quitar Access de esa ruta. |
| `respondio 404` o `502` | La dirección no lleva al panel. | Revisar la dirección; con Cloudflare, que la ruta del túnel apunte a `http://server:8000` (o `http://localhost:8000` si `cloudflared` corre fuera de Docker). |
| `CERTIFICATE_VERIFY_FAILED` | El equipo no confía en el certificado del panel. | Con Cloudflare no debería pasar: revisar que la dirección sea el dominio. Con un certificado propio, agregar `SHINJI_SOC_CA_FILE` con el certificado raíz de esa CA. |
| `No se pudo conectar` / `timed out` / `Connection refused` | No se llega al panel. | Revisar la dirección y la red; con túnel SSH, que siga abierto. |
| `SHINJI_SOC_CA_FILE apunta a un archivo que no existe` | Ruta del certificado mal escrita. | Corregir la ruta. |

Si eligió "Lo escribo yo", dale el comando de prueba con `EL_TOKEN` para que lo corra y te pegue el resultado **sin** el token.

## Paso 5: registrar

### Claude Code

1. Revisa si ya existe un registro con ese nombre: `claude mcp get shinji-soc-audit`. Si existe, muéstrale a qué dirección apunta y pide permiso para reemplazarlo; después `claude mcp remove shinji-soc-audit` (si está en varios alcances, agrega `--scope user` o `--scope local`).
2. Si la carpeta actual tiene un `.mcp.json` con `shinji-soc-audit`, avísale: ese registro de proyecto puede chocar con el nuevo. Ofrécele quitar esa entrada (con permiso).
3. Registra para su usuario (queda disponible en todos sus proyectos). El orden importa: `--transport stdio` va entre el último `-e` y el nombre; si el nombre va justo después de `-e`, Claude Code lo toma como otra variable y rechaza el comando:

   ```
   claude mcp add --scope user -e SHINJI_SOC_URL=LA_DIRECCION -e SHINJI_SOC_AUDIT_TOKEN=EL_TOKEN --transport stdio shinji-soc-audit -- RUTA_PYTHON RUTA_SERVER_PY
   ```

   Agrega `-e SHINJI_SOC_CA_FILE=RUTA_CA` antes de `--transport` solo si hace falta. En Windows, si alguna ruta tiene espacios, ponla entre comillas.
4. Avísale que la configuración, token incluido, queda en `~/.claude.json` y que no comparta ese archivo.

### Claude Desktop

1. El archivo de configuración está en:
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

   También se abre desde la app: menú **Claude > Settings… > Developer > Edit Config**.
2. Si puedes editar archivos: pide permiso, haz una copia (`claude_desktop_config.json.bak`), lee el JSON y agrega `shinji-soc-audit` dentro de `mcpServers` **sin borrar** los servidores que ya tenga. Si no puedes, dale el bloque para pegar:

   ```json
   {
     "mcpServers": {
       "shinji-soc-audit": {
         "command": "RUTA_PYTHON",
         "args": ["RUTA_SERVER_PY"],
         "env": {
           "SHINJI_SOC_URL": "LA_DIRECCION",
           "SHINJI_SOC_AUDIT_TOKEN": "EL_TOKEN"
         }
       }
     }
   }
   ```

   En JSON, las barras invertidas de las rutas de Windows se escriben dobles (`C:\\Users\\...`).
3. Dile que **cierre Claude Desktop por completo y lo vuelva a abrir**: solo lee la configuración al arrancar.

## Paso 6: comprobar y despedirte

- **Claude Code:** corre `claude mcp list`; `shinji-soc-audit` tiene que decir `✔ Connected`. Dentro de una sesión, `/mcp` muestra lo mismo. Puede hacer falta abrir una sesión nueva de Claude Code para usarlo.
- **Claude Desktop:** botón **+** del cuadro de mensaje > **Connectors > Manage connectors** > `shinji-soc-audit`. Si no aparece, los errores quedan en `mcp-server-shinji-soc-audit.log` (Windows `%APPDATA%\Claude\logs`, macOS `~/Library/Logs/Claude`, Linux `~/.config/Claude/logs`).

Cierra con un resumen de 3 o 4 líneas: qué quedó registrado, a qué dirección apunta (sin el token) y cómo usarlo, por ejemplo:

- "Audita las recomendaciones de vulnerabilidades de Shinji SOC con shinji-soc-audit."
- "Revisa los resúmenes de eventos de seguridad pendientes en shinji-soc-audit."

Recuérdale que cada lote consume parte del límite de uso de su plan de Claude, y que si alguna vez pega o comparte el token, lo regenere en el panel y vuelva a usar esta skill para actualizar el registro.

## Referencia

- Guía completa del servidor MCP: https://github.com/Andy1218100/Shinji-SOC/blob/main/docs/MCP.md
- `server.py` lee `SHINJI_SOC_URL` (por defecto `http://localhost:8000`), `SHINJI_SOC_AUDIT_TOKEN` (si falta, `AUDIT_API_TOKEN` del `.env` de la carpeta del proyecto) y `SHINJI_SOC_CA_FILE` (opcional).
- Herramientas que expone: `obtener_informe` (trae textos de la IA local sin auditar: `vulnerabilidades`, `eventos` o `informes`) y `enviar_auditoria` (guarda veredictos, correcciones y reglas).
