# Guía del servidor MCP: auditar la IA local con Claude

Shinji SOC trae un servidor MCP (`tools/mcp_audit/server.py`) que permite a Claude revisar los textos que escribe la IA local (un modelo chico, de 3B parámetros): las recomendaciones de vulnerabilidades, los resúmenes de eventos de seguridad y los informes de los servidores. Claude corrige los que están mal y deja reglas para que la IA local no repita el error.

- [Cómo funciona](#cómo-funciona)
- [Requisitos](#requisitos)
- [1. Genera el token de auditoría](#1-genera-el-token-de-auditoría)
- [2. Consigue el servidor MCP](#2-consigue-el-servidor-mcp)
- [3a. Regístralo en Claude Code](#3a-regístralo-en-claude-code)
- [3b. O regístralo en Claude Desktop](#3b-o-regístralo-en-claude-desktop)
- [4. Úsalo](#4-úsalo)
- [Cambiar el token o quitar el servidor](#cambiar-el-token-o-quitar-el-servidor)
- [Problemas frecuentes](#problemas-frecuentes)

## Cómo funciona

```
 Tu equipo                                         Servidor de Shinji SOC
 ┌─────────────────────────────────────┐           ┌──────────────────────┐
 │ Claude Code o Claude Desktop        │           │ panel                │
 │   └─ server.py (MCP, stdio)  ───────┼─ HTTPS ──►│ /api/v1/audit/*      │
 │        token de auditoría           │           │ (datos minimizados)  │
 └─────────────────────────────────────┘           └──────────────────────┘
```

- El servidor MCP corre **en tu equipo**, como un programa que Claude abre. No se instala nada en el servidor de Shinji SOC.
- Usa tu cuenta de Claude: **no necesita una API key de Anthropic**. Cada auditoría consume parte del límite de uso de tu plan.
- Se autentica ante el panel con un **token de auditoría**, distinto de tu usuario y tu MFA. Ese token solo da acceso a los endpoints de auditoría.
- Los datos llegan **minimizados**: los servidores como H1, H2…, las IPs como seudónimos, y nunca nombres de usuario ni rutas personales. El detalle está en la [referencia técnica](REFERENCIA.md#auditoría-de-la-ia-local-con-claude-code-mcp).

Con dos herramientas:

- **`obtener_informe`**: trae un lote de textos de la IA local todavía sin auditar, con los datos necesarios para juzgarlos.
- **`enviar_auditoria`**: guarda el veredicto de cada texto (correcto o corregido) y las reglas nuevas. Las correcciones reemplazan el texto en el panel y se marcan "corregida por Claude".

## Requisitos

- **Claude Code** o **Claude Desktop**, con tu cuenta iniciada.
- **Python 3.10 o más nuevo** en tu equipo. El servidor MCP solo usa la biblioteca estándar: no hay que instalar paquetes.
- Que tu equipo llegue al panel por la misma dirección con la que lo abres en el navegador.
- Rol **super admin** en el panel, para generar el token.

## 1. Genera el token de auditoría

En el panel: **Configuración > Inteligencia artificial > Auditoría con Claude Code > Generar nuevo**. Pide tu código MFA.

El panel nunca muestra el token completo, solo cómo termina: se guarda en el `.env` del servidor. Para leerlo, en el servidor de Shinji SOC, dentro de la carpeta del proyecto:

```bash
grep AUDIT_API_TOKEN .env
```

> **Trátalo como una contraseña.** Con él se pueden leer los datos minimizados y cambiar los textos de la IA. No lo subas a ningún repositorio.

**Si Claude corre en el mismo equipo que el panel**, dentro de la carpeta del proyecto, puedes saltarte este paso de copiar: el servidor MCP lee el token directamente del `.env` de esa carpeta.

## 2. Consigue el servidor MCP

Es un solo archivo. Si ya clonaste el repositorio en tu equipo, está en `tools/mcp_audit/server.py`. Si no, descárgalo:

```bash
curl -fsSL https://raw.githubusercontent.com/Andy1218100/Shinji-SOC/main/tools/mcp_audit/server.py -o server.py
```

Guárdalo en una carpeta fija (por ejemplo `C:\shinji-soc-mcp\server.py` o `~/shinji-soc-mcp/server.py`): Claude lo abre desde esa ruta cada vez.

Comprueba qué Python tienes y su ruta completa:

- **Windows:** `py -0p` o `where python`. Usa la ruta completa de `python.exe` (por ejemplo `C:\Users\tu_usuario\AppData\Local\Programs\Python\Python312\python.exe`): el `python` que trae Windows desde la Microsoft Store a veces es un atajo que no ejecuta nada.
- **Linux y macOS:** `which python3`.

## 3a. Regístralo en Claude Code

Necesitas cuatro datos: la ruta de Python, la ruta de `server.py`, la dirección del panel y el token.

```bash
claude mcp add --scope user \
  -e SHINJI_SOC_URL=https://panel.tudominio.com \
  -e SHINJI_SOC_AUDIT_TOKEN=EL_TOKEN \
  --transport stdio shinji-soc-audit \
  -- /ruta/a/python3 /ruta/a/server.py
```

- `--scope user` lo deja disponible en todos tus proyectos. Con `--scope local` (el valor por defecto) queda solo en la carpeta donde corres el comando.
- `--transport stdio` va entre el último `-e` y el nombre a propósito: si el nombre va justo después de `-e`, Claude Code lo lee como otra variable y rechaza el comando ([documentación de Claude Code](https://code.claude.com/docs/en/mcp)).
- Todo lo que va después de `--` es el comando que abre el servidor.

Con el panel publicado por Cloudflare Tunnel, el certificado es público y no hace falta nada más. Si el panel usa un certificado propio (una CA que no es pública), agrega `-e SHINJI_SOC_CA_FILE=/ruta/a/ca.crt` con el certificado raíz de esa CA.

**Ejemplo completo en Windows** (PowerShell, en una sola línea):

```powershell
claude mcp add --scope user -e SHINJI_SOC_URL=https://panel.tudominio.com -e SHINJI_SOC_AUDIT_TOKEN=EL_TOKEN --transport stdio shinji-soc-audit -- C:\Users\tu_usuario\AppData\Local\Programs\Python\Python312\python.exe C:\shinji-soc-mcp\server.py
```

**Comprueba la conexión:**

```bash
claude mcp list
```

`shinji-soc-audit` tiene que aparecer como `✔ Connected`. Dentro de una sesión de Claude Code, `/mcp` muestra lo mismo.

> El alcance `user` guarda la configuración, token incluido, en `~/.claude.json` de tu usuario ([documentación de Claude Code](https://code.claude.com/docs/en/mcp)). No compartas ese archivo.

## 3b. O regístralo en Claude Desktop

1. En Claude Desktop, abre el menú **Claude > Settings… > Developer > Edit Config**. Se abre el archivo `claude_desktop_config.json`, que está en:
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. Agrega el servidor dentro de `mcpServers` (si el archivo ya tiene otros, agrégalo junto a ellos):

   ```json
   {
     "mcpServers": {
       "shinji-soc-audit": {
         "command": "C:\\Users\\tu_usuario\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
         "args": ["C:\\shinji-soc-mcp\\server.py"],
         "env": {
           "SHINJI_SOC_URL": "https://panel.tudominio.com",
           "SHINJI_SOC_AUDIT_TOKEN": "EL_TOKEN"
         }
       }
     }
   }
   ```

   En JSON, las barras invertidas de Windows se escriben dobles. Con un certificado propio, agrega `"SHINJI_SOC_CA_FILE"` con la ruta del certificado raíz de esa CA.

3. **Cierra Claude Desktop por completo y vuelve a abrirlo**: solo lee la configuración al arrancar.

4. Comprueba que aparezca: botón **+** del cuadro de mensaje > **Connectors > Manage connectors** > `shinji-soc-audit`.

Estos pasos y rutas son los de la [guía oficial de MCP para Claude Desktop](https://modelcontextprotocol.io/docs/develop/connect-local-servers).

## Si el panel está en un servidor remoto

Es el caso normal: el servidor MCP corre en tu equipo y se conecta al panel por la dirección de `SHINJI_SOC_URL`, esté donde esté. Según cómo llegues al servidor:

- **Panel publicado con Cloudflare Tunnel:** usa tu dominio (`https://panel.tudominio.com`). Si pusiste Cloudflare Access delante del panel, deja fuera de Access la ruta `/api/v1/audit/`, porque el servidor MCP no puede iniciar sesión en Access.
- **Solo tienes SSH al servidor:** abre un túnel desde tu equipo y usa `SHINJI_SOC_URL=http://localhost:8000`. El tráfico va cifrado dentro de SSH, y funciona aunque el puerto 8000 esté cerrado al exterior (`SERVER_BIND=127.0.0.1`). El túnel tiene que estar abierto mientras uses la auditoría:

  ```bash
  ssh -N -L 8000:127.0.0.1:8000 usuario@servidor
  ```

- **Claude Code en el propio servidor** (por SSH, dentro de la carpeta del proyecto): el servidor MCP lee el token del `.env` y se conecta a `http://localhost:8000` sin configurar nada más.

Lo que no funciona es registrarlo como servidor MCP remoto, por URL: `server.py` solo funciona como programa local que Claude abre (stdio). Siempre hace falta una copia de `server.py` en el equipo donde corre Claude.

## 4. Úsalo

Pídeselo a Claude en lenguaje normal, por ejemplo:

- "Audita las recomendaciones de vulnerabilidades de Shinji SOC con shinji-soc-audit."
- "Revisa los resúmenes de eventos de seguridad pendientes en shinji-soc-audit."
- "Audita los informes de los hosts de Shinji SOC, de a 10."

Claude trae un lote (20 por defecto, hasta 100), lo revisa con los criterios que trae la propia herramienta y guarda el resultado. Las correcciones se ven en el panel en cuanto termina.

- **Ve de a un lote.** Cada lote de vulnerabilidades son unos 4.000 a 5.000 tokens de tu límite de uso.
- **Reglas:** cuando un error se repite, Claude agrega una regla corta (hasta 50 activas) que la IA local usa en sus próximas respuestas. Así mejora sin reentrenar el modelo.
- **Validación:** el panel rechaza las correcciones que citan versiones o CVEs que no están en los datos.

## Cambiar el token o quitar el servidor

**Cambiar el token** (si crees que se filtró): genera uno nuevo en el panel, como en el paso 1. El anterior deja de servir en el momento. Después actualiza el registro:

- Claude Code: quita el servidor y vuelve a agregarlo con el token nuevo.

  ```bash
  claude mcp remove shinji-soc-audit
  ```

- Claude Desktop: cambia el token en `claude_desktop_config.json` y reinicia la app.

Si el servidor MCP lee el token del `.env` local (Claude en el mismo equipo que el panel), no hay que cambiar nada.

**Apagar la auditoría:** en el servidor de Shinji SOC, deja vacío `AUDIT_API_TOKEN=` en el `.env` y reinicia el servidor (`docker compose restart server`); sin token, los endpoints de auditoría responden 403. Después quita el servidor de Claude con `claude mcp remove shinji-soc-audit`.

## Problemas frecuentes

| Mensaje | Qué pasa | Qué hacer |
|---|---|---|
| `Falta el token` | El servidor MCP no recibió el token. | Revisa `SHINJI_SOC_AUDIT_TOKEN` en el registro. |
| `respondio 403: Auditoria externa desactivada` | El panel no tiene token de auditoría. | Genéralo en Configuración (paso 1). |
| `respondio 401: Token de auditoria invalido` | El token no coincide con el del panel. | Copia de nuevo el valor de `AUDIT_API_TOKEN` del `.env` del servidor. |
| `No se pudo conectar ... CERTIFICATE_VERIFY_FAILED` | Tu equipo no confía en el certificado del panel. | Con Cloudflare Tunnel no debería pasar: revisa que `SHINJI_SOC_URL` sea tu dominio. Con un certificado propio, usa `SHINJI_SOC_CA_FILE`. |
| `No se pudo conectar ... Connection refused` o `timed out` | La dirección no es correcta o no se llega al panel. | Usa la misma dirección que en el navegador. Con `SERVER_BIND=127.0.0.1`, `http://IP:8000` solo funciona desde el propio servidor: usa `https://`. |
| `SHINJI_SOC_CA_FILE apunta a un archivo que no existe` | La ruta del certificado está mal. | Corrígela; en Windows, usa la ruta completa. |
| `✘ Failed to connect` en `claude mcp list` | Claude no pudo abrir el servidor. | Comprueba la ruta de Python y de `server.py` corriendo el mismo comando en una terminal: tiene que quedarse esperando, sin errores (sal con Ctrl+C). |

En Claude Desktop, los errores del servidor quedan en `mcp-server-shinji-soc-audit.log`, en `%APPDATA%\Claude\logs` (Windows), `~/Library/Logs/Claude` (macOS) o `~/.config/Claude/logs` (Linux), según la [guía oficial de MCP](https://modelcontextprotocol.io/docs/develop/connect-local-servers).
