# Shinji SOC

**Monitoreo y centro de operaciones de seguridad (SOC) autoalojado para tus propios servidores, con IA local.**

[English](README.en.md) · [Instalación](docs/INSTALACION.md) · [Agente](docs/AGENTE.md) · [MCP con Claude](docs/MCP.md) · [Manual de MFA](docs/MFA.md) · [Referencia técnica](docs/REFERENCIA.md)

Shinji SOC vigila servidores Linux (Debian, Ubuntu, Proxmox VE) desde un panel web que corre en tu propia infraestructura. Un agente liviano en cada servidor manda métricas, logs de acceso, inicios de sesión e inventario de paquetes. El servidor detecta ataques, busca vulnerabilidades y usa una IA que corre en el mismo equipo para explicar qué pasó y qué hacer. Ningún dato sale de tu red salvo que lo decidas.

## Qué hace

- **Monitoreo:** CPU, memoria, disco y red de cada servidor, con reglas de alerta por umbral.
- **Detección de intrusos:** escaneos de rutas web, flood HTTP, fuerza bruta por SSH y en la web de Proxmox, inicios de sesión después de varios fallos y procesos sospechosos en cuentas de servicio (posibles webshells).
- **Respuesta con aprobación:** cada evento trae una acción sugerida (bloquear la IP con fail2ban o terminar el proceso). Nada se ejecuta sin que un administrador lo apruebe.
- **Mapa de ataques:** origen geolocalizado de cada ataque, con la base gratuita GeoLite2 de MaxMind.
- **Vulnerabilidades:** cruza los paquetes instalados contra [OSV.dev](https://osv.dev) y separa lo que tiene parche de lo que no.
- **IA local:** Ollama (`qwen2.5:3b`) explica eventos, alertas y vulnerabilidades en lenguaje simple, sin GPU ni servicios externos. Claude es opcional.
- **Auditoría con Claude (MCP):** un servidor MCP permite que Claude Code o Claude Desktop revisen y corrijan los textos de la IA local con tu plan de Claude (sin API key de Anthropic) y con datos minimizados. Ver la [guía del servidor MCP](docs/MCP.md).
- **Notificaciones:** Telegram, ntfy o correo.
- **Cuentas con MFA obligatorio:** roles super admin, admin y solo lectura; códigos de respaldo de un solo uso.
- **Operación:** HTTPS integrado (Caddy), respaldos automáticos, retención de datos y configuración desde el propio panel.

## Requisitos

- **Servidor:** Docker con Compose v2 (Linux, o Docker Desktop en Windows/macOS), 6 GB de memoria libres para Docker y 20 GB de disco. No hace falta GPU.
- **Servidores vigilados:** Debian, Ubuntu o derivados con `systemd`, y acceso como root.

## Inicio rápido

```bash
git clone https://github.com/Andy1218100/Shinji-SOC.git
cd Shinji-SOC
cp .env.example .env    # cambia POSTGRES_PASSWORD y SESSION_SECRET_KEY
docker compose up -d --build
docker compose exec ollama ollama pull qwen2.5:3b
docker compose logs server | grep "Codigo de instalacion"
```

Abre `https://localhost` (o `http://localhost:8000`), escribe el código de instalación, crea la cuenta super admin y activa el MFA con tu teléfono. Después agrega tus servidores desde **Monitoreo > + Nuevo host**: el panel muestra el comando exacto para correr `agent/install.sh` en cada uno.

El paso a paso completo, con HTTPS para la red local o un dominio, los agentes y la solución de problemas, está en el [manual de instalación](docs/INSTALACION.md).

### Agente: instalar y desinstalar

En cada servidor Linux que quieres vigilar, como root (la API key la muestra el panel una sola vez, al crear el servidor):

```bash
curl -fsSL https://raw.githubusercontent.com/Andy1218100/Shinji-SOC/main/agent/install.sh -o /tmp/install.sh
sudo bash /tmp/install.sh https://TU_PANEL LA_API_KEY [/tmp/shinji-soc-ca.crt]
```

El tercer argumento es el certificado raíz de la CA de Caddy y solo hace falta si el panel usa `PANEL_TLS=tls internal`. Para quitar el agente y todo lo que instaló (servicio, usuario, sudoers, jail de fail2ban y los permisos de lectura dados desde el panel):

```bash
sudo shinji-soc-uninstall --dry-run   # muestra lo que haría
sudo shinji-soc-uninstall             # pide escribir QUITAR
```

Después borra el servidor del panel (**Monitoreo** > el servidor > **Eliminar**). Todo el detalle está en la [guía del agente](docs/AGENTE.md).

## Documentación

| Documento | Para qué |
|---|---|
| [Manual de instalación](docs/INSTALACION.md) | Instalar el servidor, configurar HTTPS, agregar servidores, respaldar, actualizar y desinstalar. |
| [Guía del agente](docs/AGENTE.md) | Instalar y desinstalar el agente en cada servidor que quieres vigilar, qué datos manda y cómo resolver problemas de conexión. |
| [Servidor MCP con Claude](docs/MCP.md) | Conectar Claude Code o Claude Desktop para auditar y corregir los textos de la IA local, con datos minimizados. |
| [Manual de MFA](docs/MFA.md) | Para cada persona que usa el panel: primer ingreso, códigos de respaldo, cambio de teléfono. |
| [Referencia técnica](docs/REFERENCIA.md) | Cómo funciona cada parte, la API, la auditoría con Claude Code, desarrollo y limitaciones. |

## Limitaciones

- La detección es heurística (reglas y conteos), no un modelo de aprendizaje automático: puede tener falsos positivos y no detecta ataques sofisticados.
- Los logs web tienen que estar en formato *combined* de nginx/apache.
- La IA local es un modelo chico: sus textos se validan, pero los datos de vulnerabilidades siempre vienen de OSV, no de la IA.
- Está pensado para infraestructura propia. Si expones el panel a internet, hazlo solo por HTTPS.

Más detalles en la [referencia técnica](docs/REFERENCIA.md#limitaciones-conocidas).

## Licencia

[MIT](LICENSE) © 2026 andy
