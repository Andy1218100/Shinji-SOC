# Shinji SOC

**Monitoreo y centro de operaciones de seguridad (SOC) autoalojado para tus propios servidores, con IA local.**

[English](README.en.md) · [Instalación](docs/INSTALACION.md) · [Manual de MFA](docs/MFA.md) · [Referencia técnica](docs/REFERENCIA.md)

Shinji SOC vigila servidores Linux (Debian, Ubuntu, Proxmox VE) desde un panel web que corre en tu propia infraestructura. Un agente liviano en cada servidor manda métricas, logs de acceso, inicios de sesión e inventario de paquetes. El servidor detecta ataques, busca vulnerabilidades y usa una IA que corre en el mismo equipo para explicar qué pasó y qué hacer. Ningún dato sale de tu red salvo que lo decidas.

## Qué hace

- **Monitoreo:** CPU, memoria, disco y red de cada servidor, con reglas de alerta por umbral.
- **Detección de intrusos:** escaneos de rutas web, flood HTTP, fuerza bruta por SSH y en la web de Proxmox, inicios de sesión después de varios fallos y procesos sospechosos en cuentas de servicio (posibles webshells).
- **Respuesta con aprobación:** cada evento trae una acción sugerida (bloquear la IP con fail2ban o terminar el proceso). Nada se ejecuta sin que un administrador lo apruebe.
- **Mapa de ataques:** origen geolocalizado de cada ataque, con la base gratuita GeoLite2 de MaxMind.
- **Vulnerabilidades:** cruza los paquetes instalados contra [OSV.dev](https://osv.dev) y separa lo que tiene parche de lo que no.
- **IA local:** Ollama (`qwen2.5:3b`) explica eventos, alertas y vulnerabilidades en lenguaje simple, sin GPU ni servicios externos. Claude es opcional.
- **Notificaciones:** Telegram, ntfy o correo.
- **Cuentas con MFA obligatorio:** roles super admin, admin y solo lectura; códigos de respaldo de un solo uso.
- **Operación:** HTTPS integrado (Caddy), respaldos automáticos, retención de datos y configuración desde el propio panel.

## Requisitos

- **Servidor:** Docker con Compose v2 (Linux, o Docker Desktop en Windows/macOS), 6 GB de memoria libres para Docker y 20 GB de disco. No hace falta GPU.
- **Servidores vigilados:** Debian, Ubuntu o derivados con `systemd`, y acceso como root.

## Inicio rápido

```bash
git clone https://github.com/Andy1218100/shinji-soc.git
cd shinji-soc
cp .env.example .env    # cambia POSTGRES_PASSWORD y SESSION_SECRET_KEY
docker compose up -d --build
docker compose exec ollama ollama pull qwen2.5:3b
docker compose logs server | grep "Codigo de instalacion"
```

Abre `https://localhost` (o `http://localhost:8000`), escribe el código de instalación, crea la cuenta super admin y activa el MFA con tu teléfono. Después agrega tus servidores desde **Monitoreo > + Nuevo host**: el panel muestra el comando exacto para correr `agent/install.sh` en cada uno.

El paso a paso completo, con HTTPS para la red local o un dominio, los agentes y la solución de problemas, está en el [manual de instalación](docs/INSTALACION.md).

## Documentación

| Documento | Para qué |
|---|---|
| [Manual de instalación](docs/INSTALACION.md) | Instalar el servidor, configurar HTTPS, agregar servidores, respaldar, actualizar y desinstalar. |
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
