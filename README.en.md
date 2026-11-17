# Shinji SOC

**Self-hosted monitoring and security operations center (SOC) for your own servers, with a local AI.**

[Español](README.md) · [Installation (Spanish)](docs/INSTALACION.md) · [MFA guide (Spanish)](docs/MFA.md) · [Technical reference (Spanish)](docs/REFERENCIA.md)

Shinji SOC watches Linux servers (Debian, Ubuntu, Proxmox VE) from a web panel that runs on your own infrastructure. A lightweight agent on each server sends metrics, access logs, logins and the package inventory. The server detects attacks, looks for vulnerabilities and uses an AI that runs on the same machine to explain what happened and what to do. No data leaves your network unless you choose so.

> The panel and the detailed guides are in Spanish. This page summarizes them.

## Features

- **Monitoring:** CPU, memory, disk and network for each server, with threshold alert rules.
- **Intrusion detection:** web path scans, HTTP floods, SSH and Proxmox web brute force, logins after repeated failures, and suspicious processes under service accounts (possible webshells).
- **Response with approval:** each event comes with a suggested action (block the IP with fail2ban or kill the process). Nothing runs until an administrator approves it.
- **Attack map:** geolocated origin of each attack, using MaxMind's free GeoLite2 database.
- **Vulnerabilities:** matches installed packages against [OSV.dev](https://osv.dev) and separates what has a fix from what doesn't.
- **Local AI:** Ollama (`qwen2.5:3b`) explains events, alerts and vulnerabilities in plain language, with no GPU and no external service. Claude is optional.
- **Notifications:** Telegram, ntfy or email.
- **Accounts with mandatory MFA:** super admin, admin and read-only roles; single-use recovery codes.
- **Operations:** built-in HTTPS (Caddy), automatic backups, data retention and configuration from the panel itself.

## Requirements

- **Server:** Docker with Compose v2 (Linux, or Docker Desktop on Windows/macOS), 6 GB of free memory for Docker and 20 GB of disk. No GPU needed.
- **Monitored servers:** Debian, Ubuntu or derivatives with `systemd`, and root access.

## Quick start

```bash
git clone https://github.com/Andy1218100/Shinji-SOC.git
cd Shinji-SOC
cp .env.example .env    # change POSTGRES_PASSWORD and SESSION_SECRET_KEY
docker compose up -d --build
docker compose exec ollama ollama pull qwen2.5:3b
docker compose logs server | grep "Codigo de instalacion"
```

Open `https://localhost` (or `http://localhost:8000`), enter the installation code, create the super admin account and enable MFA with your phone. Then add your servers from **Monitoreo > + Nuevo host**: the panel shows the exact command to run `agent/install.sh` on each server.

The full step-by-step guide (HTTPS for a local network or a public domain, agents, backups, troubleshooting) is in the [installation manual](docs/INSTALACION.md), in Spanish.

## Limitations

- Detection is heuristic (rules and counters), not a machine learning model: it can produce false positives and does not catch sophisticated attacks.
- Web logs must use the nginx/apache *combined* format.
- The local AI is a small model: its text is validated, but vulnerability data always comes from OSV, never from the AI.
- It is meant for your own infrastructure. If you expose the panel to the internet, do it over HTTPS only.

## License

[MIT](LICENSE) © 2026 andy
