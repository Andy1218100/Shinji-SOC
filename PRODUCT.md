# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

People who run their own Linux servers and are responsible for both keeping
them healthy and keeping them safe: the owner themselves, plus a small team
or clients they administer servers for. Each person has their own account
(password + mandatory MFA), with an `admin` or `viewer` role — see
Capabilities and Constraints.

## Product Purpose

A self-hosted system that combines traditional infrastructure monitoring
(CPU/memory/disk/network, threshold alerts) with a lightweight SOC layer
(intrusion detection from logs and process behavior, geolocated attack
visibility, human-approved active response) for Linux servers. Every alert
and security event gets a plain-language explanation from AI. Success means
the operator can see server health and active attacks against it in one
place, without depending on a SaaS vendor, and can respond without risking
an outage from an automated false positive.

## Positioning

Combines ops monitoring (Zabbix-style metrics/alerts) and SOC-style
intrusion detection in one self-hosted, lightweight tool — explained by a
local AI model by default, not a cloud dependency — where detection never
acts on its own: every block or kill requires human approval. The
alternative isn't a single competitor but a gap between two extremes: pure
monitoring tools (Zabbix) have no security layer, and real SOC platforms
(evaluated AiSOC as reference: Kafka, Neo4j, ClickHouse, 20+ microservices)
are enterprise-scale and too heavy to self-host for a small operator.

## Operating Context

Linux servers (Debian/Ubuntu-family, via apt and fail2ban) running real
workloads — some personal/learning projects, some real business
infrastructure with actual users; both are in scope from day one, not just
a toy use case. The central server and dashboard run via Docker Compose
(developed on Windows with Docker Desktop, deployed on Linux). A lightweight
Python agent installs via systemd on each monitored host: sends metrics,
tails web server access logs, watches service-account processes, and
executes admin-approved actions through narrowly scoped sudo rules
(fail2ban commands and a guarded process-kill script only).

## Capabilities and Constraints

- Metrics: CPU/mem/disk/network/load per host, threshold-based alert rules,
  AI-generated explanations for triggered alerts.
- Intrusion detection: path-scan and brute-force/flood detection, parsed
  only from nginx/apache "combined" access log format — other log formats
  are not parsed and those lines are silently skipped.
- Process anomaly detection: a fixed blacklist of binaries (shells,
  interpreters, network tools) flagged when run under configured
  service-account users (e.g. www-data). This is heuristic by design and
  expected to false-positive on apps that legitimately shell out — it is
  always suggest-only, never automatic.
- GeoIP attack map: optional. Requires the operator's own MaxMind GeoLite2
  license key; without it, events show in the list with no map point.
- AI backends: Ollama running locally by default — `qwen2.5:3b`, chosen
  after measuring `llama3.1:8b` take ~9 minutes per response on CPU on the
  dev machine (no GPU). Claude is available as an alternate/supplementary
  backend via the operator's own Anthropic API key, never required.
- Response actions (block IP via fail2ban, kill a process) always require
  manual approval from the dashboard before the agent executes them; there
  is no autonomous blocking path.
- Access control (resolved 2026-11-13): individual accounts, each with
  its own password and mandatory TOTP MFA (enrolled at first login, QR
  shown only to that person, never relayed by whoever created the
  account). Two roles — `admin` (full access, including managing other
  accounts from `/users`) and `viewer` (read everything, act on
  nothing). The old single shared `ADMIN_API_KEY` is gone entirely,
  including from scripted/API access. Still missing: no audit trail of
  who approved/dismissed a specific action (accounts exist, actions
  don't record which account took them), no password-reset-by-email
  (no mail service in the project — an admin resets a stuck account's
  password from `/users` instead).
- "Learning" from traffic is heuristic — rule matching and counters in a
  sliding window, not a trained ML model. Must not be described as machine
  learning or AI-trained detection in product copy.

## Brand Commitments

None confirmed. "Prox Secure" is a working name only, inherited from the
project folder — not a confirmed product name. Final naming is an open
decision; no logo or visual identity exists yet.

**Visual direction (standing preference, confirmed 2026-11-13):** the
dashboard takes the category-standard SaaS admin look, played straight —
no custom visual world (a nautical/chart identity and a tradesperson-ledger
identity were offered and declined in favor of this). Craft bar: Linear /
Vercel (minimalist, typographic restraint), Grafana / Datadog (dense,
data-forward, built to scan fast), Tailwind UI / shadcn (clean generic
baseline). Execute the convention at that level of polish, not a
lower-effort version of it.

## Evidence on Hand

None yet. No real customers, testimonials, case studies, or production
deployments — this is a freshly built local dev stack, not yet deployed to
a real server. Future work must not fabricate any of the above.

## Product Principles

1. Self-hosted and local-first: core function (monitoring, detection, AI
   explanation) must work without a third-party SaaS; cloud AI (Claude) is
   opt-in, never required.
2. Nothing acts on its own: every security response requires a human's
   explicit approval, regardless of detection confidence.
3. Honest about what detection actually is: heuristics and counters, not a
   trained model — never oversell this as "learning" or "AI-trained" in UI
   copy or docs.
4. Practical on ordinary hardware: the default AI model must work without a
   GPU; don't assume high-end infrastructure.
5. Built for small-scale operators and their clients, not enterprise SOC
   teams: stays simple enough for one person or a small team to run, not a
   platform with dozens of services.
