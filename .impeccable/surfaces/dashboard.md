<!-- Written by hand: this machine's Impeccable install has no engine, so
     `impeccable surface-brief write` was not available. Content follows
     the same shape the script would have produced. -->

# Surface brief: dashboard (Login, Monitoreo, Host, Seguridad)

## Job and audience

Operate mode. The people who run Prox Secure for their own servers and for
a small team/clients' servers arrive to do two jobs: confirm infra is
healthy (monitoring), and review/act on security events (SOC) — fast, low
ceremony, with enough trust in the interface to approve a destructive
action (block an IP, kill a process) without hesitation.

## Outcome and proof

Primary actions: glance at host health, open an alert's AI explanation,
review a security event and approve/dismiss its suggested action, check
the attack map, log in. Success: tell "is everything OK" in seconds; when
not, understand why (AI summary) and act with confidence. Evidence: live
API data from the running backend; nothing fabricated.

## Selected direction

Standing exit (canon), confirmed explicitly over two offered custom visual
worlds (nautical chart / technician's ledger). Conventional dark SaaS
admin dashboard, executed at the craft level of Linear/Vercel (typographic
restraint, whitespace), Grafana/Datadog (data-dense, scan-fast), Tailwind
UI/shadcn (clean baseline) — not a lower-effort version of any of them.

## Scope and boundaries

In scope: Login (new), Monitoreo (host list + host detail), Seguridad
(map + events + blocked IPs) — 4 screens as one coherent system (shared
sidebar nav, shared table/badge/button language).

Out of scope: real backend auth/accounts (login is UI only, gates with
the existing single ADMIN_API_KEY via a new lightweight validation
endpoint — no sessions, no per-user roles); alert-rule management UI
(stays API-only).

Must remain untouched: existing API contracts/field names; the real
content of host/event tables; the map's data source.

## States and ranges

Design for 1-10 hosts, 0-5 open events typical, without looking broken or
empty at 1 host / 0 events. States to cover: loading, error (API
unreachable), first-run empty (no hosts yet, with a path to register
one), "all clear" empty (no alerts/events), login failure, AI summary
pending (real, happens for a few seconds after an event fires), long AI
summary text (must not break row layout), many open events (graceful
scroll, never a broken layout).

## Interaction and layout

Persistent left sidebar: product name, nav (Monitoreo / Seguridad with an
open-event-count badge), sign out. Login: centered card, single credential
field, no marketing chrome. Monitoreo: host table as primary content
(not cards), status as colored dot + text label (never color alone),
click-through to host detail. Host: existing chart + AI-ask panel,
structure unchanged. Seguridad: map first (dark tiles, not the current
light OSM), events table with inline per-row actions, blocked IPs table
below. Blocking `window.alert()` calls are replaced by a non-blocking
inline/toast status — a real usability bug found in testing.

## Constraints and open decisions

Stack: FastAPI + Jinja2 + HTMX/vanilla JS stays (no framework rewrite).
Accessibility: no specific requirement confirmed; default to reasonable
contrast/keyboard access. Not to invent: real per-user accounts/roles
backend; final product name (still "Prox Secure" placeholder); an alert-
rule management UI.

---

## Direction contract

THESIS: The category-standard SaaS ops dashboard, executed at full
craft commitment rather than a thinner version of it. Refuses: inventing
a bespoke visual world (nautical-chart and technician's-ledger directions
were drafted, shown, and explicitly declined for this surface).

OWN-WORLD: Near-black layered surfaces (not pure black), one blue accent
reserved for interactive/brand elements, green/amber/red used strictly
as status semantics (never decoration). Inter for all text — no serif,
no display face; personality lives in restraint and density, not
expression. Left sidebar + data-dense tables (not card grids) for
scanning many rows at a glance. Tabular figures on all numeric columns.

STORY: Visitor logs in, lands on Monitoreo, scans the host table — dot
plus label tells them at a glance if anything needs attention. They move
to Seguridad when something does, read the AI explanation inline on the
event row, approve or dismiss with immediate non-blocking feedback (no
alert() dialogs), see the map update, and sign out when done.

FIRST VIEWPORT (Monitoreo, the landing screen): left sidebar (240px,
fixed) with product name, nav items Monitoreo (active) and Seguridad
(badge = open event count), sign out at the bottom. Main column: page
header "Monitoreo", host table spanning the content width (host name
with status dot, CPU, mem, disk, load1, last seen), "Alertas activas"
section below in the same table language. Zero-state card when no hosts
exist yet, with the exact command to register one.

FORM: seed: none (standing exit — canon, not a rolled/catalog direction;
confirmed verbatim by the user choosing "Salida segura: dashboard SaaS
convencional" over both offered directions).

FINISH: unreviewed and undocumented is unfinished; this build ends with
the finish review, the verdict, DESIGN.md, and every shipping raster
carrying its provenance. (No rasters ship on this surface — it is
UI-only, no illustrated assets.)

---

## Build record (2026-11-13)

Built code-led (mandatory for Operate), no comp pipeline available on
this install. Self-reviewed against this contract and craft-floor.md —
the shipped `impeccable-finish-reviewer` subagent is unavailable on this
machine (Markdown-only install), so this is a self-review, disclosed as
such rather than presented as an independent pass.

Inspected at 1440px desktop and 375px mobile, authenticated and
unauthenticated, across all 4 screens. Real defects found and fixed
during the inspection round (not a hypothetical list):

1. SVG icons had no base size rule — the login button's lock icon
   rendered at native/unconstrained size (filled the whole button).
   Fixed with a global `.icon { width: 18px; height: 18px }` default.
2. The dark map tile provider (CartoDB `dark_all`) now requires an API
   key it was never given — tiles rendered as "API KEY REQUIRED"
   watermarks. Replaced with standard OSM tiles plus a CSS `filter`
   (invert/hue-rotate) on the tile pane only, so no external key
   dependency exists for the map at all.
3. The security-events table had no column-width control; the
   AI-summary column collapsed to single-word-per-line wrapping at
   normal table widths. Fixed with an explicit `<colgroup>` and
   `table-layout: fixed`.
4. `Alertas activas` on Monitoreo showed the raw host UUID instead of
   the host's name (pre-existing, caught during this pass; cheap fix,
   in scope since it's the same table being restyled).
5. `loadEvents()`/`loadBlocked()` on Seguridad had no network-failure
   handling — a dead backend left both panels stuck on "Cargando..."
   forever. Added try/catch with a calm error state, matching the
   brief's required error state.
6. Login's submit button disabled on submit but gave no loading label —
   added "Entrando..." text, satisfying the brief's required loading
   state.

Verdict: ship. All six FIRST VIEWPORT/STORY promises in the contract
above hold at both inspected widths. Known, disclosed gaps (not
defects — out of scope per this brief): GeoIP needs the user's own
MaxMind key to show map points; alert-rule management stays API-only.

**Update (2026-11-13):** the "no real backend accounts/roles" gap above
is closed. Real per-user accounts (password + mandatory TOTP MFA),
`admin`/`viewer` roles, and a `/users` management screen shipped — this
was the open decision the shape round's "Modelo de acceso" question
recorded as "usuarios individuales... aunque el backend no lo soporte
todavia." It's now supported. Login was rebuilt as a multi-step flow
(credentials → MFA verify, or → first-login setup: new password + QR
enrollment) instead of the single username+password form the first
build shipped. See DESIGN.md's Login/Reveal panel sections for the
resulting components.
