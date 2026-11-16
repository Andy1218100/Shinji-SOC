---
name: Prox Secure
description: Monitoreo + SOC autohosteado — dashboard SaaS oscuro convencional, ejecutado sin atajos
colors:
  surface-0: "#0a0c10"
  surface-1: "#11141b"
  surface-2: "#171b24"
  surface-3: "#1e232f"
  border: "#262b37"
  border-strong: "#343b4a"
  text-primary: "#e9ebf0"
  text-secondary: "#9aa2b2"
  text-muted: "#656d7d"
  accent: "#5b8def"
  accent-hover: "#6f9bf2"
  ok: "#3ec281"
  warn: "#e0a030"
  crit: "#e5595c"
typography:
  heading:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.01em"
  body:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    letterSpacing: "0.04em"
rounded:
  sm: "6px"
  md: "10px"
  lg: "14px"
spacing:
  1: "4px"
  2: "8px"
  3: "12px"
  4: "16px"
  5: "24px"
  6: "32px"
  8: "48px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface-0}"
    rounded: "{rounded.sm}"
    padding: "7px 14px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
  button-secondary:
    backgroundColor: "{colors.surface-2}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.sm}"
    padding: "7px 14px"
---

# Design System: Prox Secure

## Overview

Prox Secure's dashboard is the standing-exit direction, chosen explicitly
over two offered custom visual worlds (a nautical harbor-pilot chart, a
tradesperson's service ledger — both shown and declined). It is the
category-standard dark SaaS ops dashboard, executed at the craft level of
Linear/Vercel (typographic restraint, whitespace), Grafana/Datadog
(data-dense, scan-fast), Tailwind UI/shadcn (clean baseline) — not a
thinner version of any of them. There is no invented metaphor here on
purpose: the brief's own words were "salida segura... sin identidad
propia," and the commitment is to execute that convention without
irony or a smuggled quirk, not to dress it up after the fact.

**Key characteristics:**
- Near-black layered surfaces, never pure black.
- One accent color, reserved for interactive/brand elements only.
- Status (ok/warn/crit) communicated by color *and* text together, never
  color alone — a colored dot plus a label, or a tinted badge.
- Tables over card grids for anything meant to be scanned in bulk.
- Inter throughout; no serif, no display face. Personality lives in
  restraint and density, not expression.

## Colors

Three roles: a near-black surface stack, one accent, and three status
hues used strictly as semantics.

### Primary
- **Accent blue** (`#5b8def`, hover `#6f9bf2`): the one interactive/brand
  color — links, primary buttons, active nav state, focus rings. Never
  used decoratively.

### Neutral
- **Surface 0** (`#0a0c10`): page background.
- **Surface 1** (`#11141b`): sidebar, panel backgrounds, raised cards.
- **Surface 2** (`#171b24`): table row hover, secondary buttons, inputs.
- **Surface 3** (`#1e232f`): hover state one step up from surface 2.
- **Border** (`#262b37`) / **Border strong** (`#343b4a`): hairline
  dividers; strong for interactive borders (buttons, inputs).
- **Text primary** (`#e9ebf0`): body and headings.
- **Text secondary** (`#9aa2b2`): supporting copy, metadata.
- **Text muted** (`#656d7d`): placeholders, disabled/idle states.

### Status (semantic only)
- **Ok** (`#3ec281`): healthy host, resolved event, "all clear" state.
- **Warn** (`#e0a030`): elevated metric, warning-severity event.
- **Crit** (`#e5595c`): critical metric, critical-severity event.

### Named Rules
**The Status-Is-Never-Decoration Rule.** Green/amber/red exist only to
answer "is this host/event ok, elevated, or critical." They never appear
as page accents, button variants for non-status actions, or illustration
color. The one UI accent for everything else is the blue.

## Typography

**Body/Heading Font:** Inter (system sans fallback: -apple-system,
Segoe UI). No serif, no distinct display face — this is an Operate
surface; a system/workhorse stack is the right choice here, not a
compromise.

**Character:** Restrained and dense. Headings carry weight (600) and
negative tracking (-0.01em) but stay modest in size (18-22px) — there is
no large display moment anywhere on this surface, by design.

### Hierarchy
- **Page title** (600, 22px, -0.01em): one per page, in the content
  header (`<h1>`).
- **Section heading** (600, 18px): panel titles (`<h2>`) — "Hosts",
  "Eventos de seguridad", etc.
- **Subsection** (600, 15px): rarely used, for a named block inside a
  panel (`<h3>`), mainly empty-state headlines.
- **Body** (400, 14px, 1.5 line-height): default text, table cells.
- **Label** (600, 12px, 0.04em tracking, uppercase): table column
  headers only. This is the one place uppercase + tracking is used —
  never on buttons, nav, or body copy.

### Named Rules
**The One Uppercase Rule.** Uppercase, tracked labels are reserved for
table column headers. Nothing else on the surface uses that treatment —
not buttons, not nav items, not badges.

## Layout

Persistent left sidebar (240px, fixed), content column flows right of
it. Content padding steps from the spacing scale (`--space-6` outer,
`--space-5` between panels). Panels (`section.panel`) are flat
surface-1 cards with a single hairline border and 14px radius — no
shadow; depth comes from the surface-0 → surface-1 → surface-2 stepped
ramp, not elevation shadows.

Tables are the default content shape for anything meant to be scanned:
host list, alerts, security events, blocked IPs. Column widths on the
security-events table are fixed via `<colgroup>` so the AI-summary
column (the longest, most variable content) always gets the largest
fixed share and wraps at word boundaries instead of being squeezed.

**Responsive:** below 860px the sidebar collapses to a horizontal,
scrollable top bar; tables that don't fit scroll horizontally within
their own panel rather than reflowing into cards. This is a density
tool, not a marketing page — tables earn their keep over reflow.

## Elevation & Depth

Flat by default. Surfaces step in lightness (surface-0 through
surface-3) instead of using shadows to convey hierarchy. The one real
shadow in the system is the toast notification, which genuinely floats
above the page.

### Shadow Vocabulary
- **sm** (`0 1px 2px rgba(0,0,0,0.3)`): reserved, not currently used on
  a shipped component.
- **md** (`0 8px 24px rgba(0,0,0,0.35)`): the toast stack only.

### Named Rules
**The Flat-By-Default Rule.** Panels, cards, and table rows never carry
a shadow. If something needs to read as "above" the page rather than
"part of" it (a toast, a future popover/menu), that is the only time
`--shadow-md` applies.

## Shapes

Two radius steps in practice: `--radius-sm` (6px) for buttons, inputs,
and badges; `--radius-lg` (14px) for panels and cards. `--radius-md`
(10px) is reserved for mid-sized containers (the map, the login card
edges round at `--radius-lg`). No pill shapes except the nav badge
(sidebar open-event counter) and the status/severity badges, which use
`border-radius: 999px` deliberately to read as a count/tag rather than
a panel.

## Components

### Buttons
- **Shape:** 6px radius, 1px border, 7px/14px padding (4px/10px for the
  `.sm` row-action variant).
- **Primary:** accent background, dark text (`--on-accent`) — one
  primary action per context (submit a form, approve an event).
- **Secondary (default):** surface-2 background, border-strong border,
  primary text color.
- **Ghost:** transparent until hover, used for lower-emphasis actions
  (Descartar, Desbloquear).
- **Danger:** transparent with a crit-colored border and text; reserved,
  not yet used on a shipped action.
- **Hover/Focus:** background steps up one surface level; `:focus-visible`
  gets a 2px accent outline with 2px offset, themed (not the browser
  default).

### Badges
- **Severity badge:** tinted background (`--{ok,warn,crit}-bg`) with
  solid text in the matching hue — never a solid fill with white text.
- **Nav badge:** solid crit-tinted pill, one per nav item that tracks an
  open count (open security events, open vulnerability findings); hides
  itself at zero (`data-count="0"`) rather than showing an empty "0".

### Status (dot + label)
Every host/host-row status is a colored 8px dot plus a text label in
the matching color, always together. This is the one rule in the whole
system that cannot be relaxed: color alone is never the only signal.

### Stat tiles
Compact counts, not a marketing hero: `surface-2` background, `10px`
radius, a muted uppercase 12px label over a 22px/600 tabular-nums
number. Laid out in an auto-fit grid (`minmax(140px, 1fr)`) so they
reflow from a row to 2×2 on narrow widths without a breakpoint. The
number recolors to `ok`/`warn`/`crit` only when the tile's own meaning
is that status (e.g. the "Criticos" tile); a plain count ("Total
eventos") stays `text-primary`. Used for the attack-map summary
(Seguridad); the same pattern is the one to reach for anywhere else a
page needs "N of something" at a glance — never a full dashboard-style
hero metric.

### Ranked list (top origins)
Rows, not a table, for "top N" lists where the only columns are a rank,
an identifier, and a count: `origins-row` (padding, `surface-2` on
hover), a muted rank number, the identifier at `flex:1`, and a pill
count badge (`surface-3` background, `999px` radius) right-aligned.
Reach for this instead of a table when there's no second dimension to
show per row.

### Map (clusters)
Leaflet with `leaflet.markercluster`, restyled from its default
bright green/yellow/orange to the one accent color: `.cluster-icon` is
an `accent-bg`-filled, `accent`-bordered circle with a tabular-nums
count, no severity-based coloring (a cluster mixes severities, so it
reads as "N events here", not a status). Individual markers below
cluster threshold keep per-severity color (`crit`/`warn`) as circle
markers. Tiles are Esri's Dark Gray Canvas base, used as-is with no CSS
filter. Plain OSM tiles were dropped because tile.openstreetmap.org
started answering "Access blocked" (403), and CartoDB's free `dark_all`
started requiring an API key.

### Cards / Panels
- **Corner:** 14px.
- **Background:** surface-1, flat, 1px surface border.
- **Shadow:** none (see Elevation & Depth).
- **Padding:** `--space-5` (24px).

### Inputs
- **Style:** surface-2 background, border-strong 1px border, 6px radius.
- **Focus:** 2px accent outline, inset by 1px, border switches to accent.
- **Error:** handled by an adjacent inline message in crit text, not by
  recoloring the input itself (see login's `.login-error`).
- **Coverage:** `select`, `number`, `search`, `email`, `url` and `textarea`
  share the text-input surface; `select` gets its own chevron. Checkboxes
  take `accent-color`, and on/off settings use the `.switch` (a checkbox
  with `role="switch"`, accent track when on) with an "Activado" /
  "Desactivado" word beside it. No control ships with the browser's gray.

### Settings form (settings.html)
- **Structure:** sticky section nav on the left (search box on top,
  active section in accent, a warn dot on sections with unsaved
  changes); it becomes a sticky horizontal strip under 860px. A status
  panel opens the page (dot + label per subsystem, each a link to its
  section) so "will alerts reach me / are backups current" is answered
  first.
- **Rows:** `.setting-row` grid, label + help + muted `.env` key on the
  left, control on the right; stacked under 640px. The label is a real
  `<label for>` and the help is wired with `aria-describedby`. "When it
  applies" shows only when it is not immediate.
- **Units:** numbers carry a unit suffix (`s`, `h`, `dias`, or a word)
  and a live human equivalent ("= 10 min"); the catalog label never
  repeats the unit.
- **Sensitive confirmations:** inline panel under the control with an
  MFA field, never `prompt()`. Field errors land under the field that
  failed, the save bar only says which one.

### Navigation
- **Sidebar nav-link:** icon (18px) + label, surface-2 hover background,
  accent-tinted background + accent text when active. Icons are hand-
  authored outline SVGs (1.75 stroke, round caps/joins) — no icon font,
  no emoji.
- **Role-gated items:** a nav link whose destination requires a role
  (today: "Usuarios", admin-only) is omitted from the DOM entirely for
  users without it, not disabled or hidden with CSS — there is nothing
  to discover by inspecting the page.
- **Sidebar user block:** sits above "Cerrar sesion" in the footer,
  two lines — username (`text-primary`, 500) over role label
  (`text-muted`, 12px, "Admin" / "Solo lectura" — the human label, never
  the raw role string).
- **Mobile:** the sidebar becomes a horizontal, scrollable bar; the
  active state and badge carry over unchanged.

### Login (multi-step)
One card, one step visible at a time (the other steps are swapped via
`display`, never stacked or routed to separate pages): credentials
(username + password) → either MFA verify (returning user, one 6-digit
code field) or setup (first login on a temp password — new password
field, QR code, manual-entry secret fallback, code field, all submitted
together as one step). The branch is decided by the server's response to
step one, never guessed client-side. QR renders client-side from the
`otpauth://` URI the server returns — never sent as an image, the secret
never touches a server-rendered page twice. Same card chrome as the rest
of the system (surface-1, 14px radius, border) at a narrower max-width
than a panel, centered on `surface-0`.

### Reveal panel (one-time secret)
For a value only shown once (a generated temporary password): not a
toast — a toast's 4.5s auto-dismiss isn't enough time to read and copy
a password. A persistent panel instead, `warn`-colored border so it
reads as "handle this," the secret in a monospace-set `<code>` tile
plus an explicit copy button, and a manual "Entendido, ocultar" dismiss
— the user closes it, it never times out on its own.

### Toast (replaces blocking alerts)
Fixed bottom-right stack, one per action result, auto-dismiss after
4.5s, `toast-in` keyframe (translateY 6px → 0, opacity 0 → 1). Success
and error variants differ only by the toast's own full border color —
success uses `ok`, error uses `crit`, default uses the neutral border.
No colored left bar; the whole hairline recolors instead.

## Do's and Don'ts

### Do:
- **Do** pair every status color with a text label — dot + word, or
  tinted badge + word. Never color alone.
- **Do** use tables for anything meant to be scanned in volume; reserve
  the empty-state card pattern for the zero-content case only.
- **Do** keep the accent blue to interactive/brand moments; status hues
  stay confined to status.
- **Do** theme the browser-native surfaces (selection, scrollbar, focus
  ring) from the token set — a page assembled from defaults is the
  cheapest tell that it wasn't designed.
- **Do** show the structured fact next to AI-generated prose when both
  exist (e.g. a "Version corregida" column beside an AI recommendation
  paragraph), and say in the UI which one to trust — a small local model
  occasionally gets a number wrong even when told the real one.
- **Do** put a one-time secret (a generated password, a QR/MFA setup) in
  a persistent reveal panel with a manual dismiss — never a toast, never
  anything that disappears before a person can realistically copy it.

### Don't:
- **Don't** add a shadow to a panel, card, or table row — depth comes
  from the surface ramp, not elevation.
- **Don't** introduce a second accent color. One blue, used sparingly,
  is the rule — not a rotating palette per feature.
- **Don't** use `window.alert()` or any blocking native dialog for
  feedback; use the toast system.
- **Don't** reach for a card-grid layout where a table would scan
  faster — this is an Operate surface, not a marketing page.
- **Don't** render a role-gated nav item and hide it with CSS for users
  who lack the role — omit it from the template entirely.
