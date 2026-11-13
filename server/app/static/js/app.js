// Prox Secure — shared client behavior: auth guard, toasts, sidebar badge.

const AUTH_KEY = "proxsecure_admin_key";

function getAdminKey() {
  try {
    return localStorage.getItem(AUTH_KEY) || "";
  } catch (e) {
    return "";
  }
}

function setAdminKey(value) {
  try {
    localStorage.setItem(AUTH_KEY, value);
  } catch (e) {
    /* private browsing / storage blocked: session still works, just not remembered */
  }
}

function clearAdminKey() {
  try {
    localStorage.removeItem(AUTH_KEY);
  } catch (e) {
    /* nothing to clear */
  }
}

function adminHeaders() {
  return { "X-Admin-Key": getAdminKey() };
}

function requireAuth() {
  if (!getAdminKey()) {
    const next = encodeURIComponent(window.location.pathname);
    window.location.href = `/login?next=${next}`;
  }
}

function signOut() {
  clearAdminKey();
  window.location.href = "/login";
}

function toast(message, variant = "default") {
  let stack = document.querySelector(".toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.className = "toast-stack";
    document.body.appendChild(stack);
  }
  const el = document.createElement("div");
  el.className = `toast ${variant}`;
  el.textContent = message;
  stack.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

async function adminAction(url, method = "POST") {
  if (!getAdminKey()) {
    toast("Inicia sesion para hacer esto.", "error");
    return null;
  }
  const res = await fetch(url, { method, headers: adminHeaders() });
  if (res.status === 401) {
    toast("Tu clave ya no es valida. Inicia sesion de nuevo.", "error");
    clearAdminKey();
    return null;
  }
  if (!res.ok) {
    toast(`La accion fallo (HTTP ${res.status}).`, "error");
    return null;
  }
  return res;
}

async function refreshNavBadge() {
  const badge = document.querySelector('.nav-badge[data-nav="security"]');
  if (!badge) return;
  try {
    const res = await fetch("/api/v1/security-events?status=open");
    const events = await res.json();
    badge.textContent = events.length;
    badge.dataset.count = String(events.length);
  } catch (e) {
    /* badge stays at its last known value */
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const signoutBtn = document.querySelector("[data-action='sign-out']");
  if (signoutBtn) signoutBtn.addEventListener("click", signOut);
  refreshNavBadge();
});
