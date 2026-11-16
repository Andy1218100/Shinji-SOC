// Prox Secure — shared client behavior: toasts, sign-out, sidebar badges.
// La sesion vive en una cookie HttpOnly (no en localStorage): el navegador
// la manda sola en cada fetch del mismo origen, el JS nunca la toca.

async function signOut() {
  try {
    await fetch("/api/v1/auth/logout", { method: "POST" });
  } catch (e) {
    /* si falla igual mandamos al login */
  }
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
  const res = await fetch(url, { method });
  if (res.status === 401) {
    toast("Tu sesion expiro. Inicia sesion de nuevo.", "error");
    window.location.href = "/login?next=" + encodeURIComponent(window.location.pathname);
    return null;
  }
  if (res.status === 403) {
    toast("Tu cuenta no tiene permiso para esta accion (rol solo lectura).", "error");
    return null;
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const data = await res.clone().json();
      if (data && data.detail) detail = data.detail;
    } catch (e) { /* cuerpo no era JSON */ }
    toast(`La accion fallo: ${detail}`, "error");
    return null;
  }
  return res;
}

async function refreshNavBadgeFor(navName, url) {
  const badge = document.querySelector(`.nav-badge[data-nav="${navName}"]`);
  if (!badge) return;
  try {
    const res = await fetch(url);
    if (!res.ok) return;
    const items = await res.json();
    badge.textContent = items.length;
    badge.dataset.count = String(items.length);
  } catch (e) {
    /* badge stays at its last known value */
  }
}

function refreshNavBadge() {
  refreshNavBadgeFor("security", "/api/v1/security-events?status=open");
  // Solo lo que tiene solucion publicada: lo que no tiene parche se ve en
  // la pagina como aviso, pero no suma al contador.
  refreshNavBadgeFor("vulnerabilities", "/api/v1/vulnerabilities?status=open&actionable=true");
}

document.addEventListener("DOMContentLoaded", () => {
  const signoutBtn = document.querySelector("[data-action='sign-out']");
  if (signoutBtn) signoutBtn.addEventListener("click", signOut);
  refreshNavBadge();
});
