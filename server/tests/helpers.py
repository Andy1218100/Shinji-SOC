from contextlib import contextmanager
from types import SimpleNamespace

from app.core.config import settings


@contextmanager
def override(**values):
    """Cambia valores de `settings` solo durante el test."""
    old = {k: getattr(settings, k) for k in values}
    try:
        for k, v in values.items():
            setattr(settings, k, v)
        yield
    finally:
        for k, v in old.items():
            setattr(settings, k, v)


def finding(**kw):
    """Hallazgo de prueba con los atributos que usan vuln_scan y audit."""
    base = dict(
        vuln_id="DEBIAN-CVE-2026-0001", summary="buffer overflow", severity="warning", urgency="not yet assigned",
        fixed_version=None, ai_recommendation=None, rec_source=None, not_applicable=None, status="open",
        package_name="pkg", package_version="1.0-1",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def host(name="AMP", hostname="amp.example.org", ip_address="192.168.100.20", host_id="h1", debian_release="13"):
    return SimpleNamespace(id=host_id, name=name, hostname=hostname, ip_address=ip_address,
                           debian_release=debian_release, created_at=None)
