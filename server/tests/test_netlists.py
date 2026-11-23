import ipaddress
import unittest
from types import SimpleNamespace

from app.services import conn_watch, ids, netlists
from tests.helpers import override


class ProxyTests(unittest.TestCase):
    def test_parse_ip_variants(self):
        self.assertEqual(str(netlists.parse_ip("1.2.3.4:5678")), "1.2.3.4")
        self.assertEqual(str(netlists.parse_ip("[2001:db8::1]:443")), "2001:db8::1")
        self.assertEqual(str(netlists.parse_ip("::ffff:203.0.113.5")), "203.0.113.5")
        self.assertIsNone(netlists.parse_ip("local:tcp/22"))
        self.assertIsNone(netlists.parse_ip("-"))

    def test_cloudflare_is_proxy(self):
        self.assertTrue(netlists.is_proxy("104.16.0.1"))      # rango de Cloudflare
        self.assertTrue(netlists.is_proxy("2606:4700::1"))
        self.assertFalse(netlists.is_proxy("8.8.8.8"))

    def test_trusted_proxies_setting(self):
        with override(trusted_proxies="127.0.0.0/8, ::1, 172.18.0.0/16"):
            self.assertTrue(netlists.is_proxy("172.18.0.5"))
            self.assertTrue(netlists.is_proxy("127.0.0.1"))
        with override(trusted_proxies=""):
            self.assertFalse(netlists.is_proxy("127.0.0.1"))

    def test_resolve_client_uses_forwarded_only_from_proxies(self):
        with override(trusted_proxies="127.0.0.0/8"):
            # Desde un proxy con la IP real en el log: se usa la real.
            self.assertEqual(netlists.resolve_client("104.16.0.1", "203.0.113.9"), ("203.0.113.9", False))
            self.assertEqual(netlists.resolve_client("127.0.0.1", "203.0.113.9, 10.0.0.1"), ("203.0.113.9", False))
            # Desde un proxy sin la IP real: se marca.
            self.assertEqual(netlists.resolve_client("127.0.0.1", None), ("127.0.0.1", True))
            self.assertEqual(netlists.resolve_client("127.0.0.1", "-"), ("127.0.0.1", True))
            # Desde una IP comun, el valor reenviado lo puede inventar cualquiera: se ignora.
            self.assertEqual(netlists.resolve_client("198.51.100.7", "1.1.1.1"), ("198.51.100.7", False))

    def test_threat_match(self):
        saved = netlists._drop
        netlists._drop = [(ipaddress.ip_network("1.10.16.0/20"), "SBL123")]  # rango publico real de DROP
        try:
            with override(threat_intel_enabled=True):
                self.assertIn("SBL123", netlists.threat_match("1.10.16.5"))
                self.assertIsNone(netlists.threat_match("198.51.100.1"))
                self.assertIsNone(netlists.threat_match("local:tcp/22"))
            with override(threat_intel_enabled=False):
                self.assertIsNone(netlists.threat_match("1.10.16.5"))
        finally:
            netlists._drop = saved


class ConnectionEventTests(unittest.TestCase):
    def test_shell_like(self):
        for name in ("bash", "/usr/bin/nc", "python3", "python3.11", "php-fpm8.2", "perl"):
            self.assertTrue(conn_watch._shell_like(name), name)
        for name in ("nginx", "sshd", "postgres", None):
            self.assertFalse(conn_watch._shell_like(name), name)

    def test_prompts_for_new_kinds(self):
        host = SimpleNamespace(name="web-01")
        listener = ids.build_event_prompt(host, "new_listener", "local:tcp/4444",
                                          {"proto": "tcp", "port": 4444, "address": "0.0.0.0", "process": "nc",
                                           "cmdline": "nc -lvp 4444", "user": "www-data", "pid": 9}, "kill_process")
        self.assertIn("tcp/4444", listener)
        self.assertIn("terminar el proceso PID 9", listener)
        outbound = ids.build_event_prompt(host, "service_outbound", "203.0.113.9",
                                          {"remote_port": 4444, "user": "www-data", "cmdline": "bash -i"}, None)
        self.assertIn("reverse shell", outbound)
        self.assertIn("No hay ninguna accion automatica", outbound)
        proxied = ids.build_event_prompt(host, "path_scan", "104.16.0.1",
                                         {"path": "/.env", "method": "GET", "detras_de_proxy": True}, None)
        self.assertIn("proxy o tunel", proxied)


if __name__ == "__main__":
    unittest.main()
