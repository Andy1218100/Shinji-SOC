import unittest

from app.services import ai, audit
from tests.helpers import host


class AITests(unittest.TestCase):
    def test_degenerate_detects_foreign_scripts(self):
        self.assertTrue(ai.looks_degenerate("当然了，首先要明确的一点是 blackmail[@inka请_ToDevice"))
        self.assertFalse(ai.looks_degenerate("Actualizar el paquete apt a la version corregida."))

    def test_ungrounded_identifiers(self):
        source = "paquete cifs-utils 2:7.4-1+deb13u2 DEBIAN-CVE-2014-2830 before 6.4 versiones: 3.0.4"
        self.assertEqual(ai.ungrounded_identifiers("Actualizar a 3.0.4 corrige CVE-2014-2830.", source), [])
        self.assertEqual(ai.ungrounded_identifiers("Usar 7.4 o 6.4.", source), [])
        self.assertEqual(ai.ungrounded_identifiers("Actualizar a 2.6.0 por CVE-2026-109518.", source),
                         ["CVE-2026-109518", "2.6.0"])


class AuditScrubTests(unittest.TestCase):
    def setUp(self):
        self.hosts = [host()]
        self.aliases = {"h1": "H1"}

    def test_removes_host_identifiers_and_personal_data(self):
        text = "En AMP (amp.example.org, 192.168.100.20) el usuario /home/andy/x escribio a ana@example.org desde 10.0.0.7"
        out = audit.scrub(text, self.hosts, self.aliases)
        for leak in ("AMP", "amp.example.org", "192.168.100.20", "andy", "ana@example.org", "10.0.0.7"):
            self.assertNotIn(leak, out)
        self.assertIn("H1", out)

    def test_keeps_version_numbers(self):
        # Regresion: el patron IPv4 generico borraba "7.1.1.43" (version de imagemagick).
        out = audit.scrub("Actualizar imagemagick 7.1.1.43 a 7.1.2.31", self.hosts, self.aliases)
        self.assertIn("7.1.1.43", out)


if __name__ == "__main__":
    unittest.main()
