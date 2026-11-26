"""Lectura del registro del WAF (ModSecurity, JSON). La forma de las lineas
es la que escribio ModSecurity 3.0.14 + CRS 3.3.7 de Debian 13 en una prueba
real (recortada a los campos que se usan)."""

import json
import os
import tempfile
import unittest
from datetime import datetime
from unittest import mock

import support  # noqa: F401

import waf_watch


def msg(rule_id, text, severity="2", attack=None, data=""):
    tags = ["application-multi", "paranoia-level/1"] + ([f"attack-{attack}"] if attack else [])
    return {"message": text, "details": {"ruleId": rule_id, "severity": severity, "data": data, "tags": tags}}


def line(messages, engine="DetectionOnly", code=200, uri="/?id=1%27%20UNION%20SELECT%20password%20FROM%20users--"):
    return json.dumps({"transaction": {
        "client_ip": "198.51.100.77", "time_stamp": "Thu Nov 26 13:17:07 2026",
        "request": {"method": "GET", "uri": uri,
                    "headers": {"Host": "web.example.com", "Cookie": "session=secreta"}},
        "response": {"http_code": code, "body": "<html>pagina</html>"},
        "producer": {"secrules_engine": engine},
        "messages": messages,
    }})


SQLI = [
    msg("920350", "Host header is a numeric IP address", "4", "protocol"),
    msg("942100", "SQL Injection Attack Detected via libinjection", attack="sqli",
        data="Matched Data: sUEnk found within ARGS:id: 1' UNION SELECT password FROM users--"),
    msg("942270", "Looking for basic sql injection.", attack="sqli"),
    msg("942100", "SQL Injection Attack Detected via libinjection", attack="sqli"),
    msg("949110", "Inbound Anomaly Score Exceeded (Total Score: 23)", attack=None),
]


class ParseTests(unittest.TestCase):
    def test_attack_over_threshold(self):
        e = waf_watch.parse_line(line(SQLI))
        self.assertEqual((e["ip"], e["method"], e["host"], e["status_code"]), ("198.51.100.77", "GET", "web.example.com", 200))
        self.assertEqual(e["score"], 23)
        self.assertFalse(e["blocked"])
        self.assertEqual([r["id"] for r in e["rules"]], ["920350", "942100", "942270"])  # sin repetir ni la 949110
        self.assertEqual(e["rules"][1]["attack"], "sqli")
        self.assertEqual(e["rules"][1]["severity"], "critica")
        # Hora local del host, ahora con su zona.
        self.assertIsNotNone(datetime.fromisoformat(e["ts"]).tzinfo)

    def test_never_sends_headers_or_bodies(self):
        text = json.dumps(waf_watch.parse_line(line(SQLI)))
        self.assertNotIn("secreta", text)
        self.assertNotIn("pagina", text)

    def test_below_threshold_is_ignored(self):
        self.assertIsNone(waf_watch.parse_line(line([msg("920350", "Host header is a numeric IP address", "4")])))

    def test_blocking_mode(self):
        e = waf_watch.parse_line(line(SQLI, engine="Enabled", code=403))
        self.assertTrue(e["blocked"])
        self.assertEqual(e["status_code"], 403)

    def test_body_error_rule_counts(self):
        e = waf_watch.parse_line(line([msg("200002", "Failed to parse request body.")], uri="/api"))
        self.assertEqual(e["rules"][0]["id"], "200002")

    def test_garbage(self):
        for bad in ("", "no es json", "[]", '{"transaction": null}', '{"otra": 1}'):
            self.assertIsNone(waf_watch.parse_line(bad), bad)


class ReadTests(unittest.TestCase):
    def test_reads_new_lines_only(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "audit.log")
            with open(log, "w") as fh:
                fh.write(line(SQLI) + "\n")
            with mock.patch.object(waf_watch, "AUDIT_LOG", log), \
                    mock.patch.object(waf_watch, "STATE_PATH", os.path.join(d, "state.json")):
                self.assertEqual(waf_watch.read_new_entries(), [])  # primera vez: desde el final
                with open(log, "a") as fh:
                    fh.write(line(SQLI) + "\n" + line([msg("920350", "x", "4")]) + "\n")
                self.assertEqual(len(waf_watch.read_new_entries()), 1)


class ModeTests(unittest.TestCase):
    def test_mode_and_sites(self):
        with tempfile.TemporaryDirectory() as d:
            mode_file = os.path.join(d, "modo.conf")
            with open(mode_file, "w") as fh:
                fh.write("# comentario\nSecRuleEngine DetectionOnly\n")
            with mock.patch.object(waf_watch, "MODE_FILE", mode_file):
                self.assertEqual(waf_watch.mode(), "deteccion")
                with open(mode_file, "w") as fh:
                    fh.write("SecRuleEngine On\n")
                self.assertEqual(waf_watch.mode(), "bloqueo")
            with mock.patch.object(waf_watch, "MODE_FILE", os.path.join(d, "no-existe")):
                self.assertIsNone(waf_watch.mode())


if __name__ == "__main__":
    unittest.main()
