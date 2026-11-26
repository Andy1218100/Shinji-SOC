"""Lectura de logs de acceso: zona horaria, rotacion, lineas a medio
escribir, tope por lectura, y que archivos se eligen para vigilar."""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import support  # noqa: F401  (agrega agent/ al path y stubs)

import log_tailer

try:
    import discovery  # usa pwd: solo existe en Linux
except ImportError:
    discovery = None

LINE = '203.0.113.7 - - [26/Nov/2026:10:00:00 -0300] "GET /wp-login.php HTTP/1.1" 404 153 "-" "curl/8.0"\n'


class TimeTests(unittest.TestCase):
    def test_keeps_timezone(self):
        ts = datetime.fromisoformat(log_tailer._parse_line(LINE.strip())["ts"])
        self.assertEqual(ts.utcoffset(), timedelta(hours=-3))
        self.assertEqual(ts.astimezone(timezone.utc).hour, 13)

    def test_without_timezone_still_parses(self):
        e = log_tailer._parse_line('1.2.3.4 - - [26/Nov/2026:10:00:00] "GET / HTTP/1.1" 200 1 "-" "x"')
        self.assertEqual(e["ts"], "2026-11-26T10:00:00")

    def test_bad_time_is_none(self):
        e = log_tailer._parse_line('1.2.3.4 - - [ayer] "GET / HTTP/1.1" 200 1 "-" "x"')
        self.assertIsNone(e["ts"])


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "access.log")
        with open(self.log, "w") as fh:
            fh.write(LINE)
        patcher = mock.patch.object(log_tailer, "STATE_PATH", os.path.join(self.dir.name, "state.json"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.dir.cleanup)
        self.assertEqual(log_tailer.read_new_entries([self.log]), [])  # primera vez: desde el final

    def append(self, text):
        with open(self.log, "a") as fh:
            fh.write(text)

    def test_copytruncate_reads_from_start(self):
        # logrotate copytruncate: mismo inodo, archivo vaciado y vuelve a crecer.
        self.append(LINE)
        self.assertEqual(len(log_tailer.read_new_entries([self.log])), 1)
        with open(self.log, "w") as fh:
            fh.write(LINE)
        self.assertEqual(len(log_tailer.read_new_entries([self.log])), 1)

    def test_partial_line_waits(self):
        self.append(LINE[:30])
        self.assertEqual(log_tailer.read_new_entries([self.log]), [])
        self.append(LINE[30:])
        entries = log_tailer.read_new_entries([self.log])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["path"], "/wp-login.php")

    def test_batch_limit_keeps_the_rest(self):
        self.append(LINE * 25)
        self.assertEqual(len(log_tailer.read_new_entries([self.log], max_entries=10)), 10)
        self.assertEqual(len(log_tailer.read_new_entries([self.log], max_entries=10)), 10)
        self.assertEqual(len(log_tailer.read_new_entries([self.log], max_entries=10)), 5)
        self.assertEqual(log_tailer.read_new_entries([self.log], max_entries=10), [])

    def test_missing_file_does_not_stop_others(self):
        self.append(LINE)
        missing = os.path.join(self.dir.name, "no-existe.log")
        self.assertEqual(len(log_tailer.read_new_entries([missing, self.log])), 1)

    def test_corrupt_state_is_ignored(self):
        with open(log_tailer.STATE_PATH, "w") as fh:
            fh.write("{roto")
        self.assertEqual(log_tailer.read_new_entries([self.log]), [])


@unittest.skipIf(discovery is None, "discovery usa pwd (solo Linux)")
class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, data):
        path = os.path.join(self.dir.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_classify(self):
        self.assertTrue(discovery.classify_log(self.write("sitio.log", LINE.encode())))
        self.assertFalse(discovery.classify_log(self.write("juego.log", b"[10:00] jugador conectado\n")))
        self.assertFalse(discovery.classify_log(self.write("bin.log", b"\x00\x01\x02")))
        self.assertIsNone(discovery.classify_log(self.write("vacio.log", b"")))

    def test_rotated_and_binary_are_skipped(self):
        for name in ("access.log.1", "access.log.2.gz", "syslog-20261120", "wtmp", "system.journal"):
            self.assertTrue(discovery._is_rotated_or_binary("/var/log/" + name), name)
        for name in ("access.log", "error.log", "sitio-access.log"):
            self.assertFalse(discovery._is_rotated_or_binary("/var/log/" + name), name)

    def test_web_looking_names(self):
        self.assertTrue(discovery._looks_like_web_log("/var/log/nginx/error.log"))
        self.assertTrue(discovery._looks_like_web_log("/srv/app/logs/access.log"))
        self.assertFalse(discovery._looks_like_web_log("/var/log/syslog"))


if __name__ == "__main__":
    unittest.main()
