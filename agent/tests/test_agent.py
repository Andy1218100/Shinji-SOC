import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

import support  # noqa: F401  (agrega agent/ al path y stubs)

import auth_watch
import inventory
import log_tailer
import process_watch

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


class InventoryTests(unittest.TestCase):
    def run_collect(self, stdout):
        result = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
        with mock.patch.object(inventory.subprocess, "run", return_value=result):
            return {p["name"]: p for p in inventory.collect()}

    def test_source_fields_and_installed_only(self):
        out = (
            "ii \tbash\t5.2.37-2+b10\tbash\t5.2.37-2\n"
            "ii \tlibssl3t64\t3.5.7-1~deb13u3\topenssl\t3.5.7-1~deb13u3\n"
            "rc \tviejo\t1.0\tviejo\t1.0\n"  # desinstalado con config: no cuenta
        )
        pkgs = self.run_collect(out)
        self.assertEqual(set(pkgs), {"bash", "libssl3t64"})
        self.assertEqual(pkgs["bash"]["source_version"], "5.2.37-2")
        self.assertEqual(pkgs["libssl3t64"]["source_name"], "openssl")

    def test_multiarch_duplicates_collapse(self):
        # Regresion: amd64 + i386 repetian el nombre y el servidor daba 500.
        out = "ii \tlibc6\t2.41-12\tglibc\t2.41-12\nii \tlibc6\t2.41-12\tglibc\t2.41-12\n"
        self.assertEqual(len(self.run_collect(out)), 1)

    def test_missing_source_falls_back_to_binary(self):
        pkgs = self.run_collect("ii \tcurl\t8.14.1-2\t\t\n")
        self.assertEqual((pkgs["curl"]["source_name"], pkgs["curl"]["source_version"]), ("curl", "8.14.1-2"))


class AuthWatchTests(unittest.TestCase):
    def parse(self, msg):
        return auth_watch.parse_message(msg, NOW)

    def test_ssh_failed_invalid_user(self):
        e = self.parse("Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2")
        self.assertEqual((e["service"], e["outcome"], e["user"], e["ip"]), ("ssh", "failed", "admin", "203.0.113.9"))

    def test_ssh_accepted(self):
        e = self.parse("Accepted publickey for root from 192.168.100.2 port 60000 ssh2: ED25519 SHA256:x")
        self.assertEqual((e["outcome"], e["user"], e["method"]), ("accepted", "root", "publickey"))

    def test_pve_failure_ipv4_mapped(self):
        e = self.parse("authentication failure; rhost=::ffff:198.51.100.7 user=root@pam msg=Authentication failure")
        self.assertEqual((e["service"], e["ip"], e["user"]), ("pve", "198.51.100.7", "root@pam"))

    def test_ignored_lines(self):
        self.assertIsNone(self.parse("Connection closed by 203.0.113.9 port 51237 [preauth]"))
        # Se contaria dos veces: sshd ya loguea un "Failed" por intento.
        self.assertIsNone(self.parse("error: maximum authentication attempts exceeded for root from 1.2.3.4 port 1 ssh2 [preauth]"))
        # Renovacion de sesion de la web de Proxmox: no trae IP.
        self.assertIsNone(self.parse("<root@pam> successful auth for user 'root@pam'"))

    def test_journal_reading_saves_cursor(self):
        lines = "\n".join(json.dumps(r) for r in [
            {"__CURSOR": "c1", "__REALTIME_TIMESTAMP": "1763294400000000", "MESSAGE": "Failed password for root from 203.0.113.9 port 1 ssh2"},
            {"__CURSOR": "c2", "__REALTIME_TIMESTAMP": "1763294401000000", "MESSAGE": list(b"Invalid user x from 203.0.113.9 port 2")},
        ])
        state = {}
        result = subprocess.CompletedProcess(args=[], returncode=0, stdout=lines, stderr="")
        with mock.patch.object(auth_watch.subprocess, "run", return_value=result) as run:
            entries = auth_watch._read_journal(state)
        self.assertEqual([e["outcome"] for e in entries], ["failed", "invalid_user"])
        self.assertEqual(state["journal_cursor"], "c2")
        self.assertIn("--since", run.call_args.args[0])  # primera vez: sin historico
        with mock.patch.object(auth_watch.subprocess, "run", return_value=result) as run:
            auth_watch._read_journal(state)
        self.assertIn("--after-cursor", run.call_args.args[0])


class ProcessWatchTests(unittest.TestCase):
    def trusted(self, cmd):
        parts = cmd.split()
        return process_watch._is_trusted_script(process_watch._basename(parts), parts)

    def test_exact_allowlist(self):
        self.assertTrue(self.trusted("/usr/bin/perl -T /usr/bin/pveproxy start"))
        self.assertTrue(self.trusted("/usr/bin/perl -wT /usr/bin/pg_ctlcluster --skip-systemctl-redirect 17-main start"))
        # Variantes peligrosas siguen reportandose.
        self.assertFalse(self.trusted("/usr/bin/perl -e system(1) /usr/bin/pveproxy"))
        self.assertFalse(self.trusted("/usr/bin/perl /usr/bin/pveproxy start"))
        self.assertFalse(self.trusted("perl -T /tmp/pveproxy start"))


class LogTailerTests(unittest.TestCase):
    def test_combined_format(self):
        e = log_tailer._parse_line('203.0.113.7 - - [16/Nov/2026:10:00:00 -0300] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.0"')
        self.assertEqual((e["ip"], e["path"], e["status_code"], e["user_agent"]), ("203.0.113.7", "/.env", 404, "curl/8.0"))
        self.assertIsNone(log_tailer._parse_line("no es un log de acceso"))

    def test_rotation_and_offsets(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "access.log")
            state = os.path.join(d, "state.json")
            line = '203.0.113.7 - - [16/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 1 "-" "x"\n'
            with open(log, "w") as fh:
                fh.write(line)
            with mock.patch.object(log_tailer, "STATE_PATH", state):
                self.assertEqual(log_tailer.read_new_entries([log]), [])  # primera vez: desde el final
                with open(log, "a") as fh:
                    fh.write(line)
                self.assertEqual(len(log_tailer.read_new_entries([log])), 1)
                self.assertEqual(log_tailer.read_new_entries([log]), [])


if __name__ == "__main__":
    unittest.main()
