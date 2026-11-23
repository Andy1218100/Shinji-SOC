import os
import tempfile
import unittest

import support  # noqa: F401  (agrega agent/ al path y stubs)

import conn_watch
import log_tailer

HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
TCP = HEADER + "".join([
    # 0.0.0.0:22 en escucha (root)
    "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1000 1\n",
    # 10.0.0.5:43512 -> 203.0.113.9:4444 establecida (uid 33): saliente
    "   1: 0500000A:A9F8 097100CB:115C 01 00000000:00000000 00:00000000 00000000    33        0 1001 1\n",
    # 10.0.0.5:22 <- 198.51.100.7:51000: entrante a un puerto en escucha
    "   2: 0500000A:0016 076433C6:C738 01 00000000:00000000 00:00000000 00000000     0        0 1002 1\n",
    # 10.0.0.5:40000 -> 10.0.0.1:5432: red privada
    "   3: 0500000A:9C40 0100000A:1538 01 00000000:00000000 00:00000000 00000000   105        0 1003 1\n",
])
TCP6 = HEADER + "".join([
    # [::]:8000 en escucha
    "   0: 00000000000000000000000000000000:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2000 1\n",
    # ::ffff:10.0.0.5:41000 -> ::ffff:203.0.113.9:443 (IPv4 mapeada)
    "   1: 0000000000000000FFFF00000500000A:A028 0000000000000000FFFF0000097100CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2001 1\n",
])
UDP = HEADER + "".join([
    "   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3000 2\n",  # :68 servicio
    "   1: 00000000:AFC8 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2\n",  # :45000 efimero
])
SS = "\n".join([
    'tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=800,fd=3))',
    'tcp   LISTEN 0      4096            [::]:8000          [::]:*     users:(("uvicorn",pid=900,fd=7))',
    'tcp   ESTAB  0      0          10.0.0.5:43512  203.0.113.9:4444  users:(("bash",pid=1234,fd=3))',
    'udp   UNCONN 0      0           0.0.0.0:68         0.0.0.0:*     users:(("dhclient",pid=500,fd=6))',
])


class ConnWatchTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        for name, text in (("tcp", TCP), ("tcp6", TCP6), ("udp", UDP), ("udp6", HEADER)):
            with open(os.path.join(self.dir.name, name), "w", encoding="ascii") as fh:
                fh.write(text)

    def tearDown(self):
        self.dir.cleanup()

    def test_hex_addresses(self):
        self.assertEqual(conn_watch._hex_ip("0500000A"), "10.0.0.5")
        self.assertEqual(conn_watch._hex_ip("0000000000000000FFFF0000097100CB"), "203.0.113.9")
        self.assertEqual(conn_watch._hex_ip("00000000000000000000000001000000"), "::1")

    def test_parse_ss(self):
        owners = conn_watch.parse_ss(SS)
        self.assertEqual(owners[("tcp", "10.0.0.5", "43512", "203.0.113.9", "4444")], ("bash", 1234))
        self.assertEqual(owners[("tcp", "::", "8000", "::", "*")], ("uvicorn", 900))

    def test_snapshot(self):
        listeners, outbound = conn_watch.snapshot(self.dir.name, owners=conn_watch.parse_ss(SS))
        by_port = {(item["proto"], item["port"]): item for item in listeners}
        self.assertEqual(set(by_port), {("tcp", 22), ("tcp", 8000), ("udp", 68)})  # sin el UDP efimero
        self.assertEqual(by_port[("tcp", 22)]["process"], "sshd")
        self.assertEqual(by_port[("tcp", 8000)]["process"], "uvicorn")
        self.assertEqual(by_port[("udp", 68)]["process"], "dhclient")
        # Salientes: solo las que van a IPs publicas y no llegan a un puerto propio.
        # 203.0.113.0/24 es de documentacion (no publica): se usa una IP publica en su lugar.
        self.assertEqual(outbound, [])

    def test_snapshot_outbound_public(self):
        public = TCP.replace("097100CB", "08080808")  # 203.0.113.9 -> 8.8.8.8
        with open(os.path.join(self.dir.name, "tcp"), "w", encoding="ascii") as fh:
            fh.write(public)
        _, outbound = conn_watch.snapshot(self.dir.name, owners=conn_watch.parse_ss(SS.replace("203.0.113.9", "8.8.8.8")))
        self.assertEqual(len(outbound), 1)
        conn = outbound[0]
        self.assertEqual((conn["remote_ip"], conn["remote_port"], conn["local_port"]), ("8.8.8.8", 4444, 43512))
        self.assertEqual((conn["process"], conn["pid"]), ("bash", 1234))

    def test_tracker_sends_only_changes(self):
        tracker = conn_watch.Tracker()
        listeners = [{"proto": "tcp", "port": 22}]
        conn = {"user": "www-data", "remote_ip": "8.8.8.8", "remote_port": 4444, "process": "bash"}
        first = tracker.payload(listeners, [conn], now=1000)
        self.assertEqual(first["listeners"], listeners)
        self.assertEqual(first["outbound"], [conn])
        self.assertIsNone(tracker.payload(listeners, [conn], now=1060))      # nada nuevo
        again = tracker.payload(listeners, [conn], now=1000 + 3601)            # paso la hora
        self.assertEqual(again["outbound"], [conn])
        self.assertIsNone(again["listeners"])
        changed = tracker.payload(listeners + [{"proto": "tcp", "port": 4444}], [], now=5000)
        self.assertEqual(len(changed["listeners"]), 2)


class ForwardedForTests(unittest.TestCase):
    def test_trailing_real_ip(self):
        line = ('127.0.0.1 - - [23/Nov/2026:10:00:00 -0300] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.0" "198.51.100.20"')
        self.assertEqual(log_tailer._parse_line(line)["forwarded_for"], "198.51.100.20")

    def test_plain_combined_has_no_forwarded(self):
        line = '203.0.113.7 - - [16/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 10 "-" "curl/8.0"'
        self.assertIsNone(log_tailer._parse_line(line)["forwarded_for"])
        dash = line + ' "-"'
        self.assertIsNone(log_tailer._parse_line(dash)["forwarded_for"])



class InstallerTests(unittest.TestCase):
    def test_every_module_is_embedded(self):
        # Regresion: conn_watch.py se agrego al agente pero no a
        # _build_install.sh, y el agente instalado no habria arrancado.
        agent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(agent_dir, "install.sh"), encoding="utf-8") as fh:
            installer = fh.read()
        modules = [f for f in os.listdir(agent_dir) if f.endswith(".py") and not f.startswith("_")]
        missing = [m for m in modules if f"$INSTALL_DIR/{m}" not in installer]
        self.assertEqual(missing, [], "falta embeber en install.sh (agent/_build_install.sh)")


if __name__ == "__main__":
    unittest.main()
