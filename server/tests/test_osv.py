import json
import unittest

import httpx

from app.services import osv


def vuln(blocks):
    return {"affected": blocks}


def block(name, eco, fixed=None, urgency=None):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    b = {"package": {"name": name, "ecosystem": eco}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}
    if urgency:
        b["ecosystem_specific"] = {"urgency": urgency}
    return b


class ExtractTests(unittest.TestCase):
    def test_fixed_version_uses_host_release(self):
        # Regresion: devolvia el fix de Debian:12 para un host Debian:13.
        v = vuln([block("apt", "Debian:12", fixed="2.6.2"), block("apt", "Debian:13", fixed="3.0.4")])
        self.assertEqual(osv.extract_fixed_version(v, "apt", "Debian:13"), "3.0.4")
        self.assertEqual(osv.extract_fixed_version(v, "apt", "Debian:12"), "2.6.2")

    def test_fixed_version_none_when_release_unfixed(self):
        v = vuln([block("apt", "Debian:12", fixed="2.6.2"), block("apt", "Debian:13")])
        self.assertIsNone(osv.extract_fixed_version(v, "apt", "Debian:13"))

    def test_urgency_normalized(self):
        v = vuln([block("x", "Debian:13", urgency="low**")])
        self.assertEqual(osv.extract_urgency(v, "x", "Debian:13"), "low")
        self.assertIsNone(osv.extract_urgency(v, "x", "Debian:12"))

    def test_severity_mapping(self):
        self.assertEqual(osv.extract_severity({}, "high"), "critical")
        self.assertEqual(osv.extract_severity({}, "unimportant"), "info")
        self.assertEqual(osv.extract_severity({}, "not yet assigned"), "warning")
        self.assertEqual(osv.extract_severity({"database_specific": {"severity": "HIGH"}}, None), "critical")


class QueryBatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_chunks_of_1000_and_pagination(self):
        # Regresion: con 1479 paquetes OSV respondia 400 (max 1000 por pedido)
        # y no se seguia el next_page_token por query.
        calls = []

        def handler(request):
            body = json.loads(request.content)
            queries = body["queries"]
            calls.append(len(queries))
            if len(queries) > osv.BATCH_MAX:
                return httpx.Response(400, json={"message": "too many queries"})
            results = []
            for q in queries:
                name = q["package"]["name"]
                if name == "p0" and "page_token" not in q:
                    results.append({"vulns": [{"id": "V1"}], "next_page_token": "t"})
                elif name == "p0":
                    results.append({"vulns": [{"id": "V2"}]})
                else:
                    results.append({})
            return httpx.Response(200, json={"results": results})

        real = httpx.AsyncClient
        osv.httpx.AsyncClient = lambda **kw: real(transport=httpx.MockTransport(handler), **kw)
        try:
            found = await osv.query_batch([(f"p{i}", "1.0") for i in range(1479)], ecosystem="Debian:13")
        finally:
            osv.httpx.AsyncClient = real
        self.assertEqual(len(found), 1479)
        self.assertEqual(found[0], ["V1", "V2"])
        self.assertTrue(all(c <= osv.BATCH_MAX for c in calls))
        # Lote 1 (1000), su pagina 2 (solo p0), lote 2 (479).
        self.assertEqual(calls, [1000, 1, 479])


class GetVulnsTests(unittest.IsolatedAsyncioTestCase):
    async def test_parallel_dedup_retry_and_failures(self):
        hits = {}

        def handler(request):
            vid = request.url.path.rsplit("/", 1)[-1]
            hits[vid] = hits.get(vid, 0) + 1
            if vid == "RATE" and hits[vid] == 1:
                return httpx.Response(429)  # OSV pide esperar: se reintenta
            if vid == "BROKEN":
                return httpx.Response(500)
            return httpx.Response(200, json={"id": vid})

        real = httpx.AsyncClient
        osv.httpx.AsyncClient = lambda **kw: real(transport=httpx.MockTransport(handler), **kw)
        sleeps = []

        async def no_sleep(seconds):
            sleeps.append(seconds)

        real_sleep = osv.asyncio.sleep
        osv.asyncio.sleep = no_sleep
        try:
            out = await osv.get_vulns(["A", "B", "A", "RATE", "BROKEN"])
        finally:
            osv.httpx.AsyncClient = real
            osv.asyncio.sleep = real_sleep
        self.assertEqual(set(out), {"A", "B", "RATE"})  # BROKEN falla tras los reintentos
        self.assertEqual(hits["A"], 1)  # repetido en la lista: se pide una vez
        self.assertEqual(hits["RATE"], 2)
        self.assertEqual(hits["BROKEN"], 3)


if __name__ == "__main__":
    unittest.main()
