import unittest
from types import SimpleNamespace

from app.schemas.logs import WafBatchIn, WafEntryIn
from app.services import audit, ids


def entry(attack="sqli", rule="942100", blocked=False, uri="/?id=1 union select"):
    return WafEntryIn(ip="198.51.100.77", method="GET", uri=uri, status_code=403 if blocked else 200,
                      blocked=blocked, score=23,
                      rules=[{"id": rule, "msg": "SQL Injection Attack Detected", "attack": attack, "severity": "critica"}])


class WafEventTests(unittest.TestCase):
    def test_severity(self):
        self.assertEqual(ids._waf_severity([entry("sqli")]), "critical")
        self.assertEqual(ids._waf_severity([entry("protocol", "920350")]), "warning")

    def test_merge_accumulates(self):
        d = ids._merge_waf_detail({}, [entry(), entry()], "deteccion")
        d = ids._merge_waf_detail(d, [entry("rce", "932160", blocked=True, uri="/x?c=;cat /etc/passwd")], "bloqueo")
        self.assertEqual((d["hits"], d["blocked"], d["mode"]), (3, 1, "bloqueo"))
        self.assertEqual(d["rule_counts"], {"942100": 2, "932160": 1})
        self.assertEqual(d["attack_types"], ["rce", "sqli"])
        self.assertEqual(d["sample_uri"], "/x?c=;cat /etc/passwd")
        self.assertLessEqual(len(ids._merge_waf_detail(d, [entry()] * 20, None)["samples"]), ids.WAF_SAMPLES)

    def test_batch_limits(self):
        with self.assertRaises(ValueError):
            WafBatchIn(mode="apagado", entries=[])
        with self.assertRaises(ValueError):
            WafBatchIn(entries=[entry()] * 1001)

    def test_prompt_and_audit_facts(self):
        d = ids._merge_waf_detail({}, [entry()], "deteccion")
        host = SimpleNamespace(name="web1")
        prompt = ids.build_event_prompt(host, "waf_attack", "198.51.100.77", d, "block_ip")
        self.assertIn("solo deteccion", prompt)
        self.assertIn("ninguna se bloqueo", prompt)
        self.assertIn("sqli", prompt)
        event = SimpleNamespace(kind="waf_attack", source_ip="198.51.100.77", detail=d)
        facts = audit._event_facts(event, [], {})
        self.assertEqual((facts["peticiones"], facts["modo_waf"]), (1, "deteccion"))
        self.assertNotIn("198.51.100.77", str(facts))  # la IP va con seudonimo


if __name__ == "__main__":
    unittest.main()
