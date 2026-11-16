import unittest
from types import SimpleNamespace
from unittest import mock

from app.services import vuln_scan
from tests.helpers import finding, host


def pkg(name, version, source=None, source_version=None):
    return SimpleNamespace(name=name, version=version, source_name=source, source_version=source_version)


class GroupBySourceTests(unittest.TestCase):
    def test_groups_binaries_under_source_with_source_version(self):
        # Regresion: se consultaba OSV por binario (libssl3t64 -> 0 avisos).
        groups = {g.name: g for g in vuln_scan.group_by_source([
            pkg("libssl3t64", "3.5.7-1~deb13u3", "openssl", "3.5.7-1~deb13u3"),
            pkg("openssl", "3.5.7-1~deb13u3", "openssl", "3.5.7-1~deb13u3"),
            pkg("bash", "5.2.37-2+b10", "bash", "5.2.37-2"),
            pkg("bsdutils", "1:2.41.5-0+deb13u1", "util-linux", "2.41.5-0+deb13u1"),
        ])}
        self.assertEqual(sorted(groups["openssl"].binaries), ["libssl3t64", "openssl"])
        self.assertEqual(groups["bash"].version, "5.2.37-2")  # sin el +b10 del binNMU
        self.assertEqual(groups["util-linux"].version, "2.41.5-0+deb13u1")  # sin epoca del binario

    def test_old_agent_without_source_falls_back_to_binary(self):
        groups = vuln_scan.group_by_source([pkg("curl", "8.14.1-2")])
        self.assertEqual((groups[0].name, groups[0].version), ("curl", "8.14.1-2"))

    def test_mixed_versions_keep_oldest(self):
        with mock.patch.object(vuln_scan, "_version_lt", side_effect=lambda a, b: a < b):
            groups = vuln_scan.group_by_source([pkg("a1", "2", "src", "2.0"), pkg("a2", "1", "src", "1.0")])
        self.assertEqual(groups[0].version, "1.0")


class ApplicabilityTests(unittest.TestCase):
    def test_kernel_headers_only_not_applicable(self):
        # Regresion: 294 CVEs del kernel de Debian contra linux-libc-dev en un Proxmox.
        src = vuln_scan.SourcePackage("linux", "6.12.117-1", ["linux-libc-dev"])
        self.assertIsNotNone(vuln_scan.not_applicable_reason(src))

    def test_real_kernel_is_applicable(self):
        src = vuln_scan.SourcePackage("linux", "6.12.117-1", ["linux-libc-dev", "linux-image-6.12.117-amd64"])
        self.assertIsNone(vuln_scan.not_applicable_reason(src))

    def test_third_party_build(self):
        self.assertTrue(vuln_scan.is_third_party_build("10.6.1-1+pve3"))
        self.assertTrue(vuln_scan.is_third_party_build("3.2.0-pve1"))
        self.assertFalse(vuln_scan.is_third_party_build("2.44-3"))


class RecommendationTests(unittest.TestCase):
    def setUp(self):
        vuln_scan._active_rules.clear()

    def test_unimportant_only_gets_fixed_text(self):
        src = vuln_scan.SourcePackage("binutils", "2.44-3", ["binutils"])
        text = vuln_scan._fixed_recommendation(src, [finding(urgency="unimportant")])
        self.assertTrue(text.endswith(vuln_scan.FIXED_NOTE))

    def test_relevant_cves_go_to_ai(self):
        src = vuln_scan.SourcePackage("curl", "8.14.1-2", ["curl"])
        self.assertIsNone(vuln_scan._fixed_recommendation(src, [finding()]))

    def test_prompt_without_fix_does_not_promise_upgrade_or_uninstall(self):
        # Regresion: sin parche decia "actualizar" y con el ejemplo "desinstalar"
        # lo recomendaba hasta para apt.
        prompt = vuln_scan._build_prompt(host(), vuln_scan.SourcePackage("apt", "3.0.4", ["apt"]), [finding()])
        self.assertIn("actualizar ahora no las corrige", prompt)
        self.assertIn("No recomiendes desinstalar paquetes base", prompt)

    def test_prompt_with_fix_mentions_versions(self):
        prompt = vuln_scan._build_prompt(host(), vuln_scan.SourcePackage("apt", "3.0.3", ["apt"]),
                                         [finding(fixed_version="3.0.4")])
        self.assertIn("3.0.4", prompt)

    def test_prompt_includes_auditor_rules(self):
        vuln_scan._active_rules[:] = [SimpleNamespace(package_name=None, rule="No cites versiones upstream.")]
        prompt = vuln_scan._build_prompt(host(), vuln_scan.SourcePackage("x", "1", ["x"]), [finding()])
        self.assertIn("No cites versiones upstream.", prompt)

    def test_claude_correction_is_kept(self):
        src = vuln_scan.SourcePackage("x", "1", ["x"])
        f = finding(ai_recommendation="texto de Claude", rec_source="claude")
        self.assertFalse(vuln_scan._needs_new_recommendation(host(), src, [f]))

    def test_invented_cve_triggers_regeneration(self):
        src = vuln_scan.SourcePackage("x", "1", ["x"])
        f = finding(ai_recommendation="Corrige CVE-2099-99999 actualizando.", rec_source="ia_local")
        self.assertTrue(vuln_scan._needs_new_recommendation(host(), src, [f]))

    def test_fallback_is_retried(self):
        src = vuln_scan.SourcePackage("x", "1", ["x"])
        f = finding(ai_recommendation="algo " + vuln_scan.FALLBACK_NOTE, rec_source="fija")
        self.assertTrue(vuln_scan._needs_new_recommendation(host(), src, [f]))


if __name__ == "__main__":
    unittest.main()
