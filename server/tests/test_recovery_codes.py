import unittest

from app.services import auth


class RecoveryCodeTests(unittest.TestCase):
    def test_generated_codes_are_unique_and_readable(self):
        codes = auth.generate_recovery_codes()
        self.assertEqual(len(codes), auth.RECOVERY_CODE_COUNT)
        self.assertEqual(len(set(codes)), len(codes))
        for code in codes:
            self.assertRegex(code, r"^[A-Z2-9]{5}-[A-Z2-9]{5}$")
            # Sin caracteres que se confunden al copiarlos a mano.
            self.assertFalse(set(code) & set("01OIL"))

    def test_normalize_accepts_spaces_case_and_missing_dash(self):
        code = auth.generate_recovery_codes(1)[0]
        expected = code.replace("-", "")
        for variant in (code, code.lower(), f"  {code} ", code.replace("-", ""), code.replace("-", " ")):
            self.assertEqual(auth.normalize_recovery_code(variant), expected, variant)

    def test_totp_codes_are_not_recovery_codes(self):
        # Un codigo de 6 digitos nunca se compara contra los de respaldo.
        for value in ("123456", "12345678", "", "ABCDE-FGH", "ABCDE-FGHI0"):
            self.assertIsNone(auth.normalize_recovery_code(value), value)

    def test_hash_verifies_only_the_same_code(self):
        a, b = auth.generate_recovery_codes(2)
        stored = auth.hash_password(auth.normalize_recovery_code(a))
        self.assertTrue(auth.verify_password(auth.normalize_recovery_code(a.lower()), stored))
        self.assertFalse(auth.verify_password(auth.normalize_recovery_code(b), stored))

    def test_mfa_change_token_is_bound_to_the_user(self):
        token = auth.issue_mfa_change_token("user-1", "SECRETBASE32")
        self.assertEqual(auth.read_mfa_change_token(token, "user-1"), "SECRETBASE32")
        self.assertIsNone(auth.read_mfa_change_token(token, "user-2"))
        self.assertIsNone(auth.read_mfa_change_token(token + "x", "user-1"))


if __name__ == "__main__":
    unittest.main()
