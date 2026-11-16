import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.core.config import settings
from app.services import app_settings
from tests.helpers import override

ENV = """# Comentario del usuario
POSTGRES_PASSWORD=secreto
AI_BACKEND=ollama
# otro comentario
OLLAMA_MODEL=qwen2.5:3b
"""


class EnvFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / ".env"
        self.path.write_text(ENV, encoding="utf-8")
        self.patch = mock.patch.object(app_settings, "ENV_FILE", self.path)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.dir.cleanup()

    def test_update_in_place_keeps_comments_and_appends_new(self):
        with override(ollama_model=settings.ollama_model, ids_window_seconds=settings.ids_window_seconds):
            app_settings.update({"OLLAMA_MODEL": "llama3.1:8b", "IDS_WINDOW_SECONDS": "120"})
            self.assertEqual(settings.ollama_model, "llama3.1:8b")
            self.assertEqual(settings.ids_window_seconds, 120)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.assertIn("# Comentario del usuario", lines)
        self.assertIn("# otro comentario", lines)
        self.assertEqual(lines[4], "OLLAMA_MODEL=llama3.1:8b")  # misma linea que antes
        self.assertEqual(lines[-1], "IDS_WINDOW_SECONDS=120")

    def test_invalid_values_leave_file_untouched(self):
        before = self.path.read_text(encoding="utf-8")
        for bad in ({"IDS_WINDOW_SECONDS": "5"}, {"POSTGRES_PASSWORD": "x"}, {"CLAUDE_MODEL": "a\nEVIL=1"},
                    {"NTFY_URL": "ntfy.sh/tema"}, {"SMTP_TO": "sin-arroba"}):
            with self.assertRaises(ValueError, msg=str(bad)):
                app_settings.update(bad)
        with override(anthropic_api_key=""):
            with self.assertRaises(ValueError):
                app_settings.update({"AI_BACKEND": "claude"})
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_public_view_never_exposes_secrets(self):
        with override(anthropic_api_key="sk-ant-muy-secreta-1234", audit_api_token="token-largo-de-prueba-9876"):
            view = app_settings.public_view()
        for f in view["fields"]:
            if f["kind"] == "secret":
                self.assertIsNone(f["value"])
        dump = str(view)
        self.assertNotIn("sk-ant-muy-secreta", dump)
        self.assertNotIn("token-largo-de-prueba", dump)


if __name__ == "__main__":
    unittest.main()
