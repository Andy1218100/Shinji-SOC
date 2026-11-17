import importlib
import pkgutil
import unittest

import app


class ImportTests(unittest.TestCase):
    def test_every_module_imports(self):
        # Un error de sintaxis en un modulo que ningun test usa (paso con
        # services/backups.py) dejaba al servidor sin arrancar con los tests
        # en verde.
        failures = []
        for mod in pkgutil.walk_packages(app.__path__, "app."):
            try:
                importlib.import_module(mod.name)
            except Exception as exc:  # noqa: BLE001 - se informan todos juntos
                failures.append(f"{mod.name}: {exc!r}")
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
