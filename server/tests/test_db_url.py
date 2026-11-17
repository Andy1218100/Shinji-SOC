import unittest

from sqlalchemy.engine import make_url

from app.core.config import Settings


class DatabaseUrlTests(unittest.TestCase):
    def test_password_with_special_characters(self):
        # Regresion: la URL se armaba pegando la contrasena en
        # docker-compose.yml, y un "@" o "/" en ella hacia que el servidor
        # buscara un host inexistente ("Name or service not known").
        password = "p@ss:w/rd#?%&=+ con espacio"
        s = Settings(_env_file=None, database_url="", postgres_user="shinjisoc",
                     postgres_password=password, postgres_db="shinjisoc", postgres_host="db")
        url = make_url(s.sqlalchemy_url)
        self.assertEqual(url.host, "db")
        self.assertEqual(url.port, 5432)
        self.assertEqual(url.password, password)
        self.assertEqual(url.database, "shinjisoc")

    def test_explicit_database_url_wins(self):
        s = Settings(_env_file=None, database_url="postgresql+asyncpg://u:p@otro:5433/x")
        self.assertEqual(s.sqlalchemy_url, "postgresql+asyncpg://u:p@otro:5433/x")


if __name__ == "__main__":
    unittest.main()
