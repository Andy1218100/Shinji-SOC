"""Bootstrap: crea el primer usuario admin.

La pantalla de Usuarios (/users) requiere estar logueado como admin para
crear mas cuentas -- este script resuelve el huevo-o-gallina del primer
usuario, corriendo dentro del contenedor del servidor directo contra la
base de datos.

Uso:
    docker compose exec server python create_first_admin.py tu_usuario
"""

import asyncio
import sys

from sqlalchemy import select

from app.core.db import Base, SessionLocal, engine
from app.models.user import User
from app.services import auth


async def main(username: str) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with SessionLocal() as session:
        existing = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if existing:
            print(f"Ya existe un usuario '{username}'.", file=sys.stderr)
            sys.exit(1)

        temp_password = auth.generate_temp_password()
        user = User(
            username=username,
            role="admin",
            password_hash=auth.hash_password(temp_password),
            mfa_secret=auth.generate_mfa_secret(),
            mfa_enabled=False,
            must_set_password=True,
        )
        session.add(user)
        await session.commit()

    print("Admin creado.")
    print(f"  usuario:    {username}")
    print(f"  contrasena: {temp_password}")
    print("Entra a /login con estos datos; el primer login te va a pedir una contrasena nueva y enrolar MFA.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python create_first_admin.py <usuario>", file=sys.stderr)
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
