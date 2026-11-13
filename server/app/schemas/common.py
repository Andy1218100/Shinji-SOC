from typing import Annotated

from pydantic import BeforeValidator

UUIDStr = Annotated[str, BeforeValidator(str)]
