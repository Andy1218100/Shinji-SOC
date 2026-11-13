from fastapi import APIRouter, Depends

from app.api.deps import require_admin

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.get("/check", dependencies=[Depends(require_admin)])
async def check():
    return {"status": "ok"}
