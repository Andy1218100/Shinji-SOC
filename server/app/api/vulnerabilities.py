from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.db import get_db
from app.models.host import Host
from app.models.vulnerability import InstalledPackage, VulnerabilityFinding
from app.schemas.vulnerability import InventoryStatusOut, VulnerabilityFindingOut

router = APIRouter(prefix="/api/v1", tags=["vulnerabilities"])


@router.get("/vulnerabilities", response_model=list[VulnerabilityFindingOut])
async def list_vulnerabilities(
    status: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(VulnerabilityFinding).order_by(VulnerabilityFinding.last_seen.desc())
    if status:
        stmt = stmt.where(VulnerabilityFinding.status == status)
    result = await db.execute(stmt)
    return [VulnerabilityFindingOut.model_validate(f) for f in result.scalars().all()]


@router.post("/vulnerabilities/{finding_id}/acknowledge", dependencies=[Depends(require_admin)])
async def acknowledge_vulnerability(finding_id: str, db: AsyncSession = Depends(get_db)):
    finding = (
        await db.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.id == finding_id))
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="No encontrado")
    finding.status = "acknowledged"
    await db.commit()
    return {"status": "ok"}


@router.get("/inventory/status", response_model=list[InventoryStatusOut])
async def inventory_status(db: AsyncSession = Depends(get_db)):
    hosts = (await db.execute(select(Host))).scalars().all()
    out = []
    for host in hosts:
        count = (
            await db.execute(
                select(func.count(InstalledPackage.id)).where(InstalledPackage.host_id == host.id)
            )
        ).scalar_one()
        last_collected = (
            await db.execute(
                select(func.max(InstalledPackage.collected_at)).where(InstalledPackage.host_id == host.id)
            )
        ).scalar_one()
        out.append(
            InventoryStatusOut(
                host_id=str(host.id), host_name=host.name, package_count=count, last_collected=last_collected
            )
        )
    return out
