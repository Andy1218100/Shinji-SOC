from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_host
from app.core.db import get_db
from app.models.host import Host
from app.models.security import BlockedIP, Command
from app.schemas.security import CommandOut, CommandResultIn
from app.services import vuln_scan

router = APIRouter(prefix="/api/v1", tags=["commands"])


@router.get("/commands/pending", response_model=list[CommandOut])
async def pending_commands(
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Command).where(Command.host_id == host.id, Command.status == "pending")
    )
    commands = result.scalars().all()
    for command in commands:
        command.status = "sent"
    await db.commit()
    return [CommandOut.model_validate(c) for c in commands]


@router.post("/commands/{command_id}/result")
async def report_command_result(
    command_id: str,
    payload: CommandResultIn,
    host: Host = Depends(get_current_host),
    db: AsyncSession = Depends(get_db),
):
    command = (await db.execute(select(Command).where(Command.id == command_id))).scalar_one_or_none()
    if command is None or command.host_id != host.id:
        raise HTTPException(status_code=404, detail="Comando no encontrado")

    command.status = payload.status
    command.result = payload.result
    command.completed_at = datetime.now(timezone.utc)

    if command.action == "send_inventory" and payload.status != "done":
        # Agente viejo ("accion desconocida") o fallo al mandar: el panel deja
        # de mostrar "esperando inventario" y avisa.
        vuln_scan.inventory_request_failed(str(host.id), f"el agente no pudo mandar el inventario: {payload.result or ''}"[:200])

    if command.action == "block_ip" and payload.status == "done":
        db.add(BlockedIP(host_id=host.id, ip=command.payload.get("ip"), reason=f"Comando {command.id}"))

    await db.commit()
    return {"status": "ok"}
