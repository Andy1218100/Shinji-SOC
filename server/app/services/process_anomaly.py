from sqlalchemy.ext.asyncio import AsyncSession

from app.models.host import Host
from app.schemas.logs import ProcessEventIn
from app.services.ids import create_event


async def process_anomalies(session: AsyncSession, host: Host, events: list[ProcessEventIn]) -> None:
    for event in events:
        detail = {
            "user": event.user,
            "pid": event.pid,
            "cmdline": event.cmdline,
            "parent_cmdline": event.parent_cmdline,
        }
        await create_event(
            session,
            host,
            "process_anomaly",
            source_ip=f"local:{host.hostname}",
            detail=detail,
            severity="critical",
            suggested_action="kill_process",
        )
