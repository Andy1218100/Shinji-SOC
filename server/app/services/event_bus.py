import asyncio


class EventBus:
    """Pub/sub en memoria para notificar al dashboard de eventos nuevos via SSE.

    Un solo proceso, sin Redis ni cola externa: alcanza porque todo corre en
    un unico contenedor `server`.
    """

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def publish(self, message: dict) -> None:
        for queue in self._subscribers:
            queue.put_nowait(message)


security_events_bus = EventBus()
