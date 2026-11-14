import os
import time
from datetime import datetime, timezone

import psutil

# Para calcular Kbps de red hace falta la lectura anterior (los contadores
# de psutil son acumulados desde el boot, no una tasa). Se guarda en modulo
# porque metrics_loop llama collect() siempre desde el mismo proceso.
_last_net: tuple[float, int, int] | None = None


def _net_rates(net) -> tuple[float | None, float | None]:
    global _last_net
    now = time.monotonic()
    rx_kbps = tx_kbps = None

    if _last_net is not None:
        last_ts, last_rx, last_tx = _last_net
        elapsed = now - last_ts
        if elapsed > 0:
            rx_kbps = max(0.0, (net.bytes_recv - last_rx) * 8 / 1000 / elapsed)
            tx_kbps = max(0.0, (net.bytes_sent - last_tx) * 8 / 1000 / elapsed)

    _last_net = (now, net.bytes_recv, net.bytes_sent)
    return rx_kbps, tx_kbps


def collect() -> dict:
    cpu_total = psutil.cpu_percent(interval=1)
    cpu_times = psutil.cpu_times_percent(interval=None)  # misma ventana que el cpu_percent de arriba

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    net_rx_kbps, net_tx_kbps = _net_rates(net)

    try:
        load1, load5, load15 = os.getloadavg()
    except (AttributeError, OSError):
        load1, load5, load15 = (None, None, None)

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": cpu_total,
        "cpu_user_percent": getattr(cpu_times, "user", None),
        "cpu_system_percent": getattr(cpu_times, "system", None),
        "cpu_iowait_percent": getattr(cpu_times, "iowait", None),  # no existe en Windows/macOS
        "cpu_steal_percent": getattr(cpu_times, "steal", None),  # solo tiene sentido en VMs Linux
        "mem_percent": mem.percent,
        "mem_used_mb": mem.used / (1024 * 1024),
        "mem_total_mb": mem.total / (1024 * 1024),
        "mem_available_mb": mem.available / (1024 * 1024),
        "mem_buffers_mb": getattr(mem, "buffers", 0) / (1024 * 1024),
        "mem_cached_mb": getattr(mem, "cached", 0) / (1024 * 1024),
        "mem_shared_mb": getattr(mem, "shared", 0) / (1024 * 1024),
        "swap_percent": swap.percent,
        "swap_used_mb": swap.used / (1024 * 1024),
        "swap_total_mb": swap.total / (1024 * 1024),
        "disk_percent": disk.percent,
        "disk_used_gb": disk.used / (1024 ** 3),
        "disk_total_gb": disk.total / (1024 ** 3),
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "net_rx_bytes": net.bytes_recv,
        "net_tx_bytes": net.bytes_sent,
        "net_rx_kbps": net_rx_kbps,
        "net_tx_kbps": net_tx_kbps,
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }
