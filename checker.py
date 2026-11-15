import logging

from config import Server
from pinger import ping
from ssh_metrics import collect_metrics, SSHError

log = logging.getLogger("monitor")


def _status(value: float, threshold: float) -> str:
    return "بحرانی" if value >= threshold else "عادی"


def check_server(srv: Server, ping_timeout: int, ssh_timeout: int) -> None:
    try:
        if not ping(srv.host, ping_timeout):
            log.error("[%s] Ping سرور برقرار نیست", srv.name)
            return

        m = collect_metrics(srv, ssh_timeout)
        names = {"cpu": "CPU", "ram": "RAM", "disk": "Disk(/)"}
        parts, critical = [], False
        for key in ("cpu", "ram", "disk"):
            st = _status(m[key], srv.thresholds[key])
            critical |= st == "بحرانی"
            parts.append(f"{names[key]}: {m[key]:.1f}% ({st}، آستانه {srv.thresholds[key]:g}%)")
        msg = f"[{srv.name}] " + " | ".join(parts)
        (log.warning if critical else log.info)(msg)
    except SSHError as e:
        log.error("[%s] خطای SSH: %s", srv.name, e)
    except Exception as e:
        log.error("[%s] خطای غیرمنتظره: %s: %s", srv.name, type(e).__name__, e)
