import subprocess


def ping(host: str, timeout_seconds: int) -> bool:
    """یک Ping با ping.exe ویندوز. True اگر پاسخ دریافت شود."""
    timeout_ms = max(1, int(timeout_seconds * 1000))
    cmd = ["ping.exe", "-n", "1", "-w", str(timeout_ms), host]
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout_seconds + 5, creationflags=flags)
    except (subprocess.TimeoutExpired, OSError):
        return False
    if r.returncode != 0:
        return False
    return "TTL=" in r.stdout.upper()
