import os
import re
import paramiko

from config import Server


class SSHError(Exception):
    pass


def _load_key(path: str, passphrase):
    last = None
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key_file(path, password=passphrase)
        except paramiko.PasswordRequiredException:
            raise SSHError("کلید خصوصی رمزگذاری شده است ولی passphrase تنظیم نشده")
        except paramiko.SSHException as e:
            last = e
    raise SSHError(f"خواندن کلید خصوصی ناموفق بود: {last}")


def _run(client: paramiko.SSHClient, cmd: str, timeout: int) -> str:
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    if code != 0:
        err = stderr.read().decode("utf-8", "replace").strip()
        raise SSHError(f"اجرای دستور ناموفق (کد {code}): {err[:200]}")
    return out


_CPU_CMD = "head -n1 /proc/stat; sleep 1; head -n1 /proc/stat"


def _parse_cpu_line(line: str):
    parts = [int(x) for x in line.split()[1:]]
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    return sum(parts[:8]), idle


def _cpu_percent(out: str) -> float:
    lines = [l for l in out.splitlines() if l.startswith("cpu")]
    if len(lines) < 2:
        raise SSHError("خروجی /proc/stat نامعتبر است")
    t1, i1 = _parse_cpu_line(lines[0])
    t2, i2 = _parse_cpu_line(lines[1])
    dt = t2 - t1
    if dt <= 0:
        raise SSHError("نمونه‌گیری CPU معتبر نبود")
    return round((1 - (i2 - i1) / dt) * 100, 1)


def _ram_percent(out: str) -> float:
    total = re.search(r"^MemTotal:\s+(\d+)", out, re.M)
    avail = re.search(r"^MemAvailable:\s+(\d+)", out, re.M)
    if not total or not avail:
        raise SSHError("MemTotal/MemAvailable در /proc/meminfo یافت نشد")
    t, a = int(total.group(1)), int(avail.group(1))
    if t <= 0:
        raise SSHError("MemTotal نامعتبر است")
    return round((t - a) / t * 100, 1)


def _disk_percent(out: str) -> float:
    m = re.search(r"(\d+)%", out)
    if not m:
        raise SSHError("خروجی df قابل تحلیل نیست")
    return float(m.group(1))


def collect_metrics(srv: Server, timeout: int) -> dict:
    kwargs = dict(hostname=srv.host, port=srv.port, username=srv.username,
                  timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                  look_for_keys=False, allow_agent=False)
    if srv.auth_method == "password":
        pw = os.environ.get(srv.password_env)
        if not pw:
            raise SSHError(f"متغیر محیطی '{srv.password_env}' تنظیم نشده است")
        kwargs["password"] = pw
    else:
        if not os.path.isfile(srv.key_path):
            raise SSHError(f"فایل کلید پیدا نشد: {srv.key_path}")
        passphrase = os.environ.get(srv.key_passphrase_env) if srv.key_passphrase_env else None
        kwargs["pkey"] = _load_key(srv.key_path, passphrase)

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(**kwargs)
        cpu = _cpu_percent(_run(client, _CPU_CMD, timeout + 5))
        ram = _ram_percent(_run(client, "cat /proc/meminfo", timeout))
        disk = _disk_percent(_run(client, "df -P /", timeout))
        return {"cpu": cpu, "ram": ram, "disk": disk}
    except paramiko.BadHostKeyException:
        raise SSHError("host key با known_hosts مطابقت ندارد (احتمال تغییر سرور یا حمله MITM)")
    except paramiko.AuthenticationException:
        raise SSHError("احراز هویت SSH ناموفق بود")
    except paramiko.SSHException as e:
        raise SSHError(f"خطای SSH: {e}")
    except (TimeoutError, OSError) as e:
        raise SSHError(f"اتصال SSH برقرار نشد: {type(e).__name__}: {e}")
    finally:
        client.close()
