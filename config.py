import json
import os
from dataclasses import dataclass, field

DEFAULT_THRESHOLDS = {"cpu": 90.0, "ram": 90.0, "disk": 85.0}


class ConfigError(Exception):
    pass


@dataclass
class Server:
    name: str
    host: str
    port: int
    username: str
    auth_method: str            # "key" | "password"
    interval_minutes: float
    key_path: str = ""
    key_passphrase_env: str = ""
    password_env: str = ""
    thresholds: dict = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))


@dataclass
class Settings:
    ping_timeout: int
    ssh_timeout: int
    log_file: str
    servers: list
    errors: list


def _parse_server(raw: dict, idx: int) -> Server:
    def need(key):
        if key not in raw or raw[key] in ("", None):
            raise ConfigError(f"فیلد '{key}' الزامی است")
        return raw[key]

    name = str(need("name"))
    host = str(need("host"))
    username = str(need("username"))
    port = int(raw.get("port", 22))
    if not 1 <= port <= 65535:
        raise ConfigError("پورت نامعتبر است")
    interval = float(need("interval_minutes"))
    if interval <= 0:
        raise ConfigError("interval_minutes باید بزرگ‌تر از صفر باشد")

    auth = raw.get("auth")
    if not isinstance(auth, dict):
        raise ConfigError("بخش 'auth' الزامی است")
    method = auth.get("method")
    srv = Server(name, host, port, username, method, interval)
    if method == "key":
        srv.key_path = os.path.expanduser(str(auth.get("key_path", "")))
        if not srv.key_path:
            raise ConfigError("auth.key_path الزامی است")
        srv.key_passphrase_env = auth.get("key_passphrase_env", "")
    elif method == "password":
        srv.password_env = auth.get("password_env", "")
        if not srv.password_env:
            raise ConfigError("auth.password_env الزامی است")
    else:
        raise ConfigError("auth.method باید 'key' یا 'password' باشد")

    for k, v in (raw.get("thresholds") or {}).items():
        if k not in DEFAULT_THRESHOLDS:
            raise ConfigError(f"آستانه ناشناخته: {k}")
        v = float(v)
        if not 0 < v <= 100:
            raise ConfigError(f"آستانه {k} باید بین 0 و 100 باشد")
        srv.thresholds[k] = v
    return srv


def load_config(path: str) -> Settings:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise ConfigError(f"فایل کانفیگ پیدا نشد: {path}")
    except json.JSONDecodeError as e:
        raise ConfigError(f"JSON نامعتبر: {e}")

    servers, errors = [], []
    for i, raw in enumerate(data.get("servers", [])):
        label = raw.get("name", f"#{i + 1}") if isinstance(raw, dict) else f"#{i + 1}"
        try:
            servers.append(_parse_server(raw, i))
        except (ConfigError, ValueError, TypeError) as e:
            errors.append((label, str(e)))

    return Settings(
        ping_timeout=int(data.get("ping_timeout_seconds", 3)),
        ssh_timeout=int(data.get("ssh_timeout_seconds", 10)),
        log_file=data.get("log_file", "logs/monitor.log"),
        servers=servers,
        errors=errors,
    )
