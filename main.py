import argparse
import sys
import threading
import time

from checker import check_server
from config import ConfigError, load_config
from logger_setup import setup_logger


def server_loop(srv, settings, stop: threading.Event, log):
    """هر سرور یک نخ مستقل دارد؛ بررسی‌های یک سرور پشت‌سرهم اجرا می‌شوند."""
    interval = srv.interval_minutes * 60
    next_run = time.monotonic()
    while not stop.is_set():
        check_server(srv, settings.ping_timeout, settings.ssh_timeout)
        next_run += interval
        now = time.monotonic()
        if next_run < now:
            log.warning("[%s] بررسی از فاصله تعیین‌شده طولانی‌تر شد؛ نوبت‌های عقب‌افتاده رد شد", srv.name)
            next_run = now + interval
        stop.wait(next_run - now)


def main():
    ap = argparse.ArgumentParser(description="Linux servers monitor")
    ap.add_argument("-c", "--config", default="config.json")
    args = ap.parse_args()

    try:
        settings = load_config(args.config)
    except ConfigError as e:
        print(f"خطای کانفیگ: {e}", file=sys.stderr)
        return 1

    log = setup_logger(settings.log_file)
    for label, err in settings.errors:
        log.error("تنظیمات سرور '%s' نامعتبر است و نادیده گرفته شد: %s", label, err)
    if not settings.servers:
        log.error("هیچ سرور معتبری برای مانیتور وجود ندارد")
        return 1

    stop = threading.Event()
    threads = [threading.Thread(target=server_loop, args=(s, settings, stop, log),
                                name=s.name, daemon=True)
               for s in settings.servers]
    log.info("مانیتورینگ %d سرور شروع شد. برای خروج Ctrl+C", len(threads))
    for t in threads:
        t.start()

    try:
        while not stop.is_set():
            stop.wait(0.5)
    except KeyboardInterrupt:
        log.info("درخواست خروج دریافت شد؛ در حال خاتمه...")
        stop.set()
    for t in threads:
        t.join(timeout=15)
    log.info("پایان.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
