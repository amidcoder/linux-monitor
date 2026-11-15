import logging
import os
import sys
from logging.handlers import RotatingFileHandler


def setup_logger(log_file: str) -> logging.Logger:
    logger = logging.getLogger("monitor")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s",
                            "%Y-%m-%d %H:%M:%S")

    if sys.stderr is not None:
        console = logging.StreamHandler()
        console.setFormatter(fmt)
        logger.addHandler(console)

    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
    fh = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3,
                             encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger
