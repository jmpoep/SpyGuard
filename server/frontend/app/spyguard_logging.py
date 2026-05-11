#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import threading

LOG_PATH = "/tmp/spyguard.log"
_lock = threading.Lock()


def reset_log() -> None:
    """Truncate the log file (new analysis session)."""
    try:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.write("")
    except Exception:
        # If we can't write, we keep running silently.
        pass


def get_logger() -> logging.Logger:
    """Return the shared SpyGuard logger writing to /tmp/spyguard.log."""
    logger = logging.getLogger("spyguard")
    if getattr(logger, "_spyguard_configured", False):
        return logger

    with _lock:
        if getattr(logger, "_spyguard_configured", False):
            return logger

        logger.setLevel(logging.INFO)

        try:
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        except Exception:
            pass

        handler = None
        try:
            # Best effort: ensure the file is writable for the service user.
            # If the file already exists with restrictive permissions, this may fail.
            if os.path.exists(LOG_PATH):
                try:
                    os.chmod(LOG_PATH, 0o666)
                except Exception:
                    pass

            handler = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
        except Exception:
            # Fallback: don't crash the service if /tmp/spyguard.log isn't writable.
            handler = logging.StreamHandler(sys.stderr)

        handler.setLevel(logging.INFO)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s [%(process)d] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.propagate = False
        logger._spyguard_configured = True
        return logger

