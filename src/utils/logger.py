# utils/logger.py
import logging
import sys

from colorlog import ColoredFormatter


def setup_logger(level: str = "INFO"):
    root = logging.getLogger()  # root logger

    if root.handlers:
        return

    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        ColoredFormatter(
            "%(log_color)s%(message)s",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        )
    )
    root.addHandler(handler)
