import logging
from datetime import datetime

# Color map inspired by user's snippet
COLORS = {
    "INFO": "\033[94m",    # Blue
    "CHAT": "\033[92m",    # Green
    "WARN": "\033[93m",    # Yellow
    "WARNING": "\033[93m", # Yellow
    "ERROR": "\033[91m",   # Red
    "AI": "\033[95m",      # Magenta
    "RESET": "\033[36m",   # Cyan
    "ENDC": "\033[0m"
}


class ColoredFormatter(logging.Formatter):
    """Logging formatter that adds ANSI colors to the level name."""

    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        color = COLORS.get(levelname, COLORS.get('INFO'))
        timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        msg = super().format(record)
        return f"{color}[{timestamp}][{levelname}] {msg}{COLORS['ENDC']}"


def setup_colored_logger(logger_name: str = None):
    """Attach a colored console handler to the root logger or a named logger.

    If a console handler already exists, its formatter is replaced with the colored formatter.
    """
    root = logging.getLogger(logger_name) if logger_name else logging.getLogger()

    # Build colored formatter (keep message only to avoid duplication)
    colored_fmt = ColoredFormatter('%(message)s')

    # Find an existing console/stream handler and replace its formatter, else add one
    stream_handler = None
    for h in list(root.handlers):
        if isinstance(h, logging.StreamHandler):
            stream_handler = h
            break

    if stream_handler:
        stream_handler.setFormatter(colored_fmt)
    else:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(colored_fmt)
        root.addHandler(handler)

    # Ensure root level is not higher than INFO so colored logs show
    if root.level > logging.INFO:
        root.setLevel(logging.INFO)


__all__ = ["setup_colored_logger", "ColoredFormatter"]
