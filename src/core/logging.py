
import json
import logging
import sys
from datetime import UTC, datetime

from src.core.config import get_config

cfg = get_config()


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "service": cfg.app_name,
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return (
            f"[{datetime.now(UTC).isoformat()}] "
            f"[{record.levelname}] [{record.module}:{record.lineno}] "
            f"{record.getMessage()}"
        )


def setup_logging() -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        handlers=handlers,
        force=True,
    )

    fmt = JSONFormatter() if cfg.log_format == "json" else TextFormatter()
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.setFormatter(fmt)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
