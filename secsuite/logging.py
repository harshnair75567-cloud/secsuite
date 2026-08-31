"""Structured JSON logging with rotation"""

import json
import logging
import logging.handlers
import sys
import threading
from datetime import datetime
from typing import Dict, Optional


class JsonFormatter(logging.Formatter):
    """JSON log formatter with consistent structure"""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


class JsonLogger:
    """Thread-safe JSON logger with file rotation"""

    _instances: Dict[str, 'JsonLogger'] = {}
    _lock = threading.Lock()

    def __new__(cls, name: str = "secsuite", config: Optional[Dict] = None):
        with cls._lock:
            if name not in cls._instances:
                cls._instances[name] = super().__new__(cls)
            return cls._instances[name]

    def __init__(self, name: str = "secsuite", config: Optional[Dict] = None):
        if hasattr(self, '_initialized'):
            return

        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, self.config.get('log_level', 'INFO')))
        self.logger.propagate = False
        self._setup_handlers()
        self._initialized = True

    def _setup_handlers(self) -> None:
        """Setup file and console handlers"""
        self.logger.handlers.clear()

        log_file = self.config.get('log_file', 'secsuite.log')
        max_size = self.config.get('log_max_size', 10485760)
        backup_count = self.config.get('log_backup_count', 5)

        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_size, backupCount=backup_count
        )
        file_handler.setFormatter(JsonFormatter())
        self.logger.addHandler(file_handler)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(JsonFormatter())
        self.logger.addHandler(console_handler)

    def _log(self, level: int, message: str, **extra) -> None:
        """Internal log method with extra fields"""
        extra_fields = {"extra_fields": extra} if extra else {}
        self.logger.log(level, message, extra=extra_fields)

    def debug(self, message: str, **extra) -> None:
        self._log(logging.DEBUG, message, **extra)

    def info(self, message: str, **extra) -> None:
        self._log(logging.INFO, message, **extra)

    def warning(self, message: str, **extra) -> None:
        self._log(logging.WARNING, message, **extra)

    def error(self, message: str, **extra) -> None:
        self._log(logging.ERROR, message, **extra)

    def critical(self, message: str, **extra) -> None:
        self._log(logging.CRITICAL, message, **extra)

    def log_event(self, event_type: str, severity: str, **details) -> None:
        """Log a structured security event"""
        self.info(
            f"Security event: {event_type}",
            event_type=event_type,
            severity=severity,
            **details
        )


def get_logger(name: str = "secsuite", config: Optional[Dict] = None) -> JsonLogger:
    """Get or create a logger instance"""
    return JsonLogger(name, config)


def setup_logging(config: Dict) -> JsonLogger:
    """Setup root logger from config"""
    return get_logger("secsuite", config.get("general", {}))