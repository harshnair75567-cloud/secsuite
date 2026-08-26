"""Tests for logging utilities"""

import json
import logging
import tempfile
from pathlib import Path

import pytest

from secsuite.logging import JsonFormatter, JsonLogger, setup_logging


class TestLogging:
    """Test logging utilities"""

    def test_json_formatter(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.module = "test_module"
        record.funcName = "test_func"

        result = formatter.format(record)
        data = json.loads(result)

        assert data["message"] == "Test message"
        assert data["level"] == "INFO"
        assert data["logger"] == "test"
        assert data["module"] == "test_module"
        assert data["function"] == "test_func"

    def test_json_formatter_with_extra(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="",
            lineno=1,
            msg="Test with extra",
            args=(),
            exc_info=None
        )
        record.module = "test"
        record.funcName = "test"
        record.extra_fields = {"custom_field": "custom_value"}

        result = formatter.format(record)
        data = json.loads(result)

        assert data["custom_field"] == "custom_value"

    def test_json_logger_singleton(self):
        logger1 = JsonLogger("test_singleton")
        logger2 = JsonLogger("test_singleton")
        assert logger1 is logger2

    def test_json_logger_levels(self):
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
            temp_path = f.name

        try:
            logger = JsonLogger("test_levels", {"log_file": temp_path, "log_level": "DEBUG"})
            logger.debug("Debug message")
            logger.info("Info message")
            logger.warning("Warning message")
            logger.error("Error message")

            content = Path(temp_path).read_text()
            lines = content.strip().split('\n')
            assert len(lines) == 4

            for line in lines:
                data = json.loads(line)
                assert "timestamp" in data
                assert "level" in data
        finally:
            Path(temp_path).unlink()

    def test_log_event(self):
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
            temp_path = f.name

        try:
            logger = JsonLogger("test_event", {"log_file": temp_path})
            logger.log_event("PORT_SCAN", "HIGH", attacker_ip="192.168.1.1", target_port=22)

            content = Path(temp_path).read_text()
            data = json.loads(content.strip())

            assert data["message"] == "Security event: PORT_SCAN"
            assert data["event_type"] == "PORT_SCAN"
            assert data["severity"] == "HIGH"
            assert data["attacker_ip"] == "192.168.1.1"
            assert data["target_port"] == 22
        finally:
            Path(temp_path).unlink()

    def test_setup_logging(self):
        config = {
            "general": {
                "log_file": "test.log",
                "log_level": "INFO"
            }
        }
        logger = setup_logging(config)
        assert isinstance(logger, JsonLogger)