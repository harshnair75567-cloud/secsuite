"""Tests for configuration management"""

import json
import tempfile
from pathlib import Path

from secsuite.config import DEFAULT_CONFIG, Config


class TestConfig:
    """Test configuration management"""

    def test_default_config(self):
        config = Config()
        assert config.config == DEFAULT_CONFIG

    def test_load_config_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            custom_config = {
                "nids": {
                    "ports": [80, 443],
                    "scan_threshold": 5
                }
            }
            json.dump(custom_config, f)
            temp_path = f.name

        try:
            config = Config(temp_path)
            assert config.get("nids", "ports") == [80, 443]
            assert config.get("nids", "scan_threshold") == 5
            # Defaults should still be present
            assert config.get("nids", "enabled") is True
        finally:
            Path(temp_path).unlink()

    def test_deep_merge(self):
        config = Config()
        base = {"a": {"b": 1, "c": 2}}
        override = {"a": {"c": 3, "d": 4}}
        config._deep_merge(base, override)
        assert base == {"a": {"b": 1, "c": 3, "d": 4}}

    def test_get_set(self):
        config = Config()
        config.set("test", "key", "value")
        assert config.get("test", "key") == "value"
        assert config.get("test", "missing", "default") == "default"

    def test_get_section(self):
        config = Config()
        section = config.get_section("nids")
        assert isinstance(section, dict)
        assert section["enabled"] is True

    def test_save_config(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            config = Config()
            config.set("nids", "scan_threshold", 10)
            config.save(temp_path)

            # Reload and verify
            config2 = Config(temp_path)
            assert config2.get("nids", "scan_threshold") == 10
        finally:
            Path(temp_path).unlink()

    def test_invalid_config_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json {")
            temp_path = f.name

        try:
            config = Config(temp_path)
            # Should fall back to defaults
            assert config.config == DEFAULT_CONFIG
        finally:
            Path(temp_path).unlink()