"""Configuration management for secsuite"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_CONFIG = {
    "general": {
        "log_file": "secsuite.log",
        "log_level": "INFO",
        "log_max_size": 10485760,
        "log_backup_count": 5,
        "pid_file": "secsuite.pid"
    },
    "nids": {
        "enabled": True,
        "ports": [21, 4444, 7777, 8888, 9999, 9090],
        "scan_threshold": 3,
        "signatures_file": "signatures.json",
        "bind_address": "0.0.0.0"
    },
    "hips": {
        "enabled": True,
        "watch_zones": [],
        "safe_tools": ["mousepad", "nano", "vim", "python3", "thunar", "code", "cat", "less", "tail"],
        "poll_interval": 0.8,
        "log_file": "hips.log"
    },
    "fim": {
        "enabled": True,
        "target_dir": ".",
        "algorithm": "sha256",
        "chunk_size": 4096,
        "baseline_file": "baseline.json",
        "secret_key": "",
        "exclude_patterns": [".git", "__pycache__", "*.pyc", "*.log", "*.pid"]
    }
}


class Config:
    """Configuration manager with validation and defaults"""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config()
        self._config: Dict[str, Any] = {}
        self.load()

    def _find_config(self) -> str:
        """Find config file in standard locations"""
        locations = [
            Path.cwd() / "config.json",
            Path.home() / ".config" / "secsuite" / "config.json",
            Path("/etc/secsuite/config.json")
        ]
        for loc in locations:
            if loc.exists():
                return str(loc)
        return str(locations[0])

    def load(self) -> None:
        """Load configuration from file, merging with defaults"""
        self._config = DEFAULT_CONFIG.copy()
        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                self._deep_merge(self._config, user_config)
            except (OSError, json.JSONDecodeError) as e:
                print(f"[WARNING] Failed to load config from {self.config_path}: {e}")

    def _deep_merge(self, base: Dict, override: Dict) -> None:
        """Recursively merge override into base"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def save(self, path: Optional[str] = None) -> None:
        """Save current configuration to file"""
        target = path or self.config_path
        dir_name = os.path.dirname(target)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        with open(target, 'w') as f:
            json.dump(self._config, f, indent=2)

    def get(self, section: str, key: str = None, default: Any = None) -> Any:
        """Get configuration value"""
        if key is None:
            return self._config.get(section, default)
        return self._config.get(section, {}).get(key, default)

    def set(self, section: str, key: str, value: Any) -> None:
        """Set configuration value"""
        if section not in self._config:
            self._config[section] = {}
        self._config[section][key] = value

    def get_section(self, section: str) -> Dict:
        """Get entire configuration section"""
        return self._config.get(section, {}).copy()

    @property
    def config(self) -> Dict:
        """Return full configuration dict"""
        return self._config.copy()


_config_instance: Optional[Config] = None


def get_config(config_path: Optional[str] = None) -> Config:
    """Get global config instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_path)
    return _config_instance