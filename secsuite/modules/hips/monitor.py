"""HIPS Module - Host Intrusion Prevention System"""

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from ...utils.process import get_pids_for_file, get_process_info, kill_process, get_current_tty, is_process_safe
from ...utils.fs import walk_files, atomic_write
from ...logging import get_logger, JsonLogger


@dataclass
class FileAccessEvent:
    """File access event"""
    timestamp: str
    file_path: str
    process_name: str
    process_tty: str
    pid: int
    action: str  # "ALERT", "TERMINATE", "ALLOWED"
    user: str = ""


class AccessMonitor:
    """Monitors file access using atime"""

    def __init__(
        self,
        watch_zones: List[str],
        safe_tools: Set[str],
        poll_interval: float = 0.8,
        log_file: str = "hips.log"
    ):
        self.watch_zones = [Path(z).resolve() for z in watch_zones if Path(z).exists()]
        self.safe_tools = safe_tools
        self.poll_interval = poll_interval
        self.log_file = Path(log_file)
        self.logger = get_logger("hips.monitor")
        self._file_atimes: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.my_tty = get_current_tty()

    def start(self) -> None:
        """Start monitoring"""
        if self._running:
            return

        self._snapshot()
        self._running = True
        self._thread = threading.Thread(target=self._run, name="hips-monitor", daemon=True)
        self._thread.start()
        self.logger.info(f"HIPS monitor started, watching {len(self.watch_zones)} zones")

    def stop(self, timeout: float = 2.0) -> None:
        """Stop monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=timeout)
        self.logger.info("HIPS monitor stopped")

    def _snapshot(self) -> None:
        """Take initial snapshot of file access times"""
        with self._lock:
            self._file_atimes.clear()
            for zone in self.watch_zones:
                for filepath in walk_files(zone):
                    try:
                        self._file_atimes[str(filepath)] = filepath.stat().st_atime
                    except OSError:
                        pass

    def _run(self) -> None:
        """Main monitoring loop"""
        while self._running:
            time.sleep(self.poll_interval)
            self._check_access()

    def _check_access(self) -> None:
        """Check for file access changes"""
        current_atimes = {}

        for zone in self.watch_zones:
            for filepath in walk_files(zone):
                try:
                    current_atimes[str(filepath)] = filepath.stat().st_atime
                except OSError:
                    pass

        with self._lock:
            for path_str, atime in current_atimes.items():
                if path_str in self._file_atimes:
                    if atime != self._file_atimes[path_str]:
                        self._handle_access(path_str)
                        self._file_atimes[path_str] = atime
                else:
                    self._file_atimes[path_str] = atime

    def _handle_access(self, file_path: str) -> None:
        """Handle file access event"""
        pids = get_pids_for_file(file_path)

        for pid in pids:
            info = get_process_info(pid)
            if not info:
                continue

            is_safe = is_process_safe(pid, self.safe_tools, self.my_tty)

            event = FileAccessEvent(
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                file_path=file_path,
                process_name=info.name,
                process_tty=info.tty,
                pid=pid,
                action="ALLOWED" if is_safe else "ALERT",
                user=info.user
            )

            if not is_safe:
                self.logger.warning(
                    f"Unauthorized access: {info.name} (PID: {pid}, TTY: {info.tty}) -> {file_path}",
                    file=file_path,
                    process=info.name,
                    pid=pid,
                    tty=info.tty,
                    action="ALERT"
                )
                self._log_event(event)
                self._respond(event)
            else:
                self.logger.debug(
                    f"Allowed access: {info.name} -> {file_path}",
                    file=file_path,
                    process=info.name,
                    action="ALLOWED"
                )

    def _log_event(self, event: FileAccessEvent) -> None:
        """Log event to file"""
        try:
            event_data = {
                "time": event.timestamp,
                "file": event.file_path,
                "tool": event.process_name,
                "tty": event.process_tty,
                "pid": event.pid,
                "user": event.user,
                "action": event.action
            }
            with atomic_write(self.log_file, 'a') as f:
                f.write(json.dumps(event_data) + "\n")
        except (OSError, IOError) as e:
            self.logger.error(f"Failed to log event: {e}")

    def _respond(self, event: FileAccessEvent) -> None:
        """Respond to unauthorized access"""
        if kill_process(event.pid):
            self.logger.critical(f"Terminated PID {event.pid} ({event.process_name})")
            event.action = "TERMINATE"
            self._log_event(event)
        else:
            self.logger.error(f"Failed to terminate PID {event.pid}")


class Responder:
    """Active response actions"""

    @staticmethod
    def terminate_process(pid: int) -> bool:
        """Terminate a process"""
        return kill_process(pid, 9)

    @staticmethod
    def terminate_process_tree(pid: int) -> int:
        """Terminate process and its children"""
        # Would need pgrep -P or /proc parsing
        return 0

    @staticmethod
    def quarantine_file(file_path: str, quarantine_dir: str = "/tmp/hips_quarantine") -> bool:
        """Move file to quarantine"""
        try:
            Path(quarantine_dir).mkdir(parents=True, exist_ok=True)
            dest = Path(quarantine_dir) / Path(file_path).name
            Path(file_path).rename(dest)
            return True
        except OSError:
            return False


def run_hips(config: dict) -> None:
    """Main HIPS entry point"""
    from ...logging import setup_logging

    logger = setup_logging(config)
    hips_config = config.get("hips", {})

    watch_zones = hips_config.get("watch_zones", [])
    safe_tools = set(hips_config.get("safe_tools", []))
    poll_interval = hips_config.get("poll_interval", 0.8)
    log_file = hips_config.get("log_file", "hips.log")

    if not watch_zones:
        logger.warning("No watch zones configured, HIPS will not monitor anything")
        return

    monitor = AccessMonitor(watch_zones, safe_tools, poll_interval, log_file)

    logger.info("HIPS starting", zones=watch_zones, safe_tools=list(safe_tools))
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
    finally:
        monitor.stop()
        logger.info("HIPS stopped")