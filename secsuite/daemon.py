"""Service daemon runner with signal handling"""

import atexit
import os
import signal
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Optional


class ServiceRunner:
    """Manages service lifecycle: start, stop, restart, status"""

    def __init__(self, name: str, pid_file: str, target: Callable, args: tuple = (), kwargs: dict = None):
        self.name = name
        self.pid_file = Path(pid_file)
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self._shutdown_event = threading.Event()
        self._lock = threading.Lock()

    def start(self, daemon: bool = True) -> bool:
        """Start the service"""
        with self._lock:
            if self.running:
                print(f"[{self.name}] Already running")
                return False

            if self.pid_file.exists():
                try:
                    old_pid = int(self.pid_file.read_text().strip())
                    if self._is_process_alive(old_pid):
                        print(f"[{self.name}] Already running (PID: {old_pid})")
                        return False
                except (ValueError, OSError):
                    pass

            self._shutdown_event.clear()
            self.thread = threading.Thread(
                target=self._run_wrapper,
                name=f"{self.name}-worker",
                daemon=daemon
            )
            self.thread.start()

            time.sleep(0.1)
            if self.thread.is_alive():
                self.running = True
                self._write_pid()
                print(f"[{self.name}] Started (PID: {os.getpid()})")
                return True
            else:
                print(f"[{self.name}] Failed to start")
                return False

    def _run_wrapper(self) -> None:
        """Wrapper to catch exceptions and handle shutdown"""
        try:
            self.target(*self.args, **self.kwargs)
        except Exception as e:
            print(f"[{self.name}] Error: {e}")
        finally:
            with self._lock:
                self.running = False
                self._remove_pid()

    def stop(self, timeout: float = 5.0) -> bool:
        """Stop the service gracefully"""
        with self._lock:
            if not self.running or not self.thread:
                print(f"[{self.name}] Not running")
                return True

            self._shutdown_event.set()

        self.thread.join(timeout=timeout)

        with self._lock:
            if self.thread.is_alive():
                print(f"[{self.name}] Force stopping...")
                return False

            self.running = False
            self._remove_pid()
            print(f"[{self.name}] Stopped")
            return True

    def restart(self) -> bool:
        """Restart the service"""
        self.stop()
        time.sleep(0.5)
        return self.start()

    def status(self) -> Dict:
        """Get service status"""
        pid = None
        if self.pid_file.exists():
            try:
                pid = int(self.pid_file.read_text().strip())
            except (ValueError, OSError):
                pass

        return {
            "name": self.name,
            "running": self.running,
            "pid": pid,
            "pid_file": str(self.pid_file)
        }

    def _write_pid(self) -> None:
        """Write PID file"""
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        self.pid_file.write_text(str(os.getpid()))

    def _remove_pid(self) -> None:
        """Remove PID file"""
        try:
            self.pid_file.unlink(missing_ok=True)
        except OSError:
            pass

    def _is_process_alive(self, pid: int) -> bool:
        """Check if process is alive"""
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def wait_for_shutdown(self) -> None:
        """Block until shutdown signal received"""
        self._shutdown_event.wait()


class MultiServiceRunner:
    """Manages multiple services"""

    def __init__(self):
        self.services: Dict[str, ServiceRunner] = {}
        self._shutdown_event = threading.Event()
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        atexit.register(self.stop_all)

    def _signal_handler(self, signum, frame):
        print(f"\n[secsuite] Received signal {signum}, shutting down...")
        self._shutdown_event.set()
        self.stop_all()

    def add_service(self, name: str, pid_file: str, target: Callable, args: tuple = (), kwargs: dict = None) -> ServiceRunner:
        """Add a service to manage"""
        runner = ServiceRunner(name, pid_file, target, args, kwargs)
        self.services[name] = runner
        return runner

    def start_all(self) -> Dict[str, bool]:
        """Start all services"""
        results = {}
        for name, runner in self.services.items():
            results[name] = runner.start()
        return results

    def stop_all(self) -> Dict[str, bool]:
        """Stop all services"""
        results = {}
        for name, runner in self.services.items():
            results[name] = runner.stop()
        return results

    def status_all(self) -> Dict[str, Dict]:
        """Get status of all services"""
        return {name: runner.status() for name, runner in self.services.items()}

    def wait(self) -> None:
        """Wait for shutdown signal"""
        self._shutdown_event.wait()


def create_runner(config: Dict, modules: Dict[str, Callable]) -> MultiServiceRunner:
    """Factory to create MultiServiceRunner from config"""
    runner = MultiServiceRunner()
    general = config.get("general", {})
    pid_dir = Path(general.get("pid_file", "secsuite.pid")).parent

    for module_name, module_config in config.items():
        if module_name == "general":
            continue
        if not module_config.get("enabled", True):
            continue

        if module_name in modules:
            pid_file = str(pid_dir / f"{module_name}.pid")
            runner.add_service(
                name=module_name,
                pid_file=pid_file,
                target=modules[module_name],
                kwargs={"config": module_config}
            )

    return runner