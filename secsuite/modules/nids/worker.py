"""NIDS Port Worker"""

import socket
import threading
import time
from typing import List, Optional

from ...logging import get_logger
from ...utils.net import create_listener, recv_hex
from .engine import NIDSEngine


class PortWorker:
    """Worker thread that listens on a single port"""

    def __init__(
        self,
        port: int,
        engine: NIDSEngine,
        bind_address: str = "0.0.0.0",
        buffer_size: int = 1024,
        connection_timeout: float = 5.0
    ):
        self.port = port
        self.engine = engine
        self.bind_address = bind_address
        self.buffer_size = buffer_size
        self.connection_timeout = connection_timeout
        self.logger = get_logger(f"nids.worker.{port}")
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._socket: Optional[socket.socket] = None

    def start(self) -> None:
        """Start the worker thread"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name=f"nids-worker-{self.port}",
            daemon=True
        )
        self._thread.start()
        self.logger.info(f"Worker started on port {self.port}")

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the worker thread"""
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=timeout)
        self.logger.info(f"Worker stopped on port {self.port}")

    def _run(self) -> None:
        """Main worker loop"""
        try:
            with create_listener(self.port, self.bind_address) as sock:
                self._socket = sock
                self.logger.info(f"Listening on {self.bind_address}:{self.port}")

                while self._running:
                    try:
                        sock.settimeout(1.0)
                        client, addr = sock.accept()
                        client.settimeout(self.connection_timeout)

                        attacker_ip = addr[0]
                        self.logger.debug(f"Connection from {attacker_ip}")

                        try:
                            hex_payload = recv_hex(client, self.buffer_size)
                            if hex_payload:
                                self.engine.process_packet(attacker_ip, self.port, hex_payload)

                            self.logger.warning(
                                f"Connection from {attacker_ip} on port {self.port}",
                                attacker_ip=attacker_ip,
                                port=self.port
                            )

                        except Exception as e:
                            self.logger.error(f"Error processing connection: {e}")
                        finally:
                            client.close()

                    except socket.timeout:
                        continue
                    except OSError:
                        if self._running:
                            raise

        except Exception as e:
            if self._running:
                self.logger.error(f"Worker error on port {self.port}: {e}")


class WorkerPool:
    """Manages multiple port workers"""

    def __init__(
        self,
        ports: List[int],
        engine: NIDSEngine,
        bind_address: str = "0.0.0.0"
    ):
        self.ports = ports
        self.engine = engine
        self.bind_address = bind_address
        self.workers: List[PortWorker] = []
        self.logger = get_logger("nids.pool")

    def start_all(self) -> None:
        """Start all workers"""
        for port in self.ports:
            worker = PortWorker(port, self.engine, self.bind_address)
            worker.start()
            self.workers.append(worker)
        self.logger.info(f"Started {len(self.workers)} workers on ports: {self.ports}")

    def stop_all(self, timeout: float = 2.0) -> None:
        """Stop all workers"""
        for worker in self.workers:
            worker.stop(timeout)
        self.workers.clear()
        self.logger.info("All workers stopped")

    def get_status(self) -> List[dict]:
        """Get status of all workers"""
        return [
            {
                "port": w.port,
                "running": w._running,
                "thread_alive": w._thread.is_alive() if w._thread else False
            }
            for w in self.workers
        ]


def run_nids(config: dict) -> None:
    """Main NIDS entry point"""
    from ...logging import setup_logging

    logger = setup_logging(config)
    nids_config = config.get("nids", {})

    engine = NIDSEngine(
        signatures_file=nids_config.get("signatures_file", "signatures.json"),
        log_file=nids_config.get("log_file", "ids_log.json"),
        scan_threshold=nids_config.get("scan_threshold", 3)
    )

    ports = nids_config.get("ports", [21, 4444, 7777, 8888, 9999, 9090])
    bind_address = nids_config.get("bind_address", "0.0.0.0")

    pool = WorkerPool(ports, engine, bind_address)

    logger.info("NIDS engine starting", ports=ports, bind_address=bind_address)
    pool.start_all()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
    finally:
        pool.stop_all()
        logger.info("NIDS engine stopped")