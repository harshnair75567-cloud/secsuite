"""NIDS Detection Engine"""

import json
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from ...logging import get_logger
from ...utils.fs import read_json


@dataclass
class Signature:
    """Attack signature"""
    name: str
    flags: int
    description: str


@dataclass
class DetectionEvent:
    """Detection event"""
    timestamp: str
    attacker_ip: str
    target_port: int
    event_type: str
    severity: str
    signature_name: Optional[str] = None
    payload_hex: Optional[str] = None


class SignatureEngine:
    """Deep packet inspection engine"""

    def __init__(self, signatures_file: str = "signatures.json"):
        self.signatures_file = Path(signatures_file)
        self.signatures: List[Signature] = []
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Load signatures from JSON file"""
        data = read_json(self.signatures_file, {"signatures": []})
        self.signatures = [
            Signature(sig["name"], sig["flags"], sig.get("description", ""))
            for sig in data.get("signatures", [])
        ]

    def reload(self) -> None:
        """Reload signatures from file"""
        self._load_signatures()

    def analyze(self, hex_data: str) -> List[Signature]:
        """
        Analyze packet payload for signature matches.

        Args:
            hex_data: Packet payload as hex string

        Returns:
            List of matched signatures
        """
        matches = []
        try:
            packet = bytes.fromhex(hex_data)
            if len(packet) < 14:
                return matches

            tcp_flags = packet[13]

            for sig in self.signatures:
                if sig.flags == 0 and tcp_flags == 0 or (tcp_flags & sig.flags) == sig.flags:
                    matches.append(sig)

        except (ValueError, IndexError):
            pass

        return matches


class HeuristicEngine:
    """Heuristic detection engine for port scanning"""

    def __init__(self, scan_threshold: int = 3, cache_ttl: int = 3600):
        self.scan_threshold = scan_threshold
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def record_hit(self, attacker_ip: str, port: int) -> DetectionEvent:
        """
        Record a port hit and check for scan behavior.

        Args:
            attacker_ip: Source IP address
            port: Target port

        Returns:
            DetectionEvent with event type and severity
        """
        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S.%f")

        with self._lock:
            if attacker_ip not in self._cache:
                self._cache[attacker_ip] = {
                    "ports": set(),
                    "first_seen": now,
                    "last_seen": now
                }

            entry = self._cache[attacker_ip]
            entry["ports"].add(port)
            entry["last_seen"] = now

            unique_ports = len(entry["ports"])
            is_scan = unique_ports >= self.scan_threshold

            event = DetectionEvent(
                timestamp=timestamp,
                attacker_ip=attacker_ip,
                target_port=port,
                event_type="PORT_SCAN" if is_scan else "SINGLE_PROBE",
                severity="HIGH" if is_scan else "LOW"
            )

            self._cleanup_cache(now)
            return event

    def _cleanup_cache(self, now: datetime) -> None:
        """Remove stale cache entries"""
        expired = [
            ip for ip, entry in self._cache.items()
            if (now - entry["last_seen"]).total_seconds() > self.cache_ttl
        ]
        for ip in expired:
            del self._cache[ip]

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self._lock:
            return {
                "tracked_ips": len(self._cache),
                "total_ports": sum(len(e["ports"]) for e in self._cache.values())
            }


class EventLogger:
    """Thread-safe event logger"""

    def __init__(self, log_file: str = "ids_log.json"):
        self.log_file = Path(log_file)
        self._lock = threading.Lock()
        self.logger = get_logger("nids")

    def log(self, event: DetectionEvent) -> None:
        """Log detection event"""
        event_data = {
            "timestamp": event.timestamp,
            "attacker_ip": event.attacker_ip,
            "target_port": event.target_port,
            "event_type": event.event_type,
            "severity": event.severity
        }
        if event.signature_name:
            event_data["signature"] = event.signature_name
        if event.payload_hex:
            event_data["payload_hex"] = event.payload_hex

        with self._lock, open(self.log_file, "a") as f:
            f.write(json.dumps(event_data) + "\n")

        self.logger.log_event(
            event.event_type,
            event.severity,
            attacker_ip=event.attacker_ip,
            target_port=event.target_port,
            signature=event.signature_name
        )


class NIDSEngine:
    """Main NIDS engine combining signature and heuristic detection"""

    def __init__(
        self,
        signatures_file: str = "signatures.json",
        log_file: str = "ids_log.json",
        scan_threshold: int = 3
    ):
        self.signature_engine = SignatureEngine(signatures_file)
        self.heuristic_engine = HeuristicEngine(scan_threshold)
        self.event_logger = EventLogger(log_file)
        self.logger = get_logger("nids")

    def process_packet(self, attacker_ip: str, port: int, hex_payload: str) -> List[DetectionEvent]:
        """
        Process a packet through both engines.

        Args:
            attacker_ip: Source IP
            port: Target port
            hex_payload: Packet payload as hex

        Returns:
            List of detection events
        """
        events = []

        heuristic_event = self.heuristic_engine.record_hit(attacker_ip, port)
        events.append(heuristic_event)

        signature_matches = self.signature_engine.analyze(hex_payload)
        for sig in signature_matches:
            sig_event = DetectionEvent(
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                attacker_ip=attacker_ip,
                target_port=port,
                event_type="SIGNATURE_MATCH",
                severity="HIGH",
                signature_name=sig.name,
                payload_hex=hex_payload
            )
            events.append(sig_event)

        for event in events:
            self.event_logger.log(event)

        return events

    def get_stats(self) -> Dict:
        """Get engine statistics"""
        return {
            "signatures_loaded": len(self.signature_engine.signatures),
            "heuristic": self.heuristic_engine.get_stats()
        }