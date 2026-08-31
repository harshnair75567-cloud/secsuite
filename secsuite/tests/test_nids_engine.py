"""Tests for NIDS engine"""

import json
import tempfile
from pathlib import Path

from secsuite.modules.nids.engine import (
    DetectionEvent,
    EventLogger,
    HeuristicEngine,
    NIDSEngine,
    SignatureEngine,
)


class TestSignatureEngine:
    """Test signature engine"""

    def test_load_signatures(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"signatures": [{"name": "TEST_SIG", "flags": 1, "description": "Test"}]}')
            temp_path = f.name

        try:
            engine = SignatureEngine(temp_path)
            assert len(engine.signatures) == 1
            assert engine.signatures[0].name == "TEST_SIG"
            assert engine.signatures[0].flags == 1
        finally:
            Path(temp_path).unlink()

    def test_analyze_null_scan(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"signatures": [{"name": "NULL_SCAN", "flags": 0, "description": "Null scan"}]}')
            temp_path = f.name

        try:
            engine = SignatureEngine(temp_path)
            # Packet with all zero flags (byte 13 = 0)
            hex_data = "00" * 13 + "00" + "00" * 10
            matches = engine.analyze(hex_data)
            assert len(matches) == 1
            assert matches[0].name == "NULL_SCAN"
        finally:
            Path(temp_path).unlink()

    def test_analyze_syn_fin(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"signatures": [{"name": "SYN_FIN", "flags": 3, "description": "SYN+FIN"}]}')
            temp_path = f.name

        try:
            engine = SignatureEngine(temp_path)
            # Packet with SYN (2) + FIN (1) = 3
            hex_data = "00" * 13 + "03" + "00" * 10
            matches = engine.analyze(hex_data)
            assert len(matches) == 1
            assert matches[0].name == "SYN_FIN"
        finally:
            Path(temp_path).unlink()

    def test_analyze_no_match(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"signatures": [{"name": "TEST", "flags": 1, "description": "Test"}]}')
            temp_path = f.name

        try:
            engine = SignatureEngine(temp_path)
            # Packet with different flags
            hex_data = "00" * 13 + "02" + "00" * 10
            matches = engine.analyze(hex_data)
            assert len(matches) == 0
        finally:
            Path(temp_path).unlink()


class TestHeuristicEngine:
    """Test heuristic engine"""

    def test_single_probe(self):
        engine = HeuristicEngine(scan_threshold=3)
        event = engine.record_hit("192.168.1.1", 22)
        assert event.event_type == "SINGLE_PROBE"
        assert event.severity == "LOW"

    def test_port_scan_detection(self):
        engine = HeuristicEngine(scan_threshold=3)
        engine.record_hit("192.168.1.1", 22)
        engine.record_hit("192.168.1.1", 80)
        event = engine.record_hit("192.168.1.1", 443)
        assert event.event_type == "PORT_SCAN"
        assert event.severity == "HIGH"

    def test_different_ips_separate(self):
        engine = HeuristicEngine(scan_threshold=3)
        engine.record_hit("192.168.1.1", 22)
        engine.record_hit("192.168.1.1", 80)
        event = engine.record_hit("192.168.1.2", 443)
        assert event.event_type == "SINGLE_PROBE"

    def test_cache_cleanup(self):
        engine = HeuristicEngine(scan_threshold=3, cache_ttl=0)
        engine.record_hit("192.168.1.1", 22)
        import time
        time.sleep(0.01)
        # Trigger cleanup by recording another hit
        engine.record_hit("192.168.1.2", 22)
        stats = engine.get_stats()
        # Cache should be cleaned up due to TTL=0
        assert stats["tracked_ips"] == 1  # Only the new IP should remain


class TestEventLogger:
    """Test event logger"""

    def test_log_event(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            logger = EventLogger(temp_path)
            event = DetectionEvent(
                timestamp="2024-01-01 12:00:00.000",
                attacker_ip="192.168.1.1",
                target_port=22,
                event_type="PORT_SCAN",
                severity="HIGH"
            )
            logger.log(event)

            content = Path(temp_path).read_text()
            data = json.loads(content.strip())

            assert data["attacker_ip"] == "192.168.1.1"
            assert data["target_port"] == 22
            assert data["event_type"] == "PORT_SCAN"
            assert data["severity"] == "HIGH"
        finally:
            Path(temp_path).unlink()


class TestNIDSEngine:
    """Test integrated NIDS engine"""

    def test_process_packet(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"signatures": [{"name": "NULL_SCAN", "flags": 0, "description": "Null scan"}]}')
            sig_path = f.name

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            log_path = f.name

        try:
            engine = NIDSEngine(signatures_file=sig_path, log_file=log_path)
            events = engine.process_packet("192.168.1.1", 22, "00" * 13 + "00" + "00" * 10)

            assert len(events) == 2  # Heuristic + signature
            event_types = [e.event_type for e in events]
            assert "SINGLE_PROBE" in event_types
            assert "SIGNATURE_MATCH" in event_types

            # Check log file
            content = Path(log_path).read_text()
            lines = content.strip().split('\n')
            assert len(lines) == 2
        finally:
            Path(sig_path).unlink()
            Path(log_path).unlink()

    def test_get_stats(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"signatures": [{"name": "TEST", "flags": 1, "description": "Test"}]}')
            sig_path = f.name

        try:
            engine = NIDSEngine(signatures_file=sig_path)
            stats = engine.get_stats()
            assert stats["signatures_loaded"] == 1
            assert "heuristic" in stats
        finally:
            Path(sig_path).unlink()