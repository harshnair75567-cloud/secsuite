"""Integration tests for secsuite"""

import json
import tempfile
import time
import threading
from pathlib import Path

import pytest

from secsuite.config import Config
from secsuite.modules.nids.engine import NIDSEngine
from secsuite.modules.fim import create_baseline, audit_directory
from secsuite.utils.hashing import hash_file, HashAlgorithm


class TestIntegration:
    """Integration tests"""

    def test_full_fim_workflow(self):
        """Test complete FIM workflow: baseline -> modify -> audit"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "protected"
            target.mkdir()
            (target / "config.txt").write_text("secure config")
            (target / "data.txt").write_text("important data")

            baseline_file = str(root / "baseline.json")

            # Create baseline
            assert create_baseline(str(target), baseline_file)

            # Verify baseline loads correctly
            from secsuite.modules.fim.manifest import load_manifest
            baseline = load_manifest(baseline_file)
            assert baseline is not None
            assert len(baseline) == 2

            # Audit immediately - no changes
            result = audit_directory(str(target), baseline_file)
            assert result is not None
            assert not result["changes"].has_changes()

            # Modify a file
            (target / "config.txt").write_text("MODIFIED - COMPROMISED")

            # Audit again - should detect change
            result = audit_directory(str(target), baseline_file)
            assert result is not None
            assert result["changes"].has_changes()
            assert "config.txt" in result["changes"].modified

            # Add a file
            (target / "new_file.txt").write_text("new")

            result = audit_directory(str(target), baseline_file)
            assert "new_file.txt" in result["changes"].added

            # Delete a file
            (target / "data.txt").unlink()

            result = audit_directory(str(target), baseline_file)
            assert "data.txt" in result["changes"].deleted

    def test_nids_signature_detection(self):
        """Test NIDS signature detection with various packet types"""
        with tempfile.TemporaryDirectory() as tmpdir:
            sig_file = Path(tmpdir) / "signatures.json"
            sig_file.write_text(json.dumps({
                "signatures": [
                    {"name": "NULL_SCAN", "flags": 0, "description": "Null scan"},
                    {"name": "SYN_FIN", "flags": 3, "description": "SYN+FIN"},
                    {"name": "XMAS", "flags": 41, "description": "XMAS scan"}
                ]
            }))

            log_file = Path(tmpdir) / "ids_log.json"
            engine = NIDSEngine(str(sig_file), str(log_file))

            # Test NULL scan (flags=0)
            events = engine.process_packet("10.0.0.1", 22, "00" * 13 + "00" + "00" * 10)
            sig_events = [e for e in events if e.event_type == "SIGNATURE_MATCH"]
            assert any(e.signature_name == "NULL_SCAN" for e in sig_events)

            # Test SYN+FIN (flags=3)
            events = engine.process_packet("10.0.0.2", 80, "00" * 13 + "03" + "00" * 10)
            sig_events = [e for e in events if e.event_type == "SIGNATURE_MATCH"]
            assert any(e.signature_name == "SYN_FIN" for e in sig_events)

            # Test XMAS (flags=41)
            events = engine.process_packet("10.0.0.3", 443, "00" * 13 + "29" + "00" * 10)
            sig_events = [e for e in events if e.event_type == "SIGNATURE_MATCH"]
            assert any(e.signature_name == "XMAS" for e in sig_events)

    def test_nids_heuristic_port_scan(self):
        """Test NIDS heuristic port scan detection"""
        with tempfile.TemporaryDirectory() as tmpdir:
            sig_file = Path(tmpdir) / "signatures.json"
            sig_file.write_text(json.dumps({"signatures": []}))

            log_file = Path(tmpdir) / "ids_log.json"
            engine = NIDSEngine(str(sig_file), str(log_file), scan_threshold=3)

            # First two ports - single probes
            events = engine.process_packet("192.168.1.100", 22, "00" * 20)
            assert events[0].event_type == "SINGLE_PROBE"

            events = engine.process_packet("192.168.1.100", 80, "00" * 20)
            assert events[0].event_type == "SINGLE_PROBE"

            # Third port - should trigger PORT_SCAN
            events = engine.process_packet("192.168.1.100", 443, "00" * 20)
            assert events[0].event_type == "PORT_SCAN"
            assert events[0].severity == "HIGH"

            # Different IP - separate tracking
            events = engine.process_packet("192.168.1.200", 22, "00" * 20)
            assert events[0].event_type == "SINGLE_PROBE"

    def test_hash_consistency(self):
        """Test that hashing produces consistent results"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content for hashing")
            temp_path = f.name

        try:
            hash1 = hash_file(temp_path, HashAlgorithm.SHA256)
            hash2 = hash_file(temp_path, HashAlgorithm.SHA256)
            assert hash1 == hash2
            assert len(hash1) == 64
        finally:
            Path(temp_path).unlink()

    def test_config_persistence(self):
        """Test config save/load roundtrip"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            config = Config()
            config.set("nids", "ports", [80, 443, 8080])
            config.set("fim", "algorithm", "sha512")
            config.save(temp_path)

            config2 = Config(temp_path)
            assert config2.get("nids", "ports") == [80, 443, 8080]
            assert config2.get("fim", "algorithm") == "sha512"
        finally:
            Path(temp_path).unlink()