"""FIM Manifest - Baseline I/O operations"""

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Optional

from .engine import PyHashEngine, FileEntry
from .audit import sign_baseline, verify_baseline_integrity
from ...utils.fs import atomic_write, read_json
from ...logging import get_logger


def save_manifest(
    engine: PyHashEngine,
    output_file: str,
    secret_key: Optional[str] = None
) -> bool:
    """
    Save manifest to file.

    Args:
        engine: PyHashEngine with collected manifest
        output_file: Output file path
        secret_key: Optional HMAC key for integrity protection

    Returns:
        True if successful
    """
    logger = get_logger("fim.manifest")

    try:
        manifest = engine.get_manifest()
        data = {path: asdict(entry) for path, entry in manifest.items()}

        def write_func(f):
            json.dump(data, f, indent=2)

        if atomic_write(output_file, write_func):
            logger.info(f"Manifest saved to {output_file} ({len(manifest)} files)")

            if secret_key:
                if sign_baseline(output_file, secret_key):
                    logger.info("Baseline signed with HMAC")
                else:
                    logger.error("Failed to sign baseline")
            return True

    except (OSError, IOError, TypeError) as e:
        logger.error(f"Failed to save manifest: {e}")

    return False


def load_manifest(
    baseline_file: str,
    secret_key: Optional[str] = None
) -> Optional[Dict[str, FileEntry]]:
    """
    Load manifest from file.

    Args:
        baseline_file: Baseline file path
        secret_key: Optional HMAC key for verification

    Returns:
        Dictionary of FileEntry or None on failure
    """
    logger = get_logger("fim.manifest")

    if secret_key:
        if not verify_baseline_integrity(baseline_file, secret_key):
            logger.error("Baseline integrity verification failed - possible tampering")
            return None

    data = read_json(baseline_file)
    if not data:
        logger.error(f"Failed to load baseline from {baseline_file}")
        return None

    manifest = {}
    for path, entry_data in data.items():
        try:
            manifest[path] = FileEntry(**entry_data)
        except (TypeError, ValueError) as e:
            logger.warning(f"Invalid entry for {path}: {e}")

    logger.info(f"Loaded baseline from {baseline_file} ({len(manifest)} files)")
    return manifest


def create_baseline(
    target_dir: str,
    output_file: str,
    algorithm: str = "sha256",
    chunk_size: int = 4096,
    exclude_patterns: Optional[list] = None,
    secret_key: Optional[str] = None
) -> bool:
    """
    Create baseline for a directory.

    Args:
        target_dir: Directory to baseline
        output_file: Output baseline file
        algorithm: Hash algorithm
        chunk_size: Read chunk size
        exclude_patterns: Patterns to exclude
        secret_key: Optional HMAC key

    Returns:
        True if successful
    """
    engine = PyHashEngine(target_dir, algorithm, chunk_size, exclude_patterns)
    engine.collect()
    return save_manifest(engine, output_file, secret_key)


def audit_directory(
    target_dir: str,
    baseline_file: str,
    algorithm: str = "sha256",
    chunk_size: int = 4096,
    exclude_patterns: Optional[list] = None,
    secret_key: Optional[str] = None
) -> Optional[Dict]:
    """
    Audit a directory against baseline.

    Args:
        target_dir: Directory to audit
        baseline_file: Baseline file
        algorithm: Hash algorithm
        chunk_size: Read chunk size
        exclude_patterns: Patterns to exclude
        secret_key: Optional HMAC key

    Returns:
        Dictionary with audit results or None on failure
    """
    logger = get_logger("fim.audit")

    # Load baseline
    baseline = load_manifest(baseline_file, secret_key)
    if baseline is None:
        return None

    # Scan current state
    engine = PyHashEngine(target_dir, algorithm, chunk_size, exclude_patterns)
    current_scan = engine.collect()

    # Verify integrity
    from .audit import verify_integrity
    changes = verify_integrity(baseline, current_scan, secret_key)

    # Generate stats
    baseline_stats = {
        "files": len(baseline),
        "total_size": sum(e.size for e in baseline.values())
    }
    current_stats = {
        "files": len(current_scan),
        "total_size": sum(e.size for e in current_scan.values())
    }

    return {
        "changes": changes,
        "baseline_stats": baseline_stats,
        "current_stats": current_stats
    }


def run_fim_baseline(config: dict) -> None:
    """Run FIM baseline creation"""
    from ...logging import setup_logging

    logger = setup_logging(config)
    fim_config = config.get("fim", {})

    target_dir = fim_config.get("target_dir", ".")
    baseline_file = fim_config.get("baseline_file", "baseline.json")
    algorithm = fim_config.get("algorithm", "sha256")
    chunk_size = fim_config.get("chunk_size", 4096)
    exclude_patterns = fim_config.get("exclude_patterns", [])
    secret_key = fim_config.get("secret_key", "")

    logger.info("Creating FIM baseline", target=target_dir, output=baseline_file)

    if create_baseline(target_dir, baseline_file, algorithm, chunk_size, exclude_patterns, secret_key or None):
        logger.info("Baseline created successfully")
    else:
        logger.error("Failed to create baseline")


def run_fim_audit(config: dict) -> None:
    """Run FIM audit"""
    from ...logging import setup_logging
    from .audit import report_findings, generate_report

    logger = setup_logging(config)
    fim_config = config.get("fim", {})

    target_dir = fim_config.get("target_dir", ".")
    baseline_file = fim_config.get("baseline_file", "baseline.json")
    algorithm = fim_config.get("algorithm", "sha256")
    chunk_size = fim_config.get("chunk_size", 4096)
    exclude_patterns = fim_config.get("exclude_patterns", [])
    secret_key = fim_config.get("secret_key", "")

    logger.info("Starting FIM audit", target=target_dir, baseline=baseline_file)

    result = audit_directory(
        target_dir, baseline_file, algorithm, chunk_size,
        exclude_patterns, secret_key or None
    )

    if result is None:
        logger.error("Audit failed")
        return

    changes = result["changes"]
    report_findings(changes)

    # Generate detailed report
    report_file = f"fim_report_{int(__import__('time').time())}.json"
    generate_report(changes, result["baseline_stats"], result["current_stats"], report_file)
    logger.info(f"Detailed report saved to {report_file}")