"""FIM Audit - Integrity verification and reporting"""

import hmac
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .engine import PyHashEngine, FileEntry
from ...utils.hashing import verify_hmac, generate_hmac
from ...logging import get_logger


@dataclass
class IntegrityChanges:
    """Integrity check results"""
    added: List[str]
    modified: List[str]
    deleted: List[str]

    def has_changes(self) -> bool:
        return bool(self.added or self.modified or self.deleted)

    def total_changes(self) -> int:
        return len(self.added) + len(self.modified) + len(self.deleted)


def verify_integrity(
    baseline: Dict[str, FileEntry],
    current_scan: Dict[str, FileEntry],
    secret_key: Optional[str] = None
) -> IntegrityChanges:
    """
    Compare baseline against current scan.

    Args:
        baseline: Baseline manifest
        current_scan: Current scan results
        secret_key: Optional HMAC key for baseline verification

    Returns:
        IntegrityChanges with detected differences
    """
    changes = IntegrityChanges(added=[], modified=[], deleted=[])

    # Check for deleted and modified
    for rel_path, baseline_entry in baseline.items():
        if rel_path not in current_scan:
            changes.deleted.append(rel_path)
        else:
            current_entry = current_scan[rel_path]
            if current_entry.hash != baseline_entry.hash:
                changes.modified.append(rel_path)

    # Check for added files
    for rel_path in current_scan:
        if rel_path not in baseline:
            changes.added.append(rel_path)

    return changes


def verify_baseline_integrity(
    baseline_file: str,
    secret_key: str
) -> bool:
    """
    Verify baseline file hasn't been tampered with using HMAC.

    Args:
        baseline_file: Path to baseline JSON
        secret_key: HMAC secret key

    Returns:
        True if baseline is intact
    """
    try:
        with open(baseline_file, 'rb') as f:
            data = f.read()

        # Last 64 chars are the HMAC (sha256 = 64 hex chars)
        if len(data) < 65:
            return False

        content = data[:-64]
        stored_hmac = data[-64:].decode()

        return verify_hmac(content, stored_hmac, secret_key.encode())
    except (OSError, ValueError, UnicodeDecodeError):
        return False


def sign_baseline(baseline_file: str, secret_key: str) -> bool:
    """Add HMAC signature to baseline file"""
    try:
        with open(baseline_file, 'rb') as f:
            content = f.read()

        signature = generate_hmac(content, secret_key.encode())
        with open(baseline_file, 'wb') as f:
            f.write(content + signature.encode())
        return True
    except (OSError, IOError):
        return False


def report_findings(changes: IntegrityChanges, verbose: bool = False) -> None:
    """Print integrity check results"""
    logger = get_logger("fim.audit")

    if not changes.has_changes():
        logger.info("Integrity verified: No changes detected")
        print("\n[✓] Integrity Verified: No changes detected.")
        return

    logger.warning(
        "Integrity breach detected",
        added=len(changes.added),
        modified=len(changes.modified),
        deleted=len(changes.deleted)
    )

    print(f"\n[!] ALERT: Integrity Breach Detected! ({changes.total_changes()} changes)")

    if changes.added:
        print(f"  ADDED ({len(changes.added)}):")
        for f in changes.added:
            print(f"    + {f}")

    if changes.modified:
        print(f"  MODIFIED ({len(changes.modified)}):")
        for f in changes.modified:
            print(f"    ~ {f}")

    if changes.deleted:
        print(f"  DELETED ({len(changes.deleted)}):")
        for f in changes.deleted:
            print(f"    - {f}")


def generate_report(
    changes: IntegrityChanges,
    baseline_stats: Dict,
    current_stats: Dict,
    output_file: Optional[str] = None
) -> str:
    """Generate detailed JSON report"""
    import json
    from datetime import datetime

    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_changes": changes.total_changes(),
            "added": len(changes.added),
            "modified": len(changes.modified),
            "deleted": len(changes.deleted)
        },
        "changes": {
            "added": changes.added,
            "modified": changes.modified,
            "deleted": changes.deleted
        },
        "baseline": baseline_stats,
        "current": current_stats
    }

    json_report = json.dumps(report, indent=2)

    if output_file:
        Path(output_file).write_text(json_report)

    return json_report