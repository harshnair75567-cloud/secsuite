#!/usr/bin/env python3
"""Test runner for secsuite"""

import sys
import subprocess
from pathlib import Path


def run_tests(coverage: bool = False, verbose: bool = True) -> int:
    """Run pytest with appropriate options"""
    project_root = Path(__file__).parent

    cmd = [sys.executable, "-m", "pytest"]

    if verbose:
        cmd.append("-v")

    if coverage:
        cmd.extend(["--cov=secsuite", "--cov-report=term-missing"])

    cmd.append(str(project_root / "secsuite" / "tests"))

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=project_root)
    return result.returncode


def run_specific_test(test_path: str, verbose: bool = True) -> int:
    """Run a specific test file"""
    project_root = Path(__file__).parent

    cmd = [sys.executable, "-m", "pytest"]
    if verbose:
        cmd.append("-v")
    cmd.append(str(project_root / test_path))

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=project_root)
    return result.returncode


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run secsuite tests")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    parser.add_argument("test", nargs="?", help="Specific test file to run")

    args = parser.parse_args()

    if args.test:
        sys.exit(run_specific_test(args.test, not args.quiet))
    else:
        sys.exit(run_tests(args.coverage, not args.quiet))