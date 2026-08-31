"""Process management utilities"""

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set,Union


@dataclass
class ProcessInfo:
    """Process information"""
    pid: int
    name: str
    tty: str
    cmdline: List[str]
    user: str


def get_pids_for_file(file_path: Union[str, Path]) -> List[int]:
    """
    Get PIDs of processes that have a file open.

    Args:
        file_path: Path to file

    Returns:
        List of PIDs
    """
    try:
        result = subprocess.run(
            ["lsof", "-t", str(file_path)],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return [int(pid.strip()) for pid in result.stdout.strip().split('\n') if pid.strip()]
    except (subprocess.SubprocessError, ValueError, FileNotFoundError):
        pass
    return []


def get_process_info(pid: int) -> Optional[ProcessInfo]:
    """
    Get detailed process information.

    Args:
        pid: Process ID

    Returns:
        ProcessInfo or None if not found
    """
    try:
        # Get process name
        name_result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=3
        )
        name = name_result.stdout.strip() if name_result.returncode == 0 else "unknown"

        # Get TTY
        tty_result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "tty="],
            capture_output=True,
            text=True,
            timeout=3
        )
        tty = tty_result.stdout.strip() if tty_result.returncode == 0 else "?"

        # Get cmdline
        cmdline_result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "args="],
            capture_output=True,
            text=True,
            timeout=3
        )
        cmdline = cmdline_result.stdout.strip().split() if cmdline_result.returncode == 0 else []

        # Get user
        user_result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "user="],
            capture_output=True,
            text=True,
            timeout=3
        )
        user = user_result.stdout.strip() if user_result.returncode == 0 else "unknown"

        return ProcessInfo(pid=pid, name=name, tty=tty, cmdline=cmdline, user=user)

    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def kill_process(pid: int, signal: int = 9) -> bool:
    """
    Kill a process.

    Args:
        pid: Process ID
        signal: Signal to send (default SIGKILL=9)

    Returns:
        True if successful
    """
    try:
        os.kill(pid, signal)
        return True
    except (OSError, ProcessLookupError):
        return False


def get_current_tty() -> str:
    """Get current terminal TTY"""
    try:
        result = subprocess.run(
            ["tty"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            return result.stdout.strip().replace("/dev/", "")
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return "unknown"


def is_process_safe(
    pid: int,
    safe_tools: Set[str],
    allowed_tty: str = None
) -> bool:
    """
    Check if a process is considered safe.

    Args:
        pid: Process ID
        safe_tools: Set of safe tool names
        allowed_tty: Allowed TTY (defaults to current)

    Returns:
        True if process is safe
    """
    if allowed_tty is None:
        allowed_tty = get_current_tty()

    info = get_process_info(pid)
    if not info:
        return False

    return info.name in safe_tools and info.tty == allowed_tty


def find_processes_by_name(name: str) -> List[ProcessInfo]:
    """Find all processes with given name"""
    try:
        result = subprocess.run(
            ["pgrep", "-f", name],
            capture_output=True,
            text=True,
            timeout=3
        )
        if result.returncode == 0:
            pids = [int(p.strip()) for p in result.stdout.strip().split('\n') if p.strip()]
            return [get_process_info(pid) for pid in pids if get_process_info(pid)]
    except (subprocess.SubprocessError, ValueError, FileNotFoundError):
        pass
    return []


def get_all_processes() -> List[ProcessInfo]:
    """Get all running processes"""
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,comm,tty,args,user"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            processes = []
            for line in lines:
                parts = line.strip().split(None, 4)
                if len(parts) >= 5:
                    processes.append(ProcessInfo(
                        pid=int(parts[0]),
                        name=parts[1],
                        tty=parts[2],
                        cmdline=parts[3].split(),
                        user=parts[4]
                    ))
            return processes
    except (subprocess.SubprocessError, ValueError, FileNotFoundError):
        pass
    return []


Union = __import__('typing').Union
