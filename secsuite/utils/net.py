"""Network utilities"""

import socket
import ssl
from contextlib import contextmanager
from typing import Generator, Optional, Tuple

DEFAULT_BACKLOG = 5
DEFAULT_TIMEOUT = 30
DEFAULT_BUFFER_SIZE = 4096


@contextmanager
def create_listener(
    port: int,
    address: str = "0.0.0.0",
    backlog: int = DEFAULT_BACKLOG,
    reuse_addr: bool = True,
    timeout: float = DEFAULT_TIMEOUT
) -> Generator[socket.socket, None, None]:
    """
    Create a TCP listener socket.

    Args:
        port: Port to bind to
        address: Address to bind to
        backlog: Listen backlog
        reuse_addr: Set SO_REUSEADDR
        timeout: Socket timeout

    Yields:
        Listening socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if reuse_addr:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.bind((address, port))
        sock.listen(backlog)
        yield sock
    finally:
        sock.close()


@contextmanager
def create_connection(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    use_ssl: bool = False,
    ssl_context: Optional[ssl.SSLContext] = None
) -> Generator[socket.socket, None, None]:
    """
    Create a TCP connection.

    Args:
        host: Target host
        port: Target port
        timeout: Connection timeout
        use_ssl: Use SSL/TLS
        ssl_context: Custom SSL context

    Yields:
        Connected socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        if use_ssl:
            ctx = ssl_context or ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        yield sock
    finally:
        sock.close()


def recv_exact(sock: socket.socket, length: int, timeout: float = None) -> bytes:
    """
    Receive exactly N bytes.

    Args:
        sock: Socket to read from
        length: Number of bytes to receive
        timeout: Optional timeout override

    Returns:
        Received bytes

    Raises:
        ConnectionError: If connection closed prematurely
        socket.timeout: If timeout occurs
    """
    if timeout is not None:
        sock.settimeout(timeout)

    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data.extend(chunk)
    return bytes(data)


def recv_hex(
    sock: socket.socket,
    max_length: int = DEFAULT_BUFFER_SIZE,
    timeout: float = None
) -> Optional[str]:
    """
    Receive data and return as hex string.

    Args:
        sock: Socket to read from
        max_length: Maximum bytes to read
        timeout: Optional timeout override

    Returns:
        Hex string or None on error/timeout
    """
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        data = sock.recv(max_length)
        if data:
            return data.hex()
    except (socket.timeout, ConnectionError, OSError):
        pass
    return None


def send_hex(
    sock: socket.socket,
    hex_data: str,
    timeout: float = None
) -> bool:
    """
    Send hex string as bytes.

    Args:
        sock: Socket to write to
        hex_data: Hex string to send
        timeout: Optional timeout override

    Returns:
        True if sent successfully
    """
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        data = bytes.fromhex(hex_data)
        sock.sendall(data)
        return True
    except (ValueError, socket.timeout, ConnectionError, OSError):
        return False


def send_all(sock: socket.socket, data: bytes, timeout: float = None) -> bool:
    """Send all bytes"""
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        sock.sendall(data)
        return True
    except (socket.timeout, ConnectionError, OSError):
        return False


def get_local_ip() -> str:
    """Get local IP address"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def parse_address(address: str) -> Tuple[str, int]:
    """Parse 'host:port' string"""
    if ':' in address:
        host, port_str = address.rsplit(':', 1)
        return host, int(port_str)
    return address, 0


def format_address(host: str, port: int) -> str:
    """Format host:port string"""
    return f"{host}:{port}"