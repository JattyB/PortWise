"""Native SSH algorithm enumeration.

Performs only the SSH protocol version exchange (RFC 4253 §4.2) and reads the
server's SSH_MSG_KEXINIT (RFC 4253 §7.1). This is exactly what every SSH client
does *before* authentication — no credentials are ever sent, nothing is written
to the service beyond our own identification string and a KEXINIT, and the
socket is closed immediately. It is safe and read-only.

This exists so PortWise can report weak KEX/cipher/MAC/host-key algorithms even
when nmap's ``ssh2-enum-algos`` script was not run (it is *not* part of nmap's
default ``-sC`` script set, which is why algo findings were previously missing).
"""
from __future__ import annotations

import socket
import struct

_CLIENT_ID = b"SSH-2.0-PortWise_SafeProbe\r\n"
_SSH_MSG_KEXINIT = 20

_NAME_LIST_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _read_banner(sock: socket.socket, cap: int = 512) -> bytes:
    """Read the server identification line(s) up to the first SSH-2/1 banner."""
    data = bytearray()
    while len(data) < cap:
        chunk = sock.recv(256)
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk and data.startswith(b"SSH-"):
            break
        if b"\n" in chunk and b"SSH-" in data:
            break
    return bytes(data)


def enumerate_ssh_algorithms(host: str, port: int = 22, timeout: float = 5.0) -> dict | None:
    """Return a dict with parsed SSH algorithm name-lists, or None on failure.

    Keys returned (each a list[str]): ``kex``, ``hostkey``, ``encryption``
    (client->server), ``encryption_s2c``, ``mac`` (c2s), ``mac_s2c``,
    plus ``banner`` (str).
    """
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = _read_banner(sock)
            if not banner.startswith(b"SSH-"):
                return None
            banner_line = banner.split(b"\r\n")[0].split(b"\n")[0].decode("latin-1", "replace")

            # Send our identification string (required before KEXINIT exchange).
            sock.sendall(_CLIENT_ID)

            payload = _read_kexinit_payload(sock, timeout)
            if payload is None:
                return {"banner": banner_line}

            parsed = _parse_kexinit(payload)
            if parsed is None:
                return {"banner": banner_line}
            parsed["banner"] = banner_line
            return parsed
    except (OSError, socket.timeout, struct.error):
        return None


def _read_kexinit_payload(sock: socket.socket, timeout: float) -> bytes | None:
    """Read SSH binary packets until we get a KEXINIT, returning its payload."""
    sock.settimeout(timeout)
    # The server may have already sent KEXINIT right after its banner; read a
    # generous buffer and frame packets from it.
    buffered = bytearray()

    def _ensure(n: int) -> bool:
        while len(buffered) < n:
            chunk = sock.recv(4096)
            if not chunk:
                return False
            buffered.extend(chunk)
        return True

    for _ in range(4):  # bounded: at most a few packets before KEXINIT
        if not _ensure(4):
            return None
        packet_len = struct.unpack(">I", bytes(buffered[:4]))[0]
        if packet_len <= 0 or packet_len > 35000:
            return None
        if not _ensure(4 + packet_len):
            return None
        packet = bytes(buffered[4:4 + packet_len])
        del buffered[:4 + packet_len]
        if not packet:
            continue
        padding_len = packet[0]
        payload = packet[1:len(packet) - padding_len]
        if payload and payload[0] == _SSH_MSG_KEXINIT:
            return payload
    return None


def _parse_kexinit(payload: bytes) -> dict | None:
    # payload: byte msg=20, 16 bytes cookie, then 10 name-lists, then flags.
    if len(payload) < 17 or payload[0] != _SSH_MSG_KEXINIT:
        return None
    offset = 17  # 1 (msg) + 16 (cookie)
    lists: dict[str, list[str]] = {}
    for field in _NAME_LIST_FIELDS:
        if offset + 4 > len(payload):
            return None
        (length,) = struct.unpack(">I", payload[offset:offset + 4])
        offset += 4
        if offset + length > len(payload):
            return None
        raw = payload[offset:offset + length].decode("latin-1", "replace")
        offset += length
        lists[field] = [a for a in raw.split(",") if a]
    return {
        "kex": lists["kex_algorithms"],
        "hostkey": lists["server_host_key_algorithms"],
        "encryption": lists["encryption_algorithms_client_to_server"],
        "encryption_s2c": lists["encryption_algorithms_server_to_client"],
        "mac": lists["mac_algorithms_client_to_server"],
        "mac_s2c": lists["mac_algorithms_server_to_client"],
    }
