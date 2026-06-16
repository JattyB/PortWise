"""Native SMB negotiation probe.

Sends a single SMB ``NEGOTIATE`` request and parses the response. This is the
protocol handshake every SMB client performs *before* any authentication or
tree connect — no credentials are sent, no shares are touched, nothing is
written. It is safe and read-only.

It detects two things that previously depended on nmap NSE scripts
(``smb-security-mode`` / ``smb2-security-mode``) that are not in nmap's default
script set:

* whether the legacy **SMBv1** dialect is still negotiable, and
* the **message-signing** posture (required / enabled-not-required / disabled).
"""
from __future__ import annotations

import socket
import struct

# SMBv1 COM_NEGOTIATE with a dialect list including the SMB2 wildcard. A modern
# server with SMBv1 disabled will answer with an SMB2 NEGOTIATE response; a
# server that still speaks SMBv1 answers with an SMBv1 response.
_SMB1_NEGOTIATE = bytes.fromhex(
    "ff534d42"  # "\xffSMB"
    "72"        # COM_NEGOTIATE
    "0000000000"
    "18"
    "5301"
    "0000000000000000000000000000000000000000"
    "0000"
    "0000"
)


def _smb1_dialects() -> bytes:
    dialects = [b"NT LM 0.12", b"SMB 2.002", b"SMB 2.???"]
    body = bytearray()
    for d in dialects:
        body += b"\x02" + d + b"\x00"
    return bytes([0x00]) + struct.pack("<H", len(body)) + bytes(body)


def _netbios_wrap(message: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(message))[1:] + message


def _recv_netbios(sock: socket.socket, timeout: float) -> bytes | None:
    sock.settimeout(timeout)
    header = bytearray()
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header.extend(chunk)
    length = struct.unpack(">I", b"\x00" + bytes(header[1:4]))[0]
    body = bytearray()
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            break
        body.extend(chunk)
    return bytes(body)


def probe_smb(host: str, port: int = 445, timeout: float = 5.0) -> dict | None:
    """Return {'smbv1': bool, 'signing': str, 'dialect': str} or None on failure.

    ``signing`` is one of: ``required``, ``not_required``, ``disabled``, ``unknown``.
    """
    message = _SMB1_NEGOTIATE + _smb1_dialects()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.sendall(_netbios_wrap(message))
            response = _recv_netbios(sock, timeout)
    except (OSError, socket.timeout, struct.error):
        return None

    if not response or len(response) < 5:
        return None

    proto = response[:4]
    if proto == b"\xfeSMB":
        return _parse_smb2_negotiate(response)
    if proto == b"\xffSMB":
        return _parse_smb1_negotiate(response)
    return None


def _parse_smb2_negotiate(response: bytes) -> dict:
    result: dict[str, object] = {"smbv1": False, "signing": "unknown", "dialect": "smb2+"}
    # SMB2 header is 64 bytes; negotiate response body follows.
    body = response[64:]
    if len(body) >= 6:
        # StructureSize(2), SecurityMode(2), DialectRevision(2)
        security_mode = struct.unpack_from("<H", body, 2)[0]
        dialect = struct.unpack_from("<H", body, 4)[0]
        result["dialect"] = f"0x{dialect:04x}"
        if security_mode & 0x0002:
            result["signing"] = "required"
        elif security_mode & 0x0001:
            result["signing"] = "not_required"
        else:
            result["signing"] = "disabled"
    return result


def _parse_smb1_negotiate(response: bytes) -> dict:
    result: dict[str, object] = {"smbv1": True, "signing": "unknown", "dialect": "NT LM 0.12"}
    # SMBv1 header is 32 bytes. Negotiate response: WordCount byte then params.
    if len(response) < 39:
        return result
    word_count = response[32]
    if word_count >= 17:
        # Param block: WordCount(1)@32, DialectIndex(2)@33-34, SecurityMode(1)@35.
        security_mode = response[35]
        signing_enabled = bool(security_mode & 0x04)
        signing_required = bool(security_mode & 0x08)
        if signing_required:
            result["signing"] = "required"
        elif signing_enabled:
            result["signing"] = "not_required"
        else:
            result["signing"] = "disabled"
    return result
