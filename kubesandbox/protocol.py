"""Kubernetes wire protocol for micro-VM sandboxes: kubeconfig, REST, and the exec streams.

Only what provisioning, probing and command execution need. Control-plane calls are plain REST;
command output rides the WebSocket exec protocol (``v4.channel.k8s.io``) with no channel
multiplexer library and no kubectl binary in the way.

Also serves the SSH backend: a micro-VM has no sshd, so ``stream_and_serve`` runs the sandbox's
commands in place and exposes them on a unix socket with a hand-built ``ssh-proxy`` dialect (the
same one zstd/socat use). Hermes' own ssh client and ``scp`` cannot speak that dialect, so SSH mode
is for harnesses and transports that can — see the plugin README.
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

__all__ = ["ApiError", "KubeClient", "PodTarget", "resolve_kubeconfig"]

CH_STDIN, CH_STDOUT, CH_STDERR, CH_ERROR, CH_RESIZE = 0, 1, 2, 3, 4
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class ApiError(RuntimeError):
    """Non-2xx answer from the API server, or a transport failure that makes the call moot."""

    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}" if status else message)
        self.status = status
        self.message = message

    @property
    def not_found(self) -> bool:
        return self.status == 404


# --- kubeconfig --------------------------------------------------------------------------------


@dataclass
class KubeClient:
    server: str
    ca_pem: bytes | None = None
    token: str | None = None
    token_file: str | None = None
    insecure: bool = False

    # -- transport ------------------------------------------------------------
    @property
    def _hostport(self) -> tuple[str, int]:
        authority = self.server.split("//", 1)[-1].split("/", 1)[0]
        host, _, port = authority.rpartition(":")
        if not host:
            return authority.strip("[]"), 443
        return host.strip("[]"), int(port)

    @property
    def _prefix(self) -> str:
        rest = self.server.split("//", 1)[-1]
        return "/" + rest.split("/", 1)[1] if "/" in rest else ""

    def _headers(self) -> dict[str, str]:
        token = self.token
        if not token and self.token_file:
            try:
                with open(self.token_file, encoding="utf-8") as fh:
                    token = fh.read().strip()
            except OSError:
                token = None
        return {"Authorization": f"Bearer {token}"} if token else {}

    def _ssl(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif self.ca_pem:
            ctx.load_verify_locations(cadata=self.ca_pem.decode())
        return ctx

    def connect(self, timeout: float) -> ssl.SSLSocket | socket.socket:
        host, port = self._hostport
        raw = socket.create_connection((host, port), timeout=timeout)
        if self.server.startswith("http://"):
            return raw
        return self._ssl().wrap_socket(raw, server_hostname=host)

    def _exchange(self, method: str, path: str, *, body: dict | None = None,
                  extra: list[str] | None = None, timeout: float = 30.0,
                  headers_out: list[str] | None = None) -> tuple[int, dict[str, str], bytes, socket.socket]:
        """Send one request and read the whole answer, or hand back the socket on a 101 upgrade."""
        sock = self.connect(timeout)
        host, port = self._hostport
        payload = b"" if body is None else json.dumps(body).encode()
        lines = [f"{method} {self._prefix}{path} HTTP/1.1", f"Host: {host}:{port}"]

        if extra:
            # Upgrade request: the header block must stay exactly Upgrade / Connection / subprotocol
            # versions before the key. Length, content type, accept, ``Origin`` or a different order
            # all make the API server answer 406 or 400 instead of negotiating.
            lines.extend(extra)
        else:
            lines.append(f"Content-Length: {len(payload)}")
            if body is not None:
                lines.append("Content-Type: application/json")
            else:
                lines.append("Accept: application/json")
            lines.append("Connection: close")
        lines.extend(f"{k}: {v}" for k, v in self._headers().items())
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + payload)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                sock.close()
                raise ApiError(0, f"API server {self.server} closed the connection")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        head_text = head.decode("iso-8859-1")
        status_line = head_text.split("\r\n", 1)[0]
        try:
            status = int(status_line.split()[1])
        except (IndexError, ValueError) as exc:
            sock.close()
            raise ApiError(0, f"malformed status line from {self.server}: {status_line!r}") from exc
        headers = {}
        for line in head_text.split("\r\n")[1:]:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
        if status == 101:
            return status, headers, rest, sock
        if headers.get("transfer-encoding", "").lower() == "chunked":
            # Accumulate the raw stream, then de-chunk once: decoding incrementally discarded the
            # partial chunk tail every round, and the stray bytes parsed as a bogus chunk size.
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                rest += chunk
            rest = _dechunk(rest)
        else:
            length = headers.get("content-length")
            expected = int(length) if length is not None else None
            while expected is None or len(rest) < expected:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                rest += chunk
            if expected is not None:
                rest = rest[:expected]
        sock.close()
        return status, headers, rest, sock

    # -- REST -----------------------------------------------------------------
    def call(self, method: str, path: str, *, body: dict | None = None, timeout: float = 30.0) -> dict:
        status, _, data, _ = self._exchange(method, path, body=body, timeout=timeout)
        text = data.decode("utf-8", errors="replace")
        if status >= 300:
            raise ApiError(status, _api_message(text))
        return json.loads(text) if text.strip() else {}

    def version(self, timeout: float = 5.0) -> str:
        return str(self.call("GET", "/version", timeout=timeout).get("gitVersion", ""))

    # -- exec -----------------------------------------------------------------
    def exec_ws(self, target: "PodTarget", command: list[str], *, stdin_data: bytes | None = None,
                timeout: float = 120.0, tty: bool = False) -> tuple[bytes, int]:
        """Run *command* in a pod; return ``(merged stdout+stderr, exit_code)``."""
        from urllib.parse import quote
        query = [f"container={quote(target.container)}"] if target.container else []
        query += [f"command={quote(c)}" for c in command]
        query += [f"stdin={'true' if stdin_data is not None else 'false'}", "stdout=true", "stderr=true",
                  f"tty={'true' if tty else 'false'}"]
        path = f"/api/v1/namespaces/{target.namespace}/pods/{target.pod}/exec?" + "&".join(query)
        status, headers, rest, sock = self._exchange(
            "GET", path,
            extra=["Upgrade: websocket",
                   "Connection: Upgrade",
                   "Sec-WebSocket-Version: 13",
                   # Negotiate via Sec-WebSocket-Protocol (what the apiserver's websocket
                   # dialer reads); v5 first so we get the per-channel CLOSE signal.
                   "Sec-WebSocket-Protocol: v5.channel.k8s.io,v4.channel.k8s.io,v3.channel.k8s.io,v2.channel.k8s.io,v1.channel.k8s.io",
                   "X-Stream-Protocol-Version: v5.channel.k8s.io,v4.channel.k8s.io",
                   f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}"],
            timeout=min(timeout, 30.0))
        if status != 101:
            sock.close()
            raise ApiError(status, _api_message(rest.decode("utf-8", errors="replace")))
        ws = _WebSocket(sock, rest)
        try:
            return self._exec_roundtrip(ws, stdin_data, timeout)
        finally:
            ws.close()

    @staticmethod
    def _exec_roundtrip(ws: "_WebSocket", stdin_data: bytes | None, timeout: float) -> tuple[bytes, int]:
        if stdin_data:
            ws.send_binary(b"\x00" + stdin_data)
        # End stdin with the v5 CLOSE signal: one binary frame whose payload is
        # [StreamClose(0xFF), channel(0)]. The old "zero byte + unframed close-write"
        # never signalled EOF on a negotiated websocket subprotocol, so any command
        # reading stdin (e.g. the code-execution tool's base64 file ship) hung until
        # the 30s timeout. On a v4-negotiated server the CLOSE frame is discarded as
        # an unknown stream id, so v5 (k8s >= 1.31) is required for stdin EOF.
        ws.send_binary(b"\xff\x00")
        output, exit_code = ws.drain(timeout)
        return output, (0 if exit_code is None else exit_code)

    def exec_stream(self, target: "PodTarget", command: list[str], *, tty: bool = False):
        """Open a *persistent* exec stream: a ``_WebSocket`` whose stdin stays open for the caller.

        Used by the SSH transport (an sshd session is a long-lived bidirectional stream) and by any
        consumer that needs to keep writing after the first reply.
        """
        from urllib.parse import quote
        query = [f"container={quote(target.container)}"] if target.container else []
        query += [f"command={quote(c)}" for c in command]
        query += ["stdin=true", "stdout=true", "stderr=true", f"tty={'true' if tty else 'false'}"]
        path = f"/api/v1/namespaces/{target.namespace}/pods/{target.pod}/exec?" + "&".join(query)
        status, headers, rest, sock = self._exchange(
            "GET", path,
            extra=["Upgrade: websocket",
                   "Connection: Upgrade",
                   "Sec-WebSocket-Version: 13",
                   "Sec-WebSocket-Protocol: v5.channel.k8s.io,v4.channel.k8s.io,v3.channel.k8s.io,v2.channel.k8s.io,v1.channel.k8s.io",
                   "X-Stream-Protocol-Version: v5.channel.k8s.io,v4.channel.k8s.io",
                   f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}"],
            timeout=30.0)
        if status != 101:
            sock.close()
            raise ApiError(status, _api_message(rest.decode("utf-8", errors="replace")))
        return _WebSocket(sock, rest)



_EXIT_RE = re.compile(r"exit code:?\s+(\d+)\s*$", re.MULTILINE)


def _exit_from_error(message: str) -> int | None:
    """The command's exit status from the error channel ("... exit code 7"), else None.

    The remotecommand handler reports a non-zero exit this way and may still close the stream with a
    normal close frame, so this is the authoritative status when it is present.
    """
    matches = _EXIT_RE.findall(message)
    return int(matches[-1]) if matches else None


def _api_message(text: str) -> str:
    try:
        return (json.loads(text).get("message") or text).strip()
    except ValueError:
        return text.strip()[:400]


def _dechunk(data: bytes) -> bytes:
    """Decode a complete chunked body. A truncated tail is dropped rather than raising."""
    out, i = bytearray(), 0
    while True:
        eol = data.find(b"\r\n", i)
        if eol == -1:
            return bytes(out)
        size_text = data[i:eol].split(b";")[0].strip()
        try:
            size = int(size_text or b"0", 16)
        except ValueError:
            return bytes(out)
        if size == 0 or len(data) < eol + 2 + size + 2:
            return bytes(out)
        out += data[eol + 2:eol + 2 + size]
        i = eol + 2 + size + 2


class _WebSocket:
    """Client framing over an already-upgraded socket, masked as the spec requires."""

    def __init__(self, sock, prefetched: bytes = b""):
        self.sock = sock
        self.stream_cut_short = False  # True when the socket died before the close channel
        self.buf = bytearray(prefetched)
        self.write_lock = threading.Lock()
        self.closed = False

    def _frame(self, opcode: int, payload: bytes) -> bytes:
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        return header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    def _send(self, opcode: int, payload: bytes) -> None:
        with self.write_lock:
            self.sock.sendall(self._frame(opcode, payload))

    def send_binary(self, payload: bytes) -> None:
        self._send(0x2, payload)

    def send_stdin(self, data: bytes) -> None:
        """One stdin frame on a *persistent* stream (``exec_stream``): the socket stays open."""
        self._send(0x2, b"\x00" + data)

    def send_stdin_eof(self) -> None:
        """End stdin on a persistent stream: the v5 CLOSE frame [StreamClose, channel 0]."""
        self._send(0x2, b"\xff\x00")

    def recv_channel(self, timeout: float | None = None):
        """Next ``(channel, data)`` frame, or ``None`` on close/timeout. Blocks for at most *timeout*."""
        while True:
            effective = time.monotonic() + timeout if timeout is not None else time.monotonic() + 3600.0
            if not self._fill(2, effective):
                return None
            b0, b1 = self.buf[0], self.buf[1]
            length, offset = b1 & 0x7F, 2
            if length == 126:
                if not self._fill(4, effective):
                    return None
                length, offset = struct.unpack(">H", bytes(self.buf[2:4]))[0], 4
            elif length == 127:
                if not self._fill(10, effective):
                    return None
                length, offset = struct.unpack(">Q", bytes(self.buf[2:10]))[0], 10
            masked = bool(b1 & 0x80)
            total = offset + (4 if masked else 0) + length
            if not self._fill(total, effective):
                return None
            frame = bytes(self.buf[offset:total])
            del self.buf[:total]
            payload = frame[4:] if masked else frame
            if masked:
                key = frame[:4]
                payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
            opcode = b0 & 0x0F
            if opcode == 0x8:
                return None
            if opcode == 0x9:
                self._send(0xA, payload)
                continue
            if opcode not in (0x1, 0x2) or not payload:
                continue
            return payload[0], payload[1:]

    def _fill(self, need: int, deadline: float) -> bool:
        while len(self.buf) < need:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except (TimeoutError, socket.timeout):
                return False
            except OSError:
                self.stream_cut_short = True
                return False
            if not chunk:
                self.stream_cut_short = True
                return False
            self.buf += chunk
        return True

    def drain(self, timeout: float) -> tuple[bytes, int | None]:
        """Until the stream closes: ``(output, exit_code)``. ``None`` = timed out or cut short.

        With the v4 protocol the server closes the streams *before* it writes the close frame, so
        a stream that simply ends is not a timeout: a short read after the close channel only means
        the command's status was 0.
        """
        out = bytearray()
        exit_code = None
        deadline = time.monotonic() + timeout
        while True:
            if not self._fill(2, deadline):
                if self.stream_cut_short:
                    return bytes(out), exit_code  # socket closed cleanly without a close frame
                return bytes(out), 124  # deadline hit
            b0, b1 = self.buf[0], self.buf[1]
            length, offset = b1 & 0x7F, 2
            if length == 126:
                if not self._fill(4, deadline):
                    return bytes(out), exit_code
                length, offset = struct.unpack(">H", bytes(self.buf[2:4]))[0], 4
            elif length == 127:
                if not self._fill(10, deadline):
                    return bytes(out), exit_code
                length, offset = struct.unpack(">Q", bytes(self.buf[2:10]))[0], 10
            masked = bool(b1 & 0x80)
            total = offset + (4 if masked else 0) + length
            if not self._fill(total, deadline):
                return bytes(out), exit_code
            frame = bytes(self.buf[offset:offset + (4 if masked else 0) + length])
            del self.buf[:total]
            if masked:
                key, payload = frame[:4], frame[4:]
                payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
            else:
                payload = frame
            opcode = b0 & 0x0F
            if opcode == 0x8:  # normal websocket close; the command's status came on the error channel
                return bytes(out), exit_code
            if opcode == 0x9:
                self._send(0xA, payload)
                continue
            if opcode not in (0x1, 0x2) or not payload:
                continue
            channel, data = payload[0], payload[1:]
            if channel == CH_ERROR and data:
                message = data.decode("utf-8", errors="replace").strip()
                if message:
                    channel_exit = _exit_from_error(message)
                    if channel_exit is not None:
                        exit_code = channel_exit
                    elif os.environ.get("KS_DEBUG"):
                        sys.stderr.write(f"[debug] non-exit error channel: {message!r}\n")
            elif channel in (CH_STDOUT, CH_STDERR):
                out += data

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self._send(0x8, struct.pack(">H", 1000))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


@dataclass(frozen=True)
class PodTarget:
    namespace: str
    pod: str
    container: str = ""


def resolve_kubeconfig(kubeconfig: str | None = None, context: str | None = None) -> KubeClient:
    """Load a kubeconfig the way kubectl would, for the fields a sandbox client needs.

    PyYAML is not a Hermes dependency; its bundled reader is.
    """
    try:
        import hermes_yaml as yaml
    except ImportError:  # pragma: no cover - any install with PyYAML works too
        import yaml  # type: ignore[no-redef]

    path = kubeconfig or os.environ.get("KUBECONFIG", "").split(os.pathsep)[0] or os.path.expanduser("~/.kube/config")
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    ctx_name = context or cfg.get("current-context") or ""
    ctx = next((c.get("context") or {} for c in cfg.get("contexts") or [] if c.get("name") == ctx_name), None)
    if ctx is None:
        raise ApiError(0, f"context {ctx_name!r} is not in {path}")
    cluster = next((c.get("cluster") or {} for c in cfg.get("clusters") or [] if c.get("name") == ctx.get("cluster")), {})
    user = next((u.get("user") or {} for u in cfg.get("users") or [] if u.get("name") == ctx.get("user")), {})
    if user.get("exec"):
        raise ApiError(0, f"{path}: context {ctx_name!r} logs in with an exec plugin; "
                          "point KUBECONFIG at a token-based config")
    ca = base64.b64decode(cluster["certificate-authority-data"]) if cluster.get("certificate-authority-data") else None
    ca_file = cluster.get("certificate-authority")
    if ca_file and os.path.exists(ca_file):
        with open(ca_file, "rb") as fh:
            ca = fh.read()
    return KubeClient(server=cluster.get("server", ""), ca_pem=ca, token=user.get("token"),
                      token_file=user.get("tokenFile"), insecure=bool(cluster.get("insecure-skip-tls-verify")))
