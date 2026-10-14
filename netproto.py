"""Tiny wire protocol between agents and the collector: 4-byte length + JSON, with an HMAC to authenticate senders."""
import os, hmac, hashlib, json, struct
import crypto

KEY = os.environ.get("ALERTTRUST_AGENT_KEY", "lab-shared-secret-change-me").encode()   # shared secret (lab use only)
MAX_FRAME = 65536

def mac_for(record: dict) -> str:
    return hmac.new(KEY, crypto.canonical(record).encode(), hashlib.sha256).hexdigest()

def send_frame(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: return None
        buf += chunk
    return buf

def recv_frame(sock):
    head = _recvn(sock, 4)
    if not head: return None
    (n,) = struct.unpack(">I", head)
    if n > MAX_FRAME: raise ValueError("frame too large")
    body = _recvn(sock, n)
    return json.loads(body) if body else None
