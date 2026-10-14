"""Cryptographic core: canonical JSON, SHA-256 fingerprints, RSA-PSS signatures."""
import json, hashlib, base64, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

KEYDIR = os.environ.get("ALERTTRUST_KEYS", os.path.join(os.path.dirname(__file__), "keys"))
GENESIS = "0" * 64
_PSS = lambda: padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

def canonical(d: dict) -> str:
    """Deterministic serialization so formatting changes never alter the hash."""
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def signing_message(seq, alert_id, sealed_at, prev_hash, h) -> str:
    return f"{seq}|{alert_id}|{sealed_at}|{prev_hash}|{h}"

def ensure_keys():
    os.makedirs(KEYDIR, exist_ok=True)
    priv, pub = os.path.join(KEYDIR, "private.pem"), os.path.join(KEYDIR, "public.pem")
    if not os.path.exists(priv):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with open(priv, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(priv, 0o600)
        with open(pub, "wb") as f:
            f.write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

def sign(message: str) -> str:
    with open(os.path.join(KEYDIR, "private.pem"), "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return base64.b64encode(key.sign(message.encode(), _PSS(), hashes.SHA256())).decode()

def verify_sig(message: str, sig_b64: str) -> bool:
    """Verification needs only the PUBLIC key."""
    with open(os.path.join(KEYDIR, "public.pem"), "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    try:
        pub.verify(base64.b64decode(sig_b64), message.encode(), _PSS(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False
