import base64
import json
import hashlib
from typing import Tuple

from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.bindings import crypto_scalarmult  

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

# =========================
# Utils
# =========================

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def derive_aes_key(shared_secret: bytes) -> bytes:
    return hashlib.sha256(shared_secret).digest()  # 32B

# =========================
# ECDH (X25519)
# =========================

def generate_ecdh_keypair() -> Tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key
    return bytes(priv), bytes(pub)

def ecdh_derive_shared_secret(our_private: bytes, peer_public: bytes) -> bytes:
    return crypto_scalarmult(our_private, peer_public)

# =========================
# Ed25519 
# =========================

def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    sk = SigningKey.generate()
    vk = sk.verify_key
    return bytes(sk), bytes(vk)

def sign_message(signing_key_bytes: bytes, message: bytes) -> bytes:
    sk = SigningKey(signing_key_bytes)
    return sk.sign(message).signature

def safe_verify_key(verify_key_bytes: bytes) -> VerifyKey:
    if not isinstance(verify_key_bytes, bytes):
        raise TypeError("VerifyKey must be created from bytes")
    if len(verify_key_bytes) != 32:
        raise ValueError(f"VerifyKey must be 32 bytes, got {len(verify_key_bytes)}")
    return VerifyKey(verify_key_bytes)

def verify_signature(verify_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        vk = safe_verify_key(verify_key_bytes)
        vk.verify(message, signature)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


# =========================
# AES (CFB) 
# =========================

def aes_encrypt_text(key: bytes, plaintext: str) -> str:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    ct = cipher.encrypt(plaintext.encode("utf-8"))
    return b64e(iv + ct)

def aes_decrypt_text(key: bytes, ciphertext_b64: str) -> str:
    raw = b64d(ciphertext_b64)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    pt = cipher.decrypt(ct)
    return pt.decode("utf-8")

def aes_encrypt_bytes(key: bytes, data: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return iv + cipher.encrypt(data)

def aes_decrypt_bytes(key: bytes, data: bytes) -> bytes:
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ct)

# =========================
# RSA (OAEP) 
# =========================

def generate_rsa_keypair(bits: int = 2048) -> Tuple[str, str]:
    key = RSA.generate(bits)
    priv_pem = key.export_key(format="PEM")
    pub_pem = key.publickey().export_key(format="PEM")
    return b64e(priv_pem), b64e(pub_pem)

def rsa_encrypt_bytes(pub_b64: str, data: bytes) -> str:
    pub_pem = base64.b64decode(pub_b64)
    pub_key = RSA.import_key(pub_pem)
    cipher = PKCS1_OAEP.new(pub_key)
    enc = cipher.encrypt(data)
    return b64e(enc)

def rsa_decrypt_bytes(priv_b64: str, ciphertext_b64: str) -> bytes:
    priv_pem = base64.b64decode(priv_b64)
    priv_key = RSA.import_key(priv_pem)
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(b64d(ciphertext_b64))

# =========================
# JSON pakowanie
# =========================

def pack_encrypted_json(author: str, message: str, aes_key: bytes) -> bytes:

    enc_msg_b64 = aes_encrypt_text(aes_key, message)
    payload = {"Author": author, "Message": enc_msg_b64}
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")

def unpack_encrypted_json(data: bytes, aes_key: bytes) -> dict:
    payload = json.loads(data.decode("utf-8"))
    dec_msg = aes_decrypt_text(aes_key, payload["Message"])
    return {"Author": payload["Author"], "Message": dec_msg}

def aes_encrypt_file(key: bytes, src_path: str, dst_path: str) -> None:
    with open(src_path, "rb") as f:
        data = f.read()
    enc = aes_encrypt_bytes(key, data)
    with open(dst_path, "wb") as f:
        f.write(enc)

def aes_decrypt_file(key: bytes, src_path: str, dst_path: str) -> None:
    with open(src_path, "rb") as f:
        enc = f.read()
    dec = aes_decrypt_bytes(key, enc)
    with open(dst_path, "wb") as f:
        f.write(dec)
