"""
Cryptographic operations for C-ITS PKI.
Implements ECDSA (P-256/P-384), AES-128-CCM, ECIES per IEEE Std 1609.2-2025.
"""
import hashlib
import hmac
import os
import struct
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, SECP256R1, SECP384R1, EllipticCurvePrivateKey,
    EllipticCurvePublicKey, derive_private_key, generate_private_key,
    EllipticCurvePublicNumbers, ECDH
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend

from .types import PublicKeyAlgorithm, EccPoint


# ── Key Generation ────────────────────────────────────────────────────────────

def generate_keypair_p256() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    priv = generate_private_key(SECP256R1(), default_backend())
    return priv, priv.public_key()


def generate_keypair_p384() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    priv = generate_private_key(SECP384R1(), default_backend())
    return priv, priv.public_key()


def generate_keypair(algorithm: PublicKeyAlgorithm):
    if algorithm in (PublicKeyAlgorithm.ECDSA_NIST_P256, PublicKeyAlgorithm.ECIES_NIST_P256):
        return generate_keypair_p256()
    elif algorithm in (PublicKeyAlgorithm.ECDSA_NIST_P384, PublicKeyAlgorithm.ECIES_NIST_P384):
        return generate_keypair_p384()
    raise ValueError(f"Unsupported algorithm: {algorithm}")


# ── Hashing ───────────────────────────────────────────────────────────────────

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()

def hash_certificate(cert_encoded: bytes, algorithm: PublicKeyAlgorithm) -> bytes:
    """Return HashedId8: last 8 bytes of certificate hash."""
    if algorithm in (PublicKeyAlgorithm.ECDSA_NIST_P256, PublicKeyAlgorithm.ECIES_NIST_P256):
        return sha256(cert_encoded)[-8:]
    else:
        return sha384(cert_encoded)[-8:]

def hash_data(data: bytes, algorithm: PublicKeyAlgorithm) -> bytes:
    if algorithm in (PublicKeyAlgorithm.ECDSA_NIST_P256, PublicKeyAlgorithm.ECIES_NIST_P256):
        return sha256(data)
    else:
        return sha384(data)


# ── ECDSA Signing ─────────────────────────────────────────────────────────────

def ecdsa_sign(private_key: EllipticCurvePrivateKey, data: bytes,
               algorithm: PublicKeyAlgorithm) -> Tuple[bytes, bytes]:
    """
    Sign data using ECDSA. Returns (r, s) as raw bytes.
    IEEE 1609.2 uses a specific signature format: (R.x, s) where R is the
    ephemeral public key point — stored as x-coordinate only.
    """
    if algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        hash_alg = hashes.SHA256()
        coord_size = 32
    else:
        hash_alg = hashes.SHA384()
        coord_size = 48

    # Sign using DER encoding, then extract r and s
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    sig_der = private_key.sign(data, ECDSA(hash_alg))
    r, s = decode_dss_signature(sig_der)
    r_bytes = r.to_bytes(coord_size, 'big')
    s_bytes = s.to_bytes(coord_size, 'big')
    return r_bytes, s_bytes


def ecdsa_verify(public_key: EllipticCurvePublicKey, data: bytes,
                 r_bytes: bytes, s_bytes: bytes,
                 algorithm: PublicKeyAlgorithm) -> bool:
    """Verify ECDSA signature."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature

    if algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        hash_alg = hashes.SHA256()
    else:
        hash_alg = hashes.SHA384()

    r = int.from_bytes(r_bytes, 'big')
    s = int.from_bytes(s_bytes, 'big')
    sig_der = encode_dss_signature(r, s)
    try:
        public_key.verify(sig_der, data, ECDSA(hash_alg))
        return True
    except InvalidSignature:
        return False


# ── KDF2 (IEEE 1609.2 §5.3.5) ─────────────────────────────────────────────────

def kdf2_sha256(shared_secret: bytes, param: bytes = b'') -> bytes:
    """
    KDF2 based on SHA-256 per IEEE Std 1609.2.
    Output: TRUNCATE(SHA256(S||0x00000001||P1) || SHA256(S||0x00000002||P1), 48)
    Returns 48 bytes: ke (16 bytes) || km (32 bytes).
    """
    h1 = hashlib.sha256(shared_secret + b'\x00\x00\x00\x01' + param).digest()
    h2 = hashlib.sha256(shared_secret + b'\x00\x00\x00\x02' + param).digest()
    output = (h1 + h2)[:48]
    return output


# ── ECIES (IEEE 1609.2 §5.3.5) ────────────────────────────────────────────────

def ecies_encrypt(recipient_pub_key: EllipticCurvePublicKey,
                  plaintext_key: bytes) -> dict:
    """
    Encrypt a 16-byte AES key using ECIES per IEEE Std 1609.2 §5.3.5.

    Returns dict with:
      'v': bytes  - ephemeral public key (compressed, 33 bytes for P-256)
      'c': bytes  - encrypted key (XOR of plaintext_key with ke), 16 bytes
      't': bytes  - HMAC authentication tag, 16 bytes
    """
    curve = recipient_pub_key.curve

    # Generate ephemeral key pair
    ephem_priv = generate_private_key(curve, default_backend())
    ephem_pub = ephem_priv.public_key()

    # ECDH to get shared secret (x-coordinate of shared point)
    shared_point = ephem_priv.exchange(ECDH(), recipient_pub_key)
    # shared_point is the x-coordinate as bytes

    # KDF2
    kdf_output = kdf2_sha256(shared_point)
    ke = kdf_output[:16]   # encryption key
    km = kdf_output[16:]   # MAC key (32 bytes)

    # Encrypt AES key by XOR
    assert len(plaintext_key) == 16
    c = bytes(a ^ b for a, b in zip(plaintext_key, ke))

    # Authentication tag: HMAC-SHA256(c, km), truncated to 16 bytes
    t = hmac.new(km, c, hashlib.sha256).digest()[:16]

    # Ephemeral public key in compressed form
    v = ephem_pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint
    )

    return {'v': v, 'c': c, 't': t}


def ecies_decrypt(recipient_priv_key: EllipticCurvePrivateKey,
                  v: bytes, c: bytes, t: bytes) -> bytes:
    """
    Decrypt an ECIES-encrypted AES key per IEEE Std 1609.2 §5.3.5.
    Returns the decrypted 16-byte AES key.
    """
    curve = recipient_priv_key.curve

    # Reconstruct ephemeral public key from compressed point
    ephem_pub = EllipticCurvePublicKey.from_encoded_point(curve, v)

    # ECDH
    shared_point = recipient_priv_key.exchange(ECDH(), ephem_pub)

    # KDF2
    kdf_output = kdf2_sha256(shared_point)
    ke = kdf_output[:16]
    km = kdf_output[16:]

    # Verify MAC
    expected_t = hmac.new(km, c, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expected_t, t):
        raise ValueError("ECIES: authentication tag mismatch")

    # Decrypt AES key
    plaintext_key = bytes(a ^ b for a, b in zip(c, ke))
    return plaintext_key


# ── AES-128-CCM (IEEE 1609.2 §5.3.8) ─────────────────────────────────────────

def aes_ccm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                    aad: bytes = b'') -> bytes:
    """
    Encrypt with AES-128-CCM. Returns ciphertext || 16-byte auth tag.
    key: 16 bytes, nonce: 12 bytes.
    """
    assert len(key) == 16, "AES-128-CCM requires 16-byte key"
    assert len(nonce) == 12, "AES-128-CCM requires 12-byte nonce"
    aesccm = AESCCM(key, tag_length=16)
    return aesccm.encrypt(nonce, plaintext, aad if aad else None)


def aes_ccm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes,
                    aad: bytes = b'') -> bytes:
    """Decrypt AES-128-CCM ciphertext (last 16 bytes are auth tag)."""
    assert len(key) == 16
    assert len(nonce) == 12
    aesccm = AESCCM(key, tag_length=16)
    return aesccm.decrypt(nonce, ciphertext_with_tag, aad if aad else None)


# ── Utility ───────────────────────────────────────────────────────────────────

def random_bytes(n: int) -> bytes:
    """Cryptographically secure random bytes (CSPRNG)."""
    return os.urandom(n)

def public_key_to_point(pub_key: EllipticCurvePublicKey) -> EccPoint:
    from .types import EccPoint
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
    compressed = pub_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint
    )
    curve_name = 'P-256' if isinstance(pub_key.curve, SECP256R1) else 'P-384'
    y_parity = compressed[0] - 0x02
    return EccPoint(curve=curve_name, compressed=compressed, y_parity=y_parity)

def load_public_key_from_compressed(curve_name: str, compressed: bytes) -> EllipticCurvePublicKey:
    """Load an EllipticCurvePublicKey from compressed point bytes."""
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1
    curve = SECP256R1() if curve_name == 'P-256' else SECP384R1()
    return EllipticCurvePublicKey.from_encoded_point(curve, compressed)

def serialize_private_key(priv_key: EllipticCurvePrivateKey) -> bytes:
    """Serialize private key to PEM (for storage)."""
    return priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

def deserialize_private_key(pem: bytes) -> EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())
