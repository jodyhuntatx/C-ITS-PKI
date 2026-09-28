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

def ieee1609_signing_input(tbs_encoded: bytes, signer_encoded: bytes,
                           algorithm: PublicKeyAlgorithm) -> bytes:
    """
    Data input for ECDSA signatures on v3 structures (IEEE 1609.2 clause 5.3.1.2.2):
    Hash(tbs) || Hash(signer), where signer is the canonical COER encoding of the
    signing certificate, or the empty string for self-signed data/certificates.
    ecdsa_sign()/ecdsa_verify() hash this input once more, which yields the
    specified digest Hash(Hash(tbs) || Hash(signer)).
    """
    return hash_data(tbs_encoded, algorithm) + hash_data(signer_encoded, algorithm)

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


# ── ECIES (IEEE 1609.2 §5.3.5, ETSI TS 103 097 Annex B) ───────────────────────
#
# Wraps a 16-byte AES-CCM key k for a recipient public key R:
#   S = x-coordinate of v*R (ephemeral key v, V = v*G)
#   ke || km = KDF2(S, P1): SHA256(S || 00000001 || P1) || SHA256(S || 00000002 || P1), 48 bytes
#   c = k XOR ke,  t = first 16 bytes of HMAC-SHA256(km, c)
# P1 (the KDF parameter) depends on the format and recipient type:
#   v3 certRecipInfo:  SHA-256 of the COER-encoded recipient certificate
#   v3 rekRecipInfo:   SHA-256 of the empty string
#   v2 (TS 103 097 v1.2.1): the empty string
# Verified against the SCMS ECIES test vectors (conz27/crypto-test-vectors, ecies).

def ecies_encrypt(recipient_pub_key: EllipticCurvePublicKey,
                  plaintext_key: bytes,
                  p1: bytes = b'',
                  ephemeral_priv_key: EllipticCurvePrivateKey = None) -> dict:
    """
    Encrypt a 16-byte AES key using ECIES.

    Returns dict with:
      'v': bytes  - ephemeral public key (compressed, 33 bytes for P-256)
      'c': bytes  - encrypted key, 16 bytes
      't': bytes  - authentication tag, 16 bytes
    ephemeral_priv_key is only for reproducible test vectors; leave it None.
    """
    assert len(plaintext_key) == 16
    ephem_priv = ephemeral_priv_key or generate_private_key(recipient_pub_key.curve, default_backend())
    shared_x = ephem_priv.exchange(ECDH(), recipient_pub_key)

    kdf_output = kdf2_sha256(shared_x, p1)
    ke, km = kdf_output[:16], kdf_output[16:]
    c = bytes(a ^ b for a, b in zip(plaintext_key, ke))
    t = hmac.new(km, c, hashlib.sha256).digest()[:16]

    v = ephem_priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint
    )
    return {'v': v, 'c': c, 't': t}


def ecies_decrypt(recipient_priv_key: EllipticCurvePrivateKey,
                  v: bytes, c: bytes, t: bytes, p1: bytes = b'') -> bytes:
    """
    Decrypt an ECIES-encrypted AES key; v is the ephemeral public key as an
    X9.62 point (compressed or uncompressed). Raises ValueError on a bad tag.
    """
    ephem_pub = EllipticCurvePublicKey.from_encoded_point(recipient_priv_key.curve, v)
    shared_x = recipient_priv_key.exchange(ECDH(), ephem_pub)

    kdf_output = kdf2_sha256(shared_x, p1)
    ke, km = kdf_output[:16], kdf_output[16:]
    expected_t = hmac.new(km, c, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expected_t, t):
        raise ValueError("ECIES: authentication tag mismatch")
    return bytes(a ^ b for a, b in zip(c, ke))


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

# ── Curve constants ───────────────────────────────────────────────────────────

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P384_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973

def _curve_order(curve) -> int:
    if isinstance(curve, SECP256R1):
        return _P256_ORDER
    return _P384_ORDER


# ── Butterfly Key Mechanism (IEEE 1609.2.1) ─────────────────────────────────
#
# Expansion function (IEEE 1609.2.1 / SCMS), k = 128-bit expansion key:
#   f_k^int(x) = (AES_k(x+1) XOR (x+1)) || (AES_k(x+2) XOR (x+2)) || (AES_k(x+3) XOR (x+3))
#   f_k(x)     = f_k^int(x) mod n                         (n = curve order)
# with the 128-bit input
#   x_cert = 0^32 || i || j || 0^32   (verification / certificate keys)
#   x_enc  = 1^32 || i || j || 0^32   (response encryption keys, "original" option)
# where i is the i-period and j the certificate index within it (both 32 bits).
#
# Cocoon keys (EE and RA/EA):   sk_cc = a + f_k(x) mod n,  pk_cc = A + f_k(x)*G
# Butterfly keys (ACA/AA):      random r in [1, n-1],      pk_bf = pk_cc + r*G
# Reconstruction (EE):          sk_bf = sk_cc + r mod n
# The AA certifies pk_bf and returns (pk_bf, cert, r) encrypted to the encryption cocoon
# key (original option) or to the signing cocoon key itself (unified option).
# Verified against the SCMS reference test vectors (conz27/crypto-test-vectors, bfkeyexp).

BKE_PURPOSE_CERT = 'cert'
BKE_PURPOSE_ENC = 'enc'

_MASK_128 = (1 << 128) - 1


def bke_expansion_input(i: int, j: int, purpose: str = BKE_PURPOSE_CERT) -> int:
    """128-bit expansion function input x for i-period i and index j."""
    if not (0 <= i < 2**32 and 0 <= j < 2**32):
        raise ValueError("BKE: i and j must be 32-bit unsigned integers")
    prefix = {BKE_PURPOSE_CERT: 0, BKE_PURPOSE_ENC: 0xFFFFFFFF}[purpose]
    return (((prefix << 32 | i) << 32) | j) << 32


def bke_f_k_int(expansion_key: bytes, x: int) -> bytes:
    """f_k^int(x): three AES-128 blocks, 384 bits."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if len(expansion_key) != 16:
        raise ValueError("BKE: the expansion key must be 16 bytes (AES-128)")
    encryptor = Cipher(algorithms.AES(expansion_key), modes.ECB()).encryptor()
    out = b''
    for t in (1, 2, 3):
        block = ((x + t) & _MASK_128).to_bytes(16, 'big')
        out += bytes(a ^ b for a, b in zip(encryptor.update(block), block))
    return out


def bke_f_k(expansion_key: bytes, x: int, curve) -> int:
    """f_k(x) = f_k^int(x) mod n (NIST P-256 only)."""
    if not isinstance(curve, SECP256R1):
        raise ValueError("BKE: only NIST P-256 is supported")
    return int.from_bytes(bke_f_k_int(expansion_key, x), 'big') % _P256_ORDER


def _point_plus_scalar_g(pub: EllipticCurvePublicKey, scalar: int) -> EllipticCurvePublicKey:
    """pub + scalar*G (cryptography does not expose EC point addition)."""
    from tinyec import registry as tinyec_registry
    from tinyec import ec as tinyec_ec
    tc = tinyec_registry.get_curve('secp256r1')
    nums = pub.public_numbers()
    point = tinyec_ec.Point(tc, nums.x, nums.y) + (scalar * tc.g)
    if point.x is None or point.y is None:
        raise ValueError("BKE: resulting public key is the point at infinity")
    return EllipticCurvePublicNumbers(point.x, point.y, pub.curve).public_key(default_backend())


def _private_plus_scalar(priv: EllipticCurvePrivateKey, scalar: int) -> EllipticCurvePrivateKey:
    value = (priv.private_numbers().private_value + scalar) % _curve_order(priv.curve)
    if value == 0:
        raise ValueError("BKE: resulting private key is zero")
    return derive_private_key(value, priv.curve, default_backend())


def bke_cocoon_private_key(caterpillar_priv: EllipticCurvePrivateKey, expansion_key: bytes,
                           i: int, j: int, purpose: str = BKE_PURPOSE_CERT) -> EllipticCurvePrivateKey:
    """End entity: sk_cc = a + f_k(x) mod n."""
    x = bke_expansion_input(i, j, purpose)
    return _private_plus_scalar(caterpillar_priv, bke_f_k(expansion_key, x, caterpillar_priv.curve))


def bke_cocoon_public_key(caterpillar_pub: EllipticCurvePublicKey, expansion_key: bytes,
                          i: int, j: int, purpose: str = BKE_PURPOSE_CERT) -> EllipticCurvePublicKey:
    """RA/EA (and end entity): pk_cc = A + f_k(x)*G."""
    x = bke_expansion_input(i, j, purpose)
    return _point_plus_scalar_g(caterpillar_pub, bke_f_k(expansion_key, x, caterpillar_pub.curve))


def bke_random_offset(curve) -> int:
    """ACA/AA: fresh random offset r in [1, n-1] for one butterfly certificate."""
    n = _curve_order(curve)
    while True:
        r = int.from_bytes(os.urandom(32), 'big') % n
        if r:
            return r


def bke_butterfly_public_key(cocoon_pub: EllipticCurvePublicKey, offset: int) -> EllipticCurvePublicKey:
    """ACA/AA: pk_bf = pk_cc + r*G (the key that is certified)."""
    return _point_plus_scalar_g(cocoon_pub, offset)


def bke_butterfly_private_key(cocoon_priv: EllipticCurvePrivateKey, offset: int) -> EllipticCurvePrivateKey:
    """End entity: sk_bf = sk_cc + r mod n (the certificate's signing key)."""
    return _private_plus_scalar(cocoon_priv, offset)

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
    """Serialize private key to PKCS8 DER (for storage)."""
    return priv_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

def deserialize_private_key(der: bytes) -> EllipticCurvePrivateKey:
    return serialization.load_der_private_key(der, password=None, backend=default_backend())
