"""
ECC point, public key, and signature encoding/decoding.

Covers the COER representations of:
  - EccP256CurvePoint / EccP384CurvePoint  (IEEE 1609.2 clause 6.3.19/20)
  - PublicVerificationKey                   (clause 6.3.32)
  - PublicEncryptionKey                     (clause 6.3.30)
  - Signature                               (clause 6.3.37)
"""
from ..coer import encode_uint8, decode_uint8, encode_choice, decode_choice_tag
from ..types import (
    EccPoint, PublicVerificationKey, PublicEncryptionKey, EcdsaSignature,
    PublicKeyAlgorithm, EccP256CurvePointChoice,
)


# ── ECC Point encoding ────────────────────────────────────────────────────────

def encode_ecc_p256_point(point: EccPoint) -> bytes:
    """
    EccP256CurvePoint CHOICE (IEEE 1609.2 clause 6.3.19):
      x-only        [0]: 32-byte x-coordinate only
      compressed-y0 [2]: 32-byte x (y-parity = 0)
      compressed-y1 [3]: 32-byte x (y-parity = 1)
      uncompressed  [4]: 64 bytes (x || y)
    We always encode in compressed form.
    """
    tag = EccP256CurvePointChoice.COMPRESSED_Y0 if point.y_parity == 0 \
        else EccP256CurvePointChoice.COMPRESSED_Y1
    x_only = point.compressed[1:]   # strip the 0x02/0x03 prefix → 32 bytes
    return encode_choice(tag, x_only)


def decode_ecc_p256_point(data: bytes, offset: int):
    tag, offset = decode_choice_tag(data, offset)
    if tag in (EccP256CurvePointChoice.COMPRESSED_Y0,
               EccP256CurvePointChoice.COMPRESSED_Y1):
        x = data[offset:offset + 32]; offset += 32
        prefix = 0x02 if tag == EccP256CurvePointChoice.COMPRESSED_Y0 else 0x03
        compressed = bytes([prefix]) + x
        y_parity = tag - 2
        return EccPoint(curve='P-256', compressed=compressed, y_parity=y_parity), offset
    elif tag == EccP256CurvePointChoice.X_ONLY:
        x = data[offset:offset + 32]; offset += 32
        return EccPoint(curve='P-256', compressed=b'\x02' + x, y_parity=0), offset
    else:
        raise ValueError(f"Unsupported EccP256CurvePoint tag: {tag}")


def encode_ecc_p384_point(point: EccPoint) -> bytes:
    """EccP384CurvePoint (same structure, 48-byte coordinates)."""
    tag = 2 if point.y_parity == 0 else 3
    x_only = point.compressed[1:]   # 48 bytes
    return encode_choice(tag, x_only)


def decode_ecc_p384_point(data: bytes, offset: int):
    tag, offset = decode_choice_tag(data, offset)
    if tag in (2, 3):
        x = data[offset:offset + 48]; offset += 48
        prefix = 0x02 if tag == 2 else 0x03
        compressed = bytes([prefix]) + x
        y_parity = tag - 2
        return EccPoint(curve='P-384', compressed=compressed, y_parity=y_parity), offset
    elif tag == 0:
        x = data[offset:offset + 48]; offset += 48
        return EccPoint(curve='P-384', compressed=b'\x02' + x, y_parity=0), offset
    else:
        raise ValueError(f"Unsupported EccP384CurvePoint tag: {tag}")


# ── Public key encoding ───────────────────────────────────────────────────────

def encode_public_verification_key(vk: PublicVerificationKey) -> bytes:
    """
    PublicVerificationKey CHOICE (IEEE 1609.2 clause 6.3.32):
      ecdsaNistP256 [0]
      ecdsaNistP384 [1]
    """
    if vk.algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        return encode_choice(0, encode_ecc_p256_point(vk.point))
    else:
        return encode_choice(1, encode_ecc_p384_point(vk.point))


def decode_public_verification_key(data: bytes, offset: int):
    tag, offset = decode_choice_tag(data, offset)
    if tag == 0:
        point, offset = decode_ecc_p256_point(data, offset)
        return PublicVerificationKey(PublicKeyAlgorithm.ECDSA_NIST_P256, point), offset
    else:
        point, offset = decode_ecc_p384_point(data, offset)
        return PublicVerificationKey(PublicKeyAlgorithm.ECDSA_NIST_P384, point), offset


def encode_public_encryption_key(ek: PublicEncryptionKey) -> bytes:
    """
    PublicEncryptionKey ::= SEQUENCE {
      supportedSymmAlg SymmAlgorithm,   -- aes128Ccm = 0
      publicKey        BasePublicEncryptionKey CHOICE {
        eciesNistP256 [0]
        eciesNistP384 [1]
      }
    }
    """
    sym_alg = encode_uint8(0)   # aes128Ccm
    if ek.algorithm == PublicKeyAlgorithm.ECIES_NIST_P256:
        key_enc = encode_choice(0, encode_ecc_p256_point(ek.point))
    else:
        key_enc = encode_choice(1, encode_ecc_p384_point(ek.point))
    return sym_alg + key_enc


def decode_public_encryption_key(data: bytes, offset: int):
    _sym_alg, offset = decode_uint8(data, offset)   # should be 0
    tag, offset = decode_choice_tag(data, offset)
    if tag == 0:
        point, offset = decode_ecc_p256_point(data, offset)
        return PublicEncryptionKey(PublicKeyAlgorithm.ECIES_NIST_P256, point), offset
    else:
        point, offset = decode_ecc_p384_point(data, offset)
        return PublicEncryptionKey(PublicKeyAlgorithm.ECIES_NIST_P384, point), offset


# ── Signature encoding ────────────────────────────────────────────────────────

def encode_signature(sig: EcdsaSignature) -> bytes:
    """
    Signature CHOICE (IEEE 1609.2 clause 6.3.37):
      ecdsaNistP256Signature [0]: EcdsaP256Signature
      ecdsaNistP384Signature [1]: EcdsaP384Signature

    EcdsaP256Signature ::= SEQUENCE {
      r EccP256CurvePoint,   -- x-only form
      s OCTET STRING (SIZE(32))
    }
    r is stored as x-only (EccP256CurvePointChoice.X_ONLY = 0).
    """
    if sig.algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        r_enc = encode_choice(EccP256CurvePointChoice.X_ONLY, sig.r)   # 32 bytes
        sig_enc = r_enc + sig.s                                         # s is 32 bytes fixed
        return encode_choice(0, sig_enc)
    else:
        r_enc = encode_choice(0, sig.r)   # x-only for P-384 (48 bytes)
        sig_enc = r_enc + sig.s           # s is 48 bytes fixed
        return encode_choice(1, sig_enc)


def decode_signature(data: bytes, offset: int):
    sig_choice, offset = decode_choice_tag(data, offset)
    if sig_choice == 0:     # P-256
        _r_tag, offset = decode_choice_tag(data, offset)
        r = data[offset:offset + 32]; offset += 32
        s = data[offset:offset + 32]; offset += 32
        return EcdsaSignature(r=r, s=s, algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256), offset
    else:                   # P-384
        _r_tag, offset = decode_choice_tag(data, offset)
        r = data[offset:offset + 48]; offset += 48
        s = data[offset:offset + 48]; offset += 48
        return EcdsaSignature(r=r, s=s, algorithm=PublicKeyAlgorithm.ECDSA_NIST_P384), offset
