"""
Data structure definitions for C-ITS PKI conforming to ETSI TS 103 097 V2.2.1
and IEEE Std 1609.2-2025.  Also supports ETSI TS 103 097 V1.2.1 / IEEE 1609.2-2016.
"""
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional
import time


# ── IEEE 1609.2 time base ─────────────────────────────────────────────────────
# Time32/Time64 epoch: 2004-01-01 00:00:00 UTC
_EPOCH_2004 = 1072915200  # Unix timestamp of 2004-01-01T00:00:00Z

def unix_to_its_time32(unix_ts: float) -> int:
    """Seconds since 2004-01-01 00:00:00 UTC."""
    return max(0, int(unix_ts) - _EPOCH_2004)

def unix_to_its_time64(unix_ts: float) -> int:
    """Microseconds since 2004-01-01 00:00:00 UTC."""
    return max(0, int(unix_ts * 1_000_000) - _EPOCH_2004 * 1_000_000)

def its_time32_to_unix(its_ts: int) -> float:
    return its_ts + _EPOCH_2004

def now_its_time32() -> int:
    return unix_to_its_time32(time.time())

def now_its_time64() -> int:
    return unix_to_its_time64(time.time())


# ── Registered ITS-AIDs (ETSI TS 102 965) ────────────────────────────────────

class ItsAid(IntEnum):
    CAM = 36
    DENM = 37
    CTL = 617        # Certificate Trust List
    CRL = 622        # Certificate Revocation List
    CERT_REQUEST = 623  # Secure Certificate Request
    MDM = 637        # Misbehaviour Detection Management


# ── ETSI TS 103 097 standard version ─────────────────────────────────────────

class EtsiVersion(IntEnum):
    """
    ETSI TS 103 097 standard version selector.

    Controls the ToBeSignedCertificate optional-field bitmap width and the
    presence of fields introduced in later IEEE 1609.2 revisions:

      V1_2_1 — ETSI TS 103 097 V1.2.1 (2015), based on IEEE 1609.2-2016.
               7 optional TBS fields → 1-byte presence bitmap.
               No ``flags`` field.

      V2_2_1 — ETSI TS 103 097 V2.2.1 (2021), based on IEEE 1609.2-2022/2025.
               8 optional TBS fields (adds ``flags``) → 2-byte presence bitmap.
    """
    V1_2_1 = 1
    V2_2_1 = 2


# ── Hash algorithms ───────────────────────────────────────────────────────────

class HashAlgorithm(IntEnum):
    SHA256 = 0
    SHA384 = 1


# ── Certificate type ──────────────────────────────────────────────────────────

class CertificateType(IntEnum):
    EXPLICIT = 0
    IMPLICIT = 1


# ── IssuerIdentifier CHOICE alternatives ─────────────────────────────────────

class IssuerChoice(IntEnum):
    SHA256_AND_DIGEST = 0
    SELF = 1
    SHA384_AND_DIGEST = 2


# ── CertificateId CHOICE alternatives ────────────────────────────────────────

class CertIdChoice(IntEnum):
    LINKAGE_DATA = 0
    NAME = 1
    BINARY_ID = 2
    NONE = 3


# ── Duration CHOICE alternatives ──────────────────────────────────────────────

class DurationChoice(IntEnum):
    MICROSECONDS = 0
    MILLISECONDS = 1
    SECONDS = 2
    MINUTES = 3
    HOURS = 4
    SIXTY_HOURS = 5
    YEARS = 6


# ── Geographic region CHOICE alternatives ─────────────────────────────────────

class RegionChoice(IntEnum):
    CIRCLE = 0
    RECTANGLE = 1
    POLYGON = 2
    ID = 3


# ── SignerIdentifier CHOICE alternatives ──────────────────────────────────────

class SignerChoice(IntEnum):
    DIGEST = 0
    CERTIFICATE = 1
    SELF = 2


# ── Symmetric cipher CHOICE alternatives ─────────────────────────────────────

class SymCipherChoice(IntEnum):
    AES128_CCM = 0


# ── RecipientInfo CHOICE alternatives ────────────────────────────────────────

class RecipientChoice(IntEnum):
    PSK_RECIP_INFO = 0
    SYMMRECIP_INFO = 1
    CERT_RECIP_INFO = 2
    SIGNED_DATA_RECIP_INFO = 3


# ── Public key algorithms ─────────────────────────────────────────────────────

class PublicKeyAlgorithm(IntEnum):
    ECDSA_NIST_P256 = 0
    ECDSA_NIST_P384 = 1
    ECIES_NIST_P256 = 2
    ECIES_NIST_P384 = 3  # not in 1609.2-2016 but added in later versions


class EccP256CurvePointChoice(IntEnum):
    X_ONLY = 0
    FILL = 1          # not actually valid
    COMPRESSED_Y0 = 2
    COMPRESSED_Y1 = 3
    UNCOMPRESSED = 4


class EccP384CurvePointChoice(IntEnum):
    X_ONLY = 0
    FILL = 1
    COMPRESSED_Y0 = 2
    COMPRESSED_Y1 = 3
    UNCOMPRESSED = 4


# ── Dataclasses for certificate structures ────────────────────────────────────

@dataclass
class Duration:
    choice: DurationChoice
    value: int  # Uint16


@dataclass
class ValidityPeriod:
    start: int      # Time32 (seconds since ITS epoch)
    duration: Duration


@dataclass
class PsidSsp:
    psid: int           # ITS-AID
    ssp: Optional[bytes] = None  # ServiceSpecificPermissions (opaque bytes), absent = no SSP


@dataclass
class PsidGroupPermissions:
    psid_range: Optional[tuple] = None  # (min, max) or None for all
    ssp_range: Optional[bytes] = None
    min_chain_depth: int = 0
    chain_depth_range: int = 0
    ee_type: int = 0


@dataclass
class EccPoint:
    """Compressed or uncompressed ECC public key point."""
    curve: str          # 'P-256' or 'P-384'
    compressed: bytes   # 33 bytes (P-256) or 49 bytes (P-384), compressed form
    y_parity: int       # 0 or 1 (from compressed point prefix 0x02/0x03)

    @classmethod
    def from_cryptography_key(cls, pub_key) -> 'EccPoint':
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicKey, SECP256R1, SECP384R1
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat
        )
        compressed = pub_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        curve_name = 'P-256' if isinstance(pub_key.curve, SECP256R1) else 'P-384'
        y_parity = compressed[0] - 0x02  # 0x02 -> 0, 0x03 -> 1
        return cls(curve=curve_name, compressed=compressed, y_parity=y_parity)


@dataclass
class PublicVerificationKey:
    """VerificationKey CHOICE: ecdsaNistP256 or ecdsaNistP384."""
    algorithm: PublicKeyAlgorithm
    point: EccPoint


@dataclass
class PublicEncryptionKey:
    """PublicEncryptionKey for ECIES."""
    algorithm: PublicKeyAlgorithm  # ECIES_NIST_P256 or ECIES_NIST_P384
    point: EccPoint


@dataclass
class GeographicRegion:
    """Simplified: only IdentifiedRegion (list of country IDs) supported."""
    choice: RegionChoice
    # For ID (choice=3): list of integer country/region IDs
    ids: Optional[list] = None
    # EU-27 = 65535 as a special identified region value


@dataclass
class SubjectAssurance:
    level: int      # 0-7
    confidence: int # 0-3


@dataclass
class CertificateId:
    choice: CertIdChoice
    name: Optional[str] = None


@dataclass
class IssuerIdentifier:
    choice: IssuerChoice
    digest: Optional[bytes] = None      # HashedId8 (8 bytes) for sha256/sha384
    hash_alg: Optional[HashAlgorithm] = None  # for self


@dataclass
class EcdsaSignature:
    r: bytes  # 32 or 48 bytes
    s: bytes  # 32 or 48 bytes
    algorithm: PublicKeyAlgorithm


@dataclass
class ToBeSignedCertificate:
    id: CertificateId
    craca_id: bytes                          # HashedId3 = 3 bytes = b'\x00\x00\x00'
    crl_series: int                          # Uint16 = 0
    validity_period: ValidityPeriod
    region: Optional[GeographicRegion] = None
    assurance_level: Optional[SubjectAssurance] = None
    app_permissions: Optional[list] = None   # list of PsidSsp
    cert_issue_permissions: Optional[list] = None  # list of PsidGroupPermissions
    encryption_key: Optional[PublicEncryptionKey] = None
    verify_key_indicator: Optional[PublicVerificationKey] = None  # for explicit certs
    reconstruction_value: Optional[EccPoint] = None              # for implicit certs


@dataclass
class Certificate:
    version: int  # always 3
    cert_type: CertificateType
    issuer: IssuerIdentifier
    tbs: ToBeSignedCertificate
    signature: Optional[EcdsaSignature] = None
    # Cached COER encoding of TBS (for signing)
    tbs_encoded: bytes = field(default_factory=bytes, repr=False)
    # Cached full COER encoding
    encoded: bytes = field(default_factory=bytes, repr=False)


# ── Vanetza v2 wire-format constants ─────────────────────────────────────────
# These mirror the C++ enums in vanetza/security/v2/*.hpp.
# Kept here (alongside other protocol enums) so that v1_encoding.py is purely
# a codec module and does not double as a type-definition file.

class V1SubjectType:
    """vanetza SubjectType (subject_info.hpp)."""
    ENROLLMENT_CREDENTIAL   = 0
    AUTHORIZATION_TICKET    = 1
    AUTHORIZATION_AUTHORITY = 2
    ENROLLMENT_AUTHORITY    = 3
    ROOT_CA                 = 4
    CRL_SIGNER              = 5


class V1SignerInfoType:
    """vanetza SignerInfoType (signer_info.hpp)."""
    SELF                           = 0
    CERTIFICATE_DIGEST_WITH_SHA256 = 1
    CERTIFICATE                    = 2
    CERTIFICATE_CHAIN              = 3


class V1EccPointType:
    """vanetza EccPointType (ecc_point.hpp)."""
    X_COORDINATE_ONLY  = 0
    COMPRESSED_LSB_Y_0 = 2
    COMPRESSED_LSB_Y_1 = 3
    UNCOMPRESSED       = 4


class V1PublicKeyAlgorithm:
    """vanetza PublicKeyAlgorithm (public_key.hpp)."""
    ECDSA_NISTP256_WITH_SHA256 = 0
    ECIES_NISTP256             = 1


class V1SubjectAttributeType:
    """vanetza SubjectAttributeType (subject_attribute.hpp)."""
    VERIFICATION_KEY = 0
    ENCRYPTION_KEY   = 1
    ASSURANCE_LEVEL  = 2
    ITS_AID_LIST     = 32   # 0x20
    ITS_AID_SSP_LIST = 33   # 0x21


class V1ValidityRestrictionType:
    """vanetza ValidityRestrictionType (validity_restriction.hpp)."""
    TIME_END                = 0
    TIME_START_AND_END      = 1
    TIME_START_AND_DURATION = 2
    REGION                  = 3


class V1RegionType:
    """vanetza RegionType (region.hpp)."""
    NONE      = 0
    CIRCLE    = 1
    RECTANGLE = 2
    POLYGON   = 3
    ID        = 4


class V1RegionDictionary:
    """vanetza RegionDictionary (region.hpp)."""
    ISO_3166_1 = 0
    UN_STATS   = 1


@dataclass
class KeyPair:
    """An ECDSA or ECIES key pair with associated certificate."""
    private_key: object   # cryptography private key object
    public_key: object    # cryptography public key object
    algorithm: PublicKeyAlgorithm
    certificate: Optional[Certificate] = None
