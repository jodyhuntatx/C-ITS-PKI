"""
Certificate structure encoding/decoding (v3: IEEE 1609.2-2016 / ETSI TS 103 097 v1.3.1).

Covers the COER representations of:
  - Duration / ValidityPeriod              (IEEE 1609.2 clauses 6.3.24, 6.3.39)
  - GeographicRegion                       (clause 6.3.4)
  - IssuerIdentifier                       (clause 6.3.27)
  - CertificateId                          (clause 6.4.3)
  - VerifyKeyIndicator                     (clause 6.4.7)
  - ToBeSignedCertificate                  (clause 6.4.6)
  - Certificate / EtsiTs103097Certificate  (clause 6.4.2)

All encoding is done by asn1tools against the ASN.1 modules Vanetza compiles
(see asn1_codec.py); these functions keep the tool's dataclass API and the
``(value, new_offset)`` return convention of the decoders.

Decoders are strict: COER is canonical, so the decoded value must re-encode to
exactly the input bytes, otherwise a ValueError is raised.
"""
from ..types import (
    Certificate, ToBeSignedCertificate, IssuerIdentifier, CertificateId,
    ValidityPeriod, Duration, GeographicRegion, PublicVerificationKey,
    PublicKeyAlgorithm, EtsiVersion,
)
from . import asn1_codec as codec


def _decode_canonical(type_name: str, data: bytes, offset: int):
    """Decode a value at offset and return (asn1 value, encoded bytes consumed)."""
    try:
        value = codec.decode(type_name, bytes(data[offset:]))
    except Exception as e:
        raise ValueError(f"Invalid COER {type_name}: {e}") from None
    encoded = codec.encode(type_name, value)
    if bytes(data[offset:offset + len(encoded)]) != encoded:
        raise ValueError(f"{type_name} is not canonical COER (re-encoding differs)")
    return value, encoded


# ── Duration / ValidityPeriod ────────────────────────────────────────────────

def encode_duration(d: Duration) -> bytes:
    """Duration CHOICE (IEEE 1609.2 clause 6.3.24)."""
    return codec.encode('Duration', codec.duration_to_asn(d))


def decode_duration(data: bytes, offset: int):
    value, enc = _decode_canonical('Duration', data, offset)
    return codec.duration_from_asn(value), offset + len(enc)


def encode_validity_period(vp: ValidityPeriod) -> bytes:
    """ValidityPeriod ::= SEQUENCE { start Time32, duration Duration }."""
    return codec.encode('ValidityPeriod',
                        {'start': vp.start, 'duration': codec.duration_to_asn(vp.duration)})


def decode_validity_period(data: bytes, offset: int):
    value, enc = _decode_canonical('ValidityPeriod', data, offset)
    return (ValidityPeriod(start=value['start'], duration=codec.duration_from_asn(value['duration'])),
            offset + len(enc))


# ── GeographicRegion ─────────────────────────────────────────────────────────

def encode_geographic_region(region: GeographicRegion) -> bytes:
    """GeographicRegion CHOICE (clause 6.3.4); identifiedRegion/countryOnly only."""
    return codec.encode('GeographicRegion', codec._region(region))


def decode_geographic_region(data: bytes, offset: int):
    value, enc = _decode_canonical('GeographicRegion', data, offset)
    return codec._region_from_asn(value), offset + len(enc)


# ── IssuerIdentifier / CertificateId / VerifyKeyIndicator ────────────────────

def encode_issuer_identifier(issuer: IssuerIdentifier) -> bytes:
    return codec.encode('IssuerIdentifier', codec._issuer(issuer))


def decode_issuer_identifier(data: bytes, offset: int):
    value, enc = _decode_canonical('IssuerIdentifier', data, offset)
    return codec._issuer_from_asn(value), offset + len(enc)


def encode_certificate_id(cert_id: CertificateId) -> bytes:
    return codec.encode('CertificateId', codec._cert_id(cert_id))


def decode_certificate_id(data: bytes, offset: int):
    value, enc = _decode_canonical('CertificateId', data, offset)
    return codec._cert_id_from_asn(value), offset + len(enc)


def encode_verify_key_indicator(vk: PublicVerificationKey) -> bytes:
    return codec.encode('VerificationKeyIndicator', ('verificationKey', codec._verification_key(vk)))


def decode_verify_key_indicator(data: bytes, offset: int):
    value, enc = _decode_canonical('VerificationKeyIndicator', data, offset)
    name, vki = value
    if name == 'verificationKey':
        key_name, point = vki
        if key_name != 'ecdsaNistP256':
            raise ValueError(f"Unsupported verification key type: {key_name}")
        return PublicVerificationKey(PublicKeyAlgorithm.ECDSA_NIST_P256,
                                     codec._point_from_asn(point)), offset + len(enc)
    return codec._point_from_asn(vki), offset + len(enc)


# ── ToBeSignedCertificate / Certificate ──────────────────────────────────────

def encode_tbs_certificate(tbs: ToBeSignedCertificate,
                           version: EtsiVersion = EtsiVersion.V2_2_1) -> bytes:
    """
    ToBeSignedCertificate (IEEE 1609.2-2016 clause 6.4.8) as canonical COER.

    ``version`` is accepted for API compatibility only: v3 certificates are
    always encoded with the IEEE 1609.2-2016 schema that Vanetza uses.
    """
    return codec.encode(codec.TBS_TYPE, codec.tbs_to_asn(tbs))


def decode_tbs_certificate(data: bytes, offset: int,
                           version: EtsiVersion = EtsiVersion.V2_2_1):
    value, enc = _decode_canonical(codec.TBS_TYPE, data, offset)
    return codec.tbs_from_asn(value), offset + len(enc)


def encode_certificate(cert: Certificate,
                       version: EtsiVersion = EtsiVersion.V2_2_1) -> bytes:
    """EtsiTs103097Certificate (TS 103 097 v1.3.1 clause 6) as canonical COER."""
    return codec.encode(codec.CERTIFICATE_TYPE, codec.certificate_to_asn(cert))


def decode_certificate(data: bytes, offset: int = 0,
                       version: EtsiVersion = EtsiVersion.V2_2_1):
    """
    Decode an EtsiTs103097Certificate from COER bytes. Returns (cert, offset).

    Populates ``cert.encoded`` (exact certificate bytes, used for HashedId8 and
    as issuer input when verifying subordinate certificates) and
    ``cert.tbs_encoded`` (canonical COER of toBeSigned, used for verification).
    """
    value, enc = _decode_canonical(codec.CERTIFICATE_TYPE, data, offset)
    cert = codec.certificate_from_asn(value)
    cert.encoded = enc
    cert.tbs_encoded = codec.encode(codec.TBS_TYPE, value['toBeSigned'])
    return cert, offset + len(enc)
