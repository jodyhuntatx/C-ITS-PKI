"""
COER encoding and decoding for IEEE 1609.2 / ETSI TS 103 097 certificate structures.

Implements the canonical encoding of all certificate-level data structures
per ITU-T X.696 (COER) and IEEE Std 1609.2-2025 Annex B.

Sub-modules
-----------
keys        — ECC points, public keys (verification + encryption), signatures
permissions — PSID variable-length encoding, PsidSsp, PsidGroupPermissions
certificate — Duration, ValidityPeriod, GeographicRegion, IssuerIdentifier,
              CertificateId, VerifyKeyIndicator, ToBeSignedCertificate,
              Certificate
"""

from .keys import (
    encode_ecc_p256_point, decode_ecc_p256_point,
    encode_ecc_p384_point, decode_ecc_p384_point,
    encode_public_verification_key, decode_public_verification_key,
    encode_public_encryption_key, decode_public_encryption_key,
    encode_signature, decode_signature,
)
from .permissions import (
    encode_psid, decode_psid,
    encode_psid_ssp, encode_seq_of_psid_ssp,
    encode_psid_group_permissions, encode_seq_of_psid_group_permissions,
)
from .certificate import (
    encode_duration, decode_duration,
    encode_validity_period, decode_validity_period,
    encode_geographic_region, decode_geographic_region,
    encode_issuer_identifier, decode_issuer_identifier,
    encode_certificate_id, decode_certificate_id,
    encode_verify_key_indicator, decode_verify_key_indicator,
    encode_tbs_certificate, decode_tbs_certificate,
    encode_certificate, decode_certificate,
)

__all__ = [
    # keys
    'encode_ecc_p256_point', 'decode_ecc_p256_point',
    'encode_ecc_p384_point', 'decode_ecc_p384_point',
    'encode_public_verification_key', 'decode_public_verification_key',
    'encode_public_encryption_key', 'decode_public_encryption_key',
    'encode_signature', 'decode_signature',
    # permissions
    'encode_psid', 'decode_psid',
    'encode_psid_ssp', 'encode_seq_of_psid_ssp',
    'encode_psid_group_permissions', 'encode_seq_of_psid_group_permissions',
    # certificate
    'encode_duration', 'decode_duration',
    'encode_validity_period', 'decode_validity_period',
    'encode_geographic_region', 'decode_geographic_region',
    'encode_issuer_identifier', 'decode_issuer_identifier',
    'encode_certificate_id', 'decode_certificate_id',
    'encode_verify_key_indicator', 'decode_verify_key_indicator',
    'encode_tbs_certificate', 'decode_tbs_certificate',
    'encode_certificate', 'decode_certificate',
]
