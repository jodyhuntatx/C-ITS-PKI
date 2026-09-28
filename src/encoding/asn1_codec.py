"""
Standards-conformant COER codec for v3 (IEEE 1609.2 / ETSI TS 103 097) certificates.

Certificates are encoded with asn1tools against the exact ASN.1 modules that
Vanetza-NAP compiles for its v3 security layer (see src/asn1/README.md), so the
output is byte-compatible with Vanetza's asn1c decoder:

  - IEEE 1609.2-2016 schema (IEEE1609dot2, IEEE1609dot2BaseTypes)
  - ETSI TS 103 097 v1.3.1 profile (EtsiTs103097Certificate)

This module only converts between the dataclasses in src.types and the asn1tools
value model (dicts for SEQUENCE, (name, value) tuples for CHOICE).  COER
canonical rules that asn1tools does not enforce by itself are applied here:
DEFAULT-valued fields are omitted and public key points are always compressed.

Schema limitations (IEEE 1609.2-2016): NIST P-384 is not a valid verification
or encryption key type, only NIST P-256 (and Brainpool) are.
"""
from functools import lru_cache
from pathlib import Path

import asn1tools

from ..types import (
    Certificate, ToBeSignedCertificate, IssuerIdentifier, CertificateId,
    ValidityPeriod, Duration, GeographicRegion, SubjectAssurance,
    PsidSsp, PsidGroupPermissions, PublicVerificationKey, PublicEncryptionKey,
    EcdsaSignature, EccPoint,
    CertificateType, IssuerChoice, CertIdChoice, DurationChoice, RegionChoice,
    PublicKeyAlgorithm, HashAlgorithm,
)

_ASN1_DIR = Path(__file__).resolve().parent.parent / 'asn1'
_ASN1_FILES = ['IEEE1609dot2BaseTypes.asn', 'IEEE1609dot2.asn', 'TS103097v131.asn']

CERTIFICATE_TYPE = 'EtsiTs103097Certificate'
TBS_TYPE = 'ToBeSignedCertificate'


@lru_cache(maxsize=1)
def compiled():
    """Compile the vendored ASN.1 modules once (COER = OER with canonical values)."""
    return asn1tools.compile_files([str(_ASN1_DIR / f) for f in _ASN1_FILES], 'oer')


def encode(type_name: str, value) -> bytes:
    return compiled().encode(type_name, value)


def decode(type_name: str, data: bytes):
    return compiled().decode(type_name, data)


# ── Name tables (dataclass enum ↔ ASN.1 identifier) ──────────────────────────

_DURATION = {
    DurationChoice.MICROSECONDS: 'microseconds',
    DurationChoice.MILLISECONDS: 'milliseconds',
    DurationChoice.SECONDS: 'seconds',
    DurationChoice.MINUTES: 'minutes',
    DurationChoice.HOURS: 'hours',
    DurationChoice.SIXTY_HOURS: 'sixtyHours',
    DurationChoice.YEARS: 'years',
}
_DURATION_REV = {v: k for k, v in _DURATION.items()}

_HASH_ALG = {HashAlgorithm.SHA256: 'sha256', HashAlgorithm.SHA384: 'sha384'}
_HASH_ALG_REV = {v: k for k, v in _HASH_ALG.items()}

# PsidGroupPermissions DEFAULT values (IEEE 1609.2-2016 clause 6.4.28)
_DEFAULT_MIN_CHAIN_LENGTH = 1
_DEFAULT_CHAIN_LENGTH_RANGE = 0
_DEFAULT_EE_TYPE = 0x00


# ── ECC points and keys ──────────────────────────────────────────────────────

def _p256_point(point: EccPoint):
    if point.curve != 'P-256':
        raise ValueError(
            "v3 certificates (IEEE 1609.2-2016 / TS 103 097 v1.3.1) only support NIST P-256 keys; "
            f"got {point.curve}. Use --algo p256 with --etsi-version v3.")
    name = 'compressed-y-0' if point.y_parity == 0 else 'compressed-y-1'
    return (name, point.compressed[1:])


def _point_from_asn(value, curve: str = 'P-256') -> EccPoint:
    name, data = value
    if name in ('compressed-y-0', 'compressed-y-1'):
        parity = 0 if name == 'compressed-y-0' else 1
        return EccPoint(curve=curve, compressed=bytes([0x02 + parity]) + data, y_parity=parity)
    if name == 'uncompressedP256':
        x, y = data['x'], data['y']
        parity = y[-1] & 1
        return EccPoint(curve=curve, compressed=bytes([0x02 + parity]) + x, y_parity=parity)
    raise ValueError(f"Unsupported EccP256CurvePoint alternative in key: {name}")


def _verification_key(vk: PublicVerificationKey):
    if vk.algorithm != PublicKeyAlgorithm.ECDSA_NIST_P256:
        raise ValueError("v3 certificates only support ecdsaNistP256 verification keys")
    return ('ecdsaNistP256', _p256_point(vk.point))


def _encryption_key(ek: PublicEncryptionKey):
    if ek.algorithm != PublicKeyAlgorithm.ECIES_NIST_P256:
        raise ValueError("v3 certificates only support eciesNistP256 encryption keys")
    return {'supportedSymmAlg': 'aes128Ccm', 'publicKey': ('eciesNistP256', _p256_point(ek.point))}


def _signature(sig: EcdsaSignature):
    if sig.algorithm != PublicKeyAlgorithm.ECDSA_NIST_P256:
        raise ValueError("v3 certificates only support ecdsaNistP256Signature")
    return ('ecdsaNistP256Signature', {'rSig': ('x-only', sig.r), 'sSig': sig.s})


def _signature_from_asn(value) -> EcdsaSignature:
    name, sig = value
    if name != 'ecdsaNistP256Signature':
        raise ValueError(f"Unsupported signature type: {name}")
    r_name, r = sig['rSig']
    if r_name not in ('x-only', 'compressed-y-0', 'compressed-y-1'):
        raise ValueError(f"Unsupported rSig alternative: {r_name}")
    return EcdsaSignature(r=r, s=sig['sSig'], algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256)


# ── Permissions ──────────────────────────────────────────────────────────────

def _psid_ssp(ps: PsidSsp):
    value = {'psid': int(ps.psid)}
    if ps.ssp is not None:
        value['ssp'] = ('opaque', bytes(ps.ssp))
    return value


def _psid_ssp_from_asn(value) -> PsidSsp:
    ssp = None
    if 'ssp' in value:
        name, data = value['ssp']
        ssp = data if name == 'opaque' else None
    return PsidSsp(psid=value['psid'], ssp=ssp)


def _group_permissions(pgp: PsidGroupPermissions):
    # subjectPermissions = all; explicit PSID ranges are not modelled by the tool
    value = {'subjectPermissions': ('all', None)}
    # COER: DEFAULT-valued components must be absent
    if pgp.min_chain_depth != _DEFAULT_MIN_CHAIN_LENGTH:
        value['minChainLength'] = pgp.min_chain_depth
    if pgp.chain_depth_range != _DEFAULT_CHAIN_LENGTH_RANGE:
        value['chainLengthRange'] = pgp.chain_depth_range
    ee_type = pgp.ee_type or 0
    if ee_type != _DEFAULT_EE_TYPE:
        value['eeType'] = (bytes([ee_type]), 8)
    return value


def _group_permissions_from_asn(value) -> PsidGroupPermissions:
    ee = value.get('eeType')
    return PsidGroupPermissions(
        min_chain_depth=value.get('minChainLength', _DEFAULT_MIN_CHAIN_LENGTH),
        chain_depth_range=value.get('chainLengthRange', _DEFAULT_CHAIN_LENGTH_RANGE),
        ee_type=ee[0][0] if ee else _DEFAULT_EE_TYPE,
    )


# ── Region ───────────────────────────────────────────────────────────────────

def _region(region: GeographicRegion):
    if region.choice != RegionChoice.ID or not region.ids:
        raise ValueError("Only identifiedRegion with country IDs is supported")
    return ('identifiedRegion', [('countryOnly', int(cid)) for cid in region.ids])


def _region_from_asn(value) -> GeographicRegion:
    name, regions = value
    if name != 'identifiedRegion':
        raise ValueError(f"Unsupported GeographicRegion alternative: {name}")
    ids = [data for alt, data in regions if alt == 'countryOnly']
    return GeographicRegion(choice=RegionChoice.ID, ids=ids)


# ── Duration / validity ──────────────────────────────────────────────────────

def duration_to_asn(d: Duration):
    return (_DURATION[DurationChoice(d.choice)], d.value)


def duration_from_asn(value) -> Duration:
    name, v = value
    return Duration(_DURATION_REV[name], v)


# ── Issuer / id ──────────────────────────────────────────────────────────────

def _issuer(issuer: IssuerIdentifier):
    if issuer.choice == IssuerChoice.SELF:
        return ('self', _HASH_ALG[HashAlgorithm(issuer.hash_alg)])
    if issuer.choice == IssuerChoice.SHA256_AND_DIGEST:
        return ('sha256AndDigest', bytes(issuer.digest))
    if issuer.choice == IssuerChoice.SHA384_AND_DIGEST:
        return ('sha384AndDigest', bytes(issuer.digest))
    raise ValueError(f"Unknown IssuerIdentifier choice: {issuer.choice}")


def _issuer_from_asn(value) -> IssuerIdentifier:
    name, data = value
    if name == 'self':
        return IssuerIdentifier(IssuerChoice.SELF, hash_alg=_HASH_ALG_REV[data])
    if name == 'sha256AndDigest':
        return IssuerIdentifier(IssuerChoice.SHA256_AND_DIGEST, digest=data)
    if name == 'sha384AndDigest':
        return IssuerIdentifier(IssuerChoice.SHA384_AND_DIGEST, digest=data)
    raise ValueError(f"Unsupported IssuerIdentifier alternative: {name}")


def _cert_id(cert_id: CertificateId):
    if cert_id.choice == CertIdChoice.NAME:
        return ('name', cert_id.name)
    if cert_id.choice == CertIdChoice.NONE:
        return ('none', None)
    raise ValueError(f"CertificateId {cert_id.choice!r} is not allowed by TS 103 097")


def _cert_id_from_asn(value) -> CertificateId:
    name, data = value
    if name == 'name':
        return CertificateId(CertIdChoice.NAME, name=data)
    if name == 'none':
        return CertificateId(CertIdChoice.NONE)
    raise ValueError(f"Unsupported CertificateId alternative: {name}")


# ── ToBeSignedCertificate / Certificate ──────────────────────────────────────

def tbs_to_asn(tbs: ToBeSignedCertificate) -> dict:
    if tbs.verify_key_indicator is None:
        raise ValueError("verifyKeyIndicator is required for explicit certificates")
    value = {
        'id': _cert_id(tbs.id),
        'cracaId': bytes(tbs.craca_id),
        'crlSeries': tbs.crl_series,
        'validityPeriod': {
            'start': tbs.validity_period.start,
            'duration': duration_to_asn(tbs.validity_period.duration),
        },
        'verifyKeyIndicator': ('verificationKey', _verification_key(tbs.verify_key_indicator)),
    }
    if tbs.region is not None:
        value['region'] = _region(tbs.region)
    if tbs.assurance_level is not None:
        level = tbs.assurance_level
        value['assuranceLevel'] = bytes([((level.level & 0x7) << 5) | (level.confidence & 0x03)])
    if tbs.app_permissions:
        value['appPermissions'] = [_psid_ssp(p) for p in tbs.app_permissions]
    if tbs.cert_issue_permissions:
        value['certIssuePermissions'] = [_group_permissions(p) for p in tbs.cert_issue_permissions]
    if tbs.encryption_key is not None:
        value['encryptionKey'] = _encryption_key(tbs.encryption_key)
    return value


def tbs_from_asn(value: dict) -> ToBeSignedCertificate:
    vp = value['validityPeriod']
    vki_name, vki = value['verifyKeyIndicator']
    verify_key = reconstruction = None
    if vki_name == 'verificationKey':
        key_name, point = vki
        if key_name != 'ecdsaNistP256':
            raise ValueError(f"Unsupported verification key type: {key_name}")
        verify_key = PublicVerificationKey(PublicKeyAlgorithm.ECDSA_NIST_P256, _point_from_asn(point))
    else:
        reconstruction = _point_from_asn(vki)

    assurance = None
    if 'assuranceLevel' in value:
        b = value['assuranceLevel'][0]
        assurance = SubjectAssurance(level=(b >> 5) & 0x7, confidence=b & 0x03)

    enc_key = None
    if 'encryptionKey' in value:
        key_name, point = value['encryptionKey']['publicKey']
        if key_name != 'eciesNistP256':
            raise ValueError(f"Unsupported encryption key type: {key_name}")
        enc_key = PublicEncryptionKey(PublicKeyAlgorithm.ECIES_NIST_P256, _point_from_asn(point))

    return ToBeSignedCertificate(
        id=_cert_id_from_asn(value['id']),
        craca_id=value['cracaId'],
        crl_series=value['crlSeries'],
        validity_period=ValidityPeriod(start=vp['start'], duration=duration_from_asn(vp['duration'])),
        region=_region_from_asn(value['region']) if 'region' in value else None,
        assurance_level=assurance,
        app_permissions=[_psid_ssp_from_asn(p) for p in value['appPermissions']]
            if 'appPermissions' in value else None,
        cert_issue_permissions=[_group_permissions_from_asn(p) for p in value['certIssuePermissions']]
            if 'certIssuePermissions' in value else None,
        encryption_key=enc_key,
        verify_key_indicator=verify_key,
        reconstruction_value=reconstruction,
    )


def certificate_to_asn(cert: Certificate) -> dict:
    value = {
        'version': cert.version,
        'type': 'explicit' if cert.cert_type == CertificateType.EXPLICIT else 'implicit',
        'issuer': _issuer(cert.issuer),
        'toBeSigned': tbs_to_asn(cert.tbs),
    }
    if cert.signature is not None:
        value['signature'] = _signature(cert.signature)
    return value


def certificate_from_asn(value: dict) -> Certificate:
    return Certificate(
        version=value['version'],
        cert_type=CertificateType.EXPLICIT if value['type'] == 'explicit' else CertificateType.IMPLICIT,
        issuer=_issuer_from_asn(value['issuer']),
        tbs=tbs_from_asn(value['toBeSigned']),
        signature=_signature_from_asn(value['signature']) if 'signature' in value else None,
    )
