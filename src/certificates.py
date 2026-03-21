"""
Certificate issuance for C-ITS PKI entities.
Implements security profiles from ETSI TS 103 097 V2.2.1 clause 7.2.
"""
import time
from typing import Optional

from .types import (
    Certificate, ToBeSignedCertificate, IssuerIdentifier, CertificateId,
    ValidityPeriod, Duration, GeographicRegion, SubjectAssurance,
    PsidSsp, PsidGroupPermissions, PublicVerificationKey, PublicEncryptionKey,
    EcdsaSignature, CertificateType, IssuerChoice, CertIdChoice,
    DurationChoice, RegionChoice, PublicKeyAlgorithm, HashAlgorithm, ItsAid,
    unix_to_its_time32
)
from .encoding import encode_certificate, encode_tbs_certificate
from .crypto import (
    generate_keypair, ecdsa_sign, hash_certificate, public_key_to_point
)


# ── Constants (ETSI TS 103 097 V2.2.1 clause 8.1) ────────────────────────────

CRACA_ID  = b'\x00\x00\x00'    # cracaId = 000000H (FR-CI-10)
CRL_SERIES = 0                  # crlSeries = 0 (FR-CI-10)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _all_permissions() -> list:
    """
    PsidGroupPermissions granting all PSIDs to all end-entity types.
    subjectPermissions = all, minChainDepth=0, chainDepthRange=0, eeType={app, enrol}.
    """
    return [PsidGroupPermissions(min_chain_depth=0, chain_depth_range=0, ee_type=0x60)]


def _make_validity_period(start_unix: float,
                           duration_years: int = 0,
                           duration_hours: int = 0,
                           duration_seconds: int = 0) -> ValidityPeriod:
    start = unix_to_its_time32(start_unix)
    if duration_years > 0:
        return ValidityPeriod(start=start, duration=Duration(DurationChoice.YEARS, duration_years))
    elif duration_hours > 0:
        return ValidityPeriod(start=start, duration=Duration(DurationChoice.HOURS, duration_hours))
    else:
        return ValidityPeriod(start=start, duration=Duration(DurationChoice.SECONDS, max(1, duration_seconds)))


def _build_and_sign(tbs: ToBeSignedCertificate,
                    cert_type: CertificateType,
                    issuer: IssuerIdentifier,
                    signing_priv_key,
                    algorithm: PublicKeyAlgorithm) -> Certificate:
    """
    Encode the ToBeSignedCertificate, sign it, build the full Certificate,
    and cache both tbs_encoded and the full COER-encoded certificate.
    """
    # Encode TBS
    tbs_encoded = encode_tbs_certificate(tbs)

    # ECDSA sign the TBS encoding
    r, s = ecdsa_sign(signing_priv_key, tbs_encoded, algorithm)
    signature = EcdsaSignature(r=r, s=s, algorithm=algorithm)

    # Assemble Certificate
    cert = Certificate(
        version=3,
        cert_type=cert_type,
        issuer=issuer,
        tbs=tbs,
        signature=signature,
    )
    cert.tbs_encoded = tbs_encoded

    # Encode and cache the full certificate
    cert.encoded = encode_certificate(cert)
    return cert


# ── Profile 9.1 — Root CA Certificate ────────────────────────────────────────

def issue_root_ca_certificate(
    name: str,
    sign_priv_key,
    sign_pub_key,
    algorithm:       PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    validity_years:  int = 10,
    region_ids:      Optional[list] = None,
    start_time:      Optional[float] = None,
) -> Certificate:
    """
    Self-signed Root CA certificate per ETSI TS 103 097 V2.2.1 profile 9.1.

    Constraints:
      - issuer = self
      - certIssuePermissions: present (all)
      - appPermissions: present (CRL + CTL ITS-AIDs)
      - encryptionKey: absent
      - CertificateId = name
    """
    t = start_time or time.time()
    vp = _make_validity_period(t, duration_years=validity_years)
    vk = PublicVerificationKey(algorithm=algorithm, point=public_key_to_point(sign_pub_key))

    region = GeographicRegion(choice=RegionChoice.ID, ids=region_ids) if region_ids else None

    tbs = ToBeSignedCertificate(
        id=CertificateId(CertIdChoice.NAME, name=name),
        craca_id=CRACA_ID,
        crl_series=CRL_SERIES,
        validity_period=vp,
        region=region,
        app_permissions=[
            PsidSsp(psid=int(ItsAid.CRL)),
            PsidSsp(psid=int(ItsAid.CTL)),
        ],
        cert_issue_permissions=_all_permissions(),
        encryption_key=None,
        verify_key_indicator=vk,
    )

    hash_alg = HashAlgorithm.SHA256 if algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256 \
        else HashAlgorithm.SHA384
    issuer = IssuerIdentifier(choice=IssuerChoice.SELF, hash_alg=hash_alg)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, sign_priv_key, algorithm)


# ── Profile 9.2 — Enrolment Authority (EA) Certificate ───────────────────────

def issue_ea_certificate(
    name: str,
    ea_sign_priv_key, ea_sign_pub_key,
    ea_enc_pub_key,
    root_ca_cert: Certificate,
    root_ca_priv_key,
    sign_algorithm:  PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    enc_algorithm:   PublicKeyAlgorithm = PublicKeyAlgorithm.ECIES_NIST_P256,
    validity_years:  int = 5,
    region_ids:      Optional[list] = None,
    start_time:      Optional[float] = None,
) -> Certificate:
    """
    EA subordinate CA certificate per ETSI TS 103 097 V2.2.1 profile 9.2.

    Constraints:
      - issuer = sha256AndDigest/sha384AndDigest of Root CA
      - certIssuePermissions: present
      - appPermissions: present (cert request signing)
      - encryptionKey: present
    """
    t = start_time or time.time()
    vp = _make_validity_period(t, duration_years=validity_years)
    vk = PublicVerificationKey(algorithm=sign_algorithm, point=public_key_to_point(ea_sign_pub_key))
    ek = PublicEncryptionKey(algorithm=enc_algorithm, point=public_key_to_point(ea_enc_pub_key))

    region = GeographicRegion(choice=RegionChoice.ID, ids=region_ids) if region_ids else None

    tbs = ToBeSignedCertificate(
        id=CertificateId(CertIdChoice.NAME, name=name),
        craca_id=CRACA_ID,
        crl_series=CRL_SERIES,
        validity_period=vp,
        region=region,
        app_permissions=[PsidSsp(psid=int(ItsAid.CERT_REQUEST))],
        cert_issue_permissions=_all_permissions(),
        encryption_key=ek,
        verify_key_indicator=vk,
    )

    root_hash = hash_certificate(root_ca_cert.encoded, sign_algorithm)
    if sign_algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA256_AND_DIGEST, digest=root_hash)
    else:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA384_AND_DIGEST, digest=root_hash)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, root_ca_priv_key, sign_algorithm)


# ── Profile 9.3 — Authorization Authority (AA) Certificate ───────────────────

def issue_aa_certificate(
    name: str,
    aa_sign_priv_key, aa_sign_pub_key,
    aa_enc_pub_key,
    root_ca_cert: Certificate,
    root_ca_priv_key,
    sign_algorithm:  PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    enc_algorithm:   PublicKeyAlgorithm = PublicKeyAlgorithm.ECIES_NIST_P256,
    validity_years:  int = 5,
    region_ids:      Optional[list] = None,
    start_time:      Optional[float] = None,
) -> Certificate:
    """
    AA subordinate CA certificate per ETSI TS 103 097 V2.2.1 profile 9.3.

    Constraints:
      - issuer = digest of Root CA
      - certIssuePermissions: present (AT signing)
      - appPermissions: present (cert response signing)
      - encryptionKey: present
    """
    t = start_time or time.time()
    vp = _make_validity_period(t, duration_years=validity_years)
    vk = PublicVerificationKey(algorithm=sign_algorithm, point=public_key_to_point(aa_sign_pub_key))
    ek = PublicEncryptionKey(algorithm=enc_algorithm, point=public_key_to_point(aa_enc_pub_key))

    region = GeographicRegion(choice=RegionChoice.ID, ids=region_ids) if region_ids else None

    tbs = ToBeSignedCertificate(
        id=CertificateId(CertIdChoice.NAME, name=name),
        craca_id=CRACA_ID,
        crl_series=CRL_SERIES,
        validity_period=vp,
        region=region,
        app_permissions=[PsidSsp(psid=int(ItsAid.CERT_REQUEST))],
        cert_issue_permissions=_all_permissions(),
        encryption_key=ek,
        verify_key_indicator=vk,
    )

    root_hash = hash_certificate(root_ca_cert.encoded, sign_algorithm)
    if sign_algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA256_AND_DIGEST, digest=root_hash)
    else:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA384_AND_DIGEST, digest=root_hash)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, root_ca_priv_key, sign_algorithm)


# ── Profile 9.4 — Trust List Manager (TLM) Certificate ───────────────────────

def issue_tlm_certificate(
    name: str,
    tlm_sign_priv_key, tlm_sign_pub_key,
    algorithm:       PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    validity_years:  int = 10,
    start_time:      Optional[float] = None,
) -> Certificate:
    """
    Self-signed TLM certificate per ETSI TS 103 097 V2.2.1 profile 9.4.

    Constraints:
      - issuer = self
      - appPermissions: CTL ITS-AID only
      - encryptionKey: absent
      - certIssuePermissions: absent
    """
    t = start_time or time.time()
    vp = _make_validity_period(t, duration_years=validity_years)
    vk = PublicVerificationKey(algorithm=algorithm, point=public_key_to_point(tlm_sign_pub_key))

    tbs = ToBeSignedCertificate(
        id=CertificateId(CertIdChoice.NAME, name=name),
        craca_id=CRACA_ID,
        crl_series=CRL_SERIES,
        validity_period=vp,
        app_permissions=[PsidSsp(psid=int(ItsAid.CTL))],
        cert_issue_permissions=None,
        encryption_key=None,
        verify_key_indicator=vk,
    )

    hash_alg = HashAlgorithm.SHA256 if algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256 \
        else HashAlgorithm.SHA384
    issuer = IssuerIdentifier(choice=IssuerChoice.SELF, hash_alg=hash_alg)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, tlm_sign_priv_key, algorithm)


# ── Profile 9.5 — Enrolment Credential (EC) ──────────────────────────────────

def issue_enrolment_credential(
    name: str,
    its_sign_priv_key, its_sign_pub_key,
    ea_cert: Certificate,
    ea_priv_key,
    sign_algorithm:  PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    validity_years:  int = 1,
    region_ids:      Optional[list] = None,
    start_time:      Optional[float] = None,
) -> Certificate:
    """
    Enrolment Credential per ETSI TS 103 097 V2.2.1 profile 9.5.

    Constraints:
      - issuer = digest of EA certificate
      - CertificateId = name
      - appPermissions: cert request message signing (CERT_REQUEST ITS-AID)
      - certIssuePermissions: absent
      - Long-term identity credential; used to obtain ATs
    """
    t = start_time or time.time()
    vp = _make_validity_period(t, duration_years=validity_years)
    vk = PublicVerificationKey(algorithm=sign_algorithm, point=public_key_to_point(its_sign_pub_key))

    region = GeographicRegion(choice=RegionChoice.ID, ids=region_ids) if region_ids else None

    tbs = ToBeSignedCertificate(
        id=CertificateId(CertIdChoice.NAME, name=name),
        craca_id=CRACA_ID,
        crl_series=CRL_SERIES,
        validity_period=vp,
        region=region,
        app_permissions=[PsidSsp(psid=int(ItsAid.CERT_REQUEST))],
        cert_issue_permissions=None,
        encryption_key=None,
        verify_key_indicator=vk,
    )

    ea_hash = hash_certificate(ea_cert.encoded, sign_algorithm)
    if sign_algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA256_AND_DIGEST, digest=ea_hash)
    else:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA384_AND_DIGEST, digest=ea_hash)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, ea_priv_key, sign_algorithm)


# ── Profile 9.6 — Authorization Ticket (AT) ──────────────────────────────────

def issue_authorization_ticket(
    its_sign_priv_key, its_sign_pub_key,
    aa_cert: Certificate,
    aa_priv_key,
    app_psids:       Optional[list] = None,
    sign_algorithm:  PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    validity_hours:  int = 168,   # 1 week
    region_ids:      Optional[list] = None,
    start_time:      Optional[float] = None,
) -> Certificate:
    """
    Authorization Ticket per ETSI TS 103 097 V2.2.1 profile 9.6.

    Constraints:
      - issuer = digest of AA certificate
      - CertificateId = none (pseudonymous — NFR-SEC-06)
      - appPermissions: present (V2X message signing)
      - certIssuePermissions: absent
      - Short-lived pseudonym certificate (default 1 week)
    """
    t = start_time or time.time()
    vp = _make_validity_period(t, duration_hours=validity_hours)
    vk = PublicVerificationKey(algorithm=sign_algorithm, point=public_key_to_point(its_sign_pub_key))

    region = GeographicRegion(choice=RegionChoice.ID, ids=region_ids) if region_ids else None

    psids = app_psids or [
        PsidSsp(psid=int(ItsAid.CAM)),
        PsidSsp(psid=int(ItsAid.DENM)),
    ]

    tbs = ToBeSignedCertificate(
        id=CertificateId(CertIdChoice.NONE),      # id = none (pseudonymous)
        craca_id=CRACA_ID,
        crl_series=CRL_SERIES,
        validity_period=vp,
        region=region,
        app_permissions=psids,
        cert_issue_permissions=None,              # AT must not have certIssuePermissions
        encryption_key=None,
        verify_key_indicator=vk,
    )

    aa_hash = hash_certificate(aa_cert.encoded, sign_algorithm)
    if sign_algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA256_AND_DIGEST, digest=aa_hash)
    else:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA384_AND_DIGEST, digest=aa_hash)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, aa_priv_key, sign_algorithm)
