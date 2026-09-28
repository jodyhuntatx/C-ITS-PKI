"""
Certificate issuance for C-ITS PKI entities.
Implements security profiles from ETSI TS 103 097 V2.2.1 (clause 9) and
ETSI TS 103 097 V1.2.1 (clause 7) / vanetza v2 format.
"""
import time
from typing import Optional

from .types import (
    Certificate, ToBeSignedCertificate, IssuerIdentifier, CertificateId,
    ValidityPeriod, Duration, GeographicRegion, SubjectAssurance,
    PsidSsp, PsidGroupPermissions, PublicVerificationKey, PublicEncryptionKey,
    EcdsaSignature, CertificateType, IssuerChoice, CertIdChoice,
    DurationChoice, RegionChoice, PublicKeyAlgorithm, HashAlgorithm, ItsAid,
    EtsiVersion, unix_to_its_time32, V1SubjectType
)
from .encoding import encode_certificate, encode_tbs_certificate
from .crypto import (
    generate_keypair, ecdsa_sign, hash_certificate, public_key_to_point,
    ieee1609_signing_input
)
from .v1_encoding import build_and_sign_v1, hash_certificate_v1


# ── Constants (ETSI TS 103 097 V2.2.1 clause 8.1) ────────────────────────────

CRACA_ID  = b'\x00\x00\x00'    # cracaId = 000000H (FR-CI-10)
CRL_SERIES = 0                  # crlSeries = 0 (FR-CI-10)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash_cert(cert, algorithm: PublicKeyAlgorithm, version: EtsiVersion) -> bytes:
    """
    Return the HashedId8 of a certificate, selecting the correct hash function
    based on encoding format.
    V1_2_1 (vanetza): always SHA-256, last 8 bytes of full encoded cert.
    V2_2_1 (COER):    SHA-256 or SHA-384 depending on algorithm, last 8 bytes.
    """
    if version == EtsiVersion.V1_2_1:
        return hash_certificate_v1(cert.encoded)
    return hash_certificate(cert.encoded, algorithm)


# EndEntityType ::= BIT STRING { app(0), enrol(1) } (SIZE(8)) -> bit 0 is the MSB
EE_TYPE_APP   = 0x80
EE_TYPE_ENROL = 0x40


def _all_permissions(min_chain_length: int, ee_type: int) -> list:
    """
    certIssuePermissions granting all PSIDs (subjectPermissions = all).
    min_chain_length: number of certificates below the issuer down to the end entity
    (Root CA -> EA/AA -> EC/AT = 2, EA/AA -> EC/AT = 1).
    ee_type: end-entity types the issued chain may end in (EE_TYPE_* bits).
    """
    return [PsidGroupPermissions(min_chain_depth=min_chain_length, chain_depth_range=0, ee_type=ee_type)]


# ── Vanetza v2 ITS-AID lists for CA certificates ─────────────────────────────
# Vanetza v2 requires every certificate's ITS-AID list to be a subset of its
# signer's list (check_permission_consistency), so CA certificates must list the
# AIDs of everything they issue. v3 expresses the same with certIssuePermissions.

V2_AA_AIDS = [ItsAid.CAM, ItsAid.DENM, ItsAid.GN_MGMT, ItsAid.CERT_REQUEST]
V2_EA_AIDS = [ItsAid.CERT_REQUEST]
V2_ROOT_AIDS = [ItsAid.CRL, ItsAid.CTL] + [a for a in V2_AA_AIDS + V2_EA_AIDS
                                           if a not in (ItsAid.CRL, ItsAid.CTL)]


def _v2_aid_list(aids) -> list:
    seen = []
    for aid in aids:
        if int(aid) not in seen:
            seen.append(int(aid))
    return [PsidSsp(psid=aid) for aid in seen]


def _check_v2_at_psids(psids: list) -> None:
    allowed = {int(a) for a in V2_AA_AIDS}
    extra = sorted({int(p.psid) for p in psids} - allowed)
    if extra:
        raise ValueError(
            f"ITS-AIDs {extra} are not in the v2 AA certificate's ITS-AID list {sorted(allowed)}; "
            "Vanetza v2 would reject the AT (permissions must be a subset of the signer's).")


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
                    algorithm: PublicKeyAlgorithm,
                    version: EtsiVersion = EtsiVersion.V1_2_1,
                    subject_type: int = V1SubjectType.ROOT_CA,
                    psids=None,
                    issuer_cert: Optional[Certificate] = None) -> Certificate:
    """
    Encode the ToBeSignedCertificate, sign it, build the full Certificate,
    and cache both tbs_encoded and the full encoded certificate.

    ``version`` selects the encoding format:
      V1_2_1 → vanetza-compatible binary format (ETSI TS 103 097 V1.2.1 / vanetza v2)
      V2_2_1 → COER format (ETSI TS 103 097 V2.2.1 / IEEE 1609.2-2022)

    ``subject_type`` is only used for V1_2_1 (vanetza SubjectType enum value).
    ``psids``        is only used for V1_2_1 (overrides tbs.app_permissions).
    ``issuer_cert``  is the signing CA certificate (None for self-signed); for
                     V2_2_1 its encoding is part of the IEEE 1609.2 signing input.
    """
    if version == EtsiVersion.V1_2_1:
        # Vanetza-compatible binary format
        return build_and_sign_v1(
            tbs=tbs,
            issuer=issuer,
            sign_priv_key=signing_priv_key,
            algorithm=algorithm,
            subject_type=subject_type,
            psids=psids,
        )
    else:
        # COER format (IEEE 1609.2-2016 / TS 103 097 v1.3.1, vanetza v3)
        tbs_encoded = encode_tbs_certificate(tbs, version=version)

        # IEEE 1609.2 clause 5.3.1.2.2: sign Hash(Hash(tbs) || Hash(issuer cert)),
        # with the empty string as issuer input for self-signed certificates
        if issuer.choice == IssuerChoice.SELF:
            signer_encoded = b''
        elif issuer_cert is not None:
            signer_encoded = issuer_cert.encoded
        else:
            raise ValueError("issuer_cert is required for certificates that are not self-signed")
        signing_input = ieee1609_signing_input(tbs_encoded, signer_encoded, algorithm)
        r, s = ecdsa_sign(signing_priv_key, signing_input, algorithm)
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

        # Encode and cache the full COER certificate
        cert.encoded = encode_certificate(cert, version=version)
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
    version:         EtsiVersion = EtsiVersion.V1_2_1,
) -> Certificate:
    """
    Self-signed Root CA certificate.

    V2.2.1: profile 9.1  (ETSI TS 103 097 V2.2.1)
    V1.2.1: profile 7.1  (ETSI TS 103 097 V1.2.1)

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
        cert_issue_permissions=_all_permissions(2, EE_TYPE_APP | EE_TYPE_ENROL),
        encryption_key=None,
        verify_key_indicator=vk,
    )

    hash_alg = HashAlgorithm.SHA256 if algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256 \
        else HashAlgorithm.SHA384
    issuer = IssuerIdentifier(choice=IssuerChoice.SELF, hash_alg=hash_alg)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, sign_priv_key, algorithm,
                           version=version, subject_type=V1SubjectType.ROOT_CA,
                           psids=_v2_aid_list(V2_ROOT_AIDS))


# ── Profile 9.2 / 7.2 — Enrolment Authority (EA) Certificate ─────────────────

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
    version:         EtsiVersion = EtsiVersion.V1_2_1,
) -> Certificate:
    """
    EA subordinate CA certificate.

    V2.2.1: profile 9.2  (ETSI TS 103 097 V2.2.1)
    V1.2.1: profile 7.2  (ETSI TS 103 097 V1.2.1)

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
        cert_issue_permissions=_all_permissions(1, EE_TYPE_ENROL),
        encryption_key=ek,
        verify_key_indicator=vk,
    )

    root_hash = _hash_cert(root_ca_cert, sign_algorithm, version)
    if sign_algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA256_AND_DIGEST, digest=root_hash)
    else:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA384_AND_DIGEST, digest=root_hash)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, root_ca_priv_key, sign_algorithm,
                           version=version, subject_type=V1SubjectType.ENROLLMENT_AUTHORITY,
                           psids=_v2_aid_list(V2_EA_AIDS), issuer_cert=root_ca_cert)


# ── Profile 9.3 / 7.3 — Authorization Authority (AA) Certificate ─────────────

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
    version:         EtsiVersion = EtsiVersion.V1_2_1,
) -> Certificate:
    """
    AA subordinate CA certificate.

    V2.2.1: profile 9.3  (ETSI TS 103 097 V2.2.1)
    V1.2.1: profile 7.3  (ETSI TS 103 097 V1.2.1)

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
        cert_issue_permissions=_all_permissions(1, EE_TYPE_APP),
        encryption_key=ek,
        verify_key_indicator=vk,
    )

    root_hash = _hash_cert(root_ca_cert, sign_algorithm, version)
    if sign_algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA256_AND_DIGEST, digest=root_hash)
    else:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA384_AND_DIGEST, digest=root_hash)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, root_ca_priv_key, sign_algorithm,
                           version=version, subject_type=V1SubjectType.AUTHORIZATION_AUTHORITY,
                           psids=_v2_aid_list(V2_AA_AIDS), issuer_cert=root_ca_cert)


# ── Profile 9.4 / 7.4 — Trust List Manager (TLM) Certificate ─────────────────

def issue_tlm_certificate(
    name: str,
    tlm_sign_priv_key, tlm_sign_pub_key,
    algorithm:       PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    validity_years:  int = 10,
    start_time:      Optional[float] = None,
    version:         EtsiVersion = EtsiVersion.V1_2_1,
) -> Certificate:
    """
    Self-signed TLM certificate.

    V2.2.1: profile 9.4  (ETSI TS 103 097 V2.2.1)
    V1.2.1: profile 7.4  (ETSI TS 103 097 V1.2.1)

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

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, tlm_sign_priv_key, algorithm,
                           version=version, subject_type=V1SubjectType.ROOT_CA)


# ── Profile 9.5 / 7.5 — Enrolment Credential (EC) ───────────────────────────

def issue_enrolment_credential(
    name: str,
    its_sign_priv_key, its_sign_pub_key,
    ea_cert: Certificate,
    ea_priv_key,
    sign_algorithm:  PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    validity_years:  int = 1,
    region_ids:      Optional[list] = None,
    start_time:      Optional[float] = None,
    version:         EtsiVersion = EtsiVersion.V1_2_1,
) -> Certificate:
    """
    Enrolment Credential.

    V2.2.1: profile 9.5  (ETSI TS 103 097 V2.2.1)
    V1.2.1: profile 7.5  (ETSI TS 103 097 V1.2.1)

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

    ea_hash = _hash_cert(ea_cert, sign_algorithm, version)
    if sign_algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA256_AND_DIGEST, digest=ea_hash)
    else:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA384_AND_DIGEST, digest=ea_hash)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, ea_priv_key, sign_algorithm,
                           version=version, subject_type=V1SubjectType.ENROLLMENT_CREDENTIAL,
                           issuer_cert=ea_cert)


# ── Profile 9.6 / 7.6 — Authorization Ticket (AT) ───────────────────────────

def issue_authorization_ticket(
    its_sign_priv_key, its_sign_pub_key,
    aa_cert: Certificate,
    aa_priv_key,
    app_psids:       Optional[list] = None,
    sign_algorithm:  PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    validity_hours:  int = 168,   # 1 week
    region_ids:      Optional[list] = None,
    start_time:      Optional[float] = None,
    version:         EtsiVersion = EtsiVersion.V1_2_1,
) -> Certificate:
    """
    Authorization Ticket.

    V2.2.1: profile 9.6  (ETSI TS 103 097 V2.2.1)
    V1.2.1: profile 7.6  (ETSI TS 103 097 V1.2.1)

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
    if version == EtsiVersion.V1_2_1:
        _check_v2_at_psids(psids)

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

    aa_hash = _hash_cert(aa_cert, sign_algorithm, version)
    if sign_algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA256_AND_DIGEST, digest=aa_hash)
    else:
        issuer = IssuerIdentifier(choice=IssuerChoice.SHA384_AND_DIGEST, digest=aa_hash)

    return _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, aa_priv_key, sign_algorithm,
                           version=version, subject_type=V1SubjectType.AUTHORIZATION_TICKET,
                           issuer_cert=aa_cert)

# ── Profile 9.6 / 7.6 (BKE variant) — Butterfly AT batch issuance ───────────

def issue_butterfly_authorization_tickets(
    cocoon_sign_pubs: list,
    aa_cert: Certificate,
    aa_priv_key,
    app_psids:       Optional[list] = None,
    sign_algorithm:  PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
    validity_hours:  int = 168,
    region_ids:      Optional[list] = None,
    start_time:      Optional[float] = None,
    version:         EtsiVersion = EtsiVersion.V1_2_1,
) -> list:
    """
    ACA/AA side of the IEEE 1609.2.1 Butterfly Key Mechanism (explicit certificates),
    as used by ETSI TS 102 941 clause 6.2.3.5.

    For every cocoon verification key pk_cc (expanded by the EA/RA from the end
    entity's caterpillar key), the AA draws a fresh random offset r, certifies the
    butterfly key pk_bf = pk_cc + r*G and returns r to the end entity (in the real
    protocol inside the response encrypted to the cocoon encryption key). The offset
    is what makes the certificates unlinkable for the EA, which knows the cocoon keys.

    All certificates are conformant AT profiles (id=none, no certIssuePermissions,
    appPermissions present).

    Returns a list of (Certificate, offset r) in the order of cocoon_sign_pubs.
    """
    from .crypto import bke_random_offset, bke_butterfly_public_key

    t = start_time or time.time()
    psids = app_psids or [
        PsidSsp(psid=int(ItsAid.CAM)),
        PsidSsp(psid=int(ItsAid.DENM)),
    ]
    if version == EtsiVersion.V1_2_1:
        _check_v2_at_psids(psids)
    aa_hash = _hash_cert(aa_cert, sign_algorithm, version)
    issuer = (
        IssuerIdentifier(choice=IssuerChoice.SHA256_AND_DIGEST, digest=aa_hash)
        if sign_algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256
        else IssuerIdentifier(choice=IssuerChoice.SHA384_AND_DIGEST, digest=aa_hash)
    )

    tickets = []
    for cocoon_pub in cocoon_sign_pubs:
        offset = bke_random_offset(cocoon_pub.curve)
        butterfly_pub = bke_butterfly_public_key(cocoon_pub, offset)
        vp = _make_validity_period(t, duration_hours=validity_hours)
        vk = PublicVerificationKey(algorithm=sign_algorithm, point=public_key_to_point(butterfly_pub))
        region = GeographicRegion(choice=RegionChoice.ID, ids=region_ids) if region_ids else None
        tbs = ToBeSignedCertificate(
            id=CertificateId(CertIdChoice.NONE),
            craca_id=CRACA_ID,
            crl_series=CRL_SERIES,
            validity_period=vp,
            region=region,
            app_permissions=psids,
            cert_issue_permissions=None,
            encryption_key=None,
            verify_key_indicator=vk,
        )
        cert = _build_and_sign(tbs, CertificateType.EXPLICIT, issuer, aa_priv_key,
                               sign_algorithm, version=version,
                               subject_type=V1SubjectType.AUTHORIZATION_TICKET,
                               issuer_cert=aa_cert)
        tickets.append((cert, offset))
    return tickets
