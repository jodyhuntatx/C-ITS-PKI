"""
COER encoding and decoding for IEEE 1609.2 / ETSI TS 103 097 certificate structures.

Implements the canonical encoding of all certificate-level data structures
per ITU-T X.696 (COER) and IEEE Std 1609.2-2025 Annex B.
"""
from .coer import (
    encode_uint8, encode_uint16, encode_uint32,
    encode_length, encode_octet_string, encode_utf8string,
    encode_choice, encode_sequence, encode_enumerated, encode_bit_string,
    decode_uint8, decode_uint16, decode_uint32,
    decode_length, decode_octet_string, decode_utf8string,
    decode_choice_tag
)
from .types import (
    Certificate, ToBeSignedCertificate, IssuerIdentifier, CertificateId,
    ValidityPeriod, Duration, GeographicRegion, SubjectAssurance,
    PsidSsp, PsidGroupPermissions, PublicVerificationKey, PublicEncryptionKey,
    EccPoint, EcdsaSignature, CertificateType, IssuerChoice, CertIdChoice,
    DurationChoice, RegionChoice, PublicKeyAlgorithm, EccP256CurvePointChoice,
    HashAlgorithm, EtsiVersion
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


# ── Duration encoding ─────────────────────────────────────────────────────────

def encode_duration(d: Duration) -> bytes:
    """Duration CHOICE (IEEE 1609.2 clause 6.3.24): index tag + Uint16."""
    return encode_choice(int(d.choice), encode_uint16(d.value))


def decode_duration(data: bytes, offset: int):
    choice, offset = decode_choice_tag(data, offset)
    value, offset = decode_uint16(data, offset)
    return Duration(DurationChoice(choice), value), offset


# ── ValidityPeriod encoding ───────────────────────────────────────────────────

def encode_validity_period(vp: ValidityPeriod) -> bytes:
    """ValidityPeriod ::= SEQUENCE { start Time32, duration Duration }."""
    return encode_uint32(vp.start) + encode_duration(vp.duration)


def decode_validity_period(data: bytes, offset: int):
    start, offset = decode_uint32(data, offset)
    duration, offset = decode_duration(data, offset)
    return ValidityPeriod(start=start, duration=duration), offset


# ── GeographicRegion encoding ─────────────────────────────────────────────────

def encode_geographic_region(region: GeographicRegion) -> bytes:
    """
    GeographicRegion CHOICE (IEEE 1609.2 clause 6.3.4):
      [3] identifiedRegion: SequenceOfIdentifiedRegion

    IdentifiedRegion CHOICE:
      [2] countryOnly: UnCountryId (Uint16)

    Supports EU-27 special value (65535) and arbitrary country IDs.
    """
    if region.choice == RegionChoice.ID and region.ids is not None:
        items = b''
        for region_id in region.ids:
            items += encode_choice(2, encode_uint16(region_id))
        # SequenceOf wrapper (length-prefixed list)
        return encode_choice(3, encode_octet_string(items))
    raise ValueError("Only identifiedRegion (choice=3) is currently supported")


def decode_geographic_region(data: bytes, offset: int):
    choice, offset = decode_choice_tag(data, offset)
    if choice == 3:     # identifiedRegion
        raw, offset = decode_octet_string(data, offset)
        ids = []
        i = 0
        while i < len(raw):
            idr_choice = raw[i]; i += 1
            if idr_choice == 2:     # countryOnly
                cid = int.from_bytes(raw[i:i + 2], 'big'); i += 2
                ids.append(cid)
        return GeographicRegion(choice=RegionChoice.ID, ids=ids), offset
    raise ValueError(f"Unsupported GeographicRegion choice: {choice}")


# ── PsidSsp (appPermissions) encoding ─────────────────────────────────────────

def encode_psid(psid: int) -> bytes:
    """PSID variable-length encoding per IEEE 1609.2 clause 6.3.23 (1–4 bytes)."""
    if psid < 0x80:
        return bytes([psid])
    elif psid < 0x4000:
        return bytes([0x80 | (psid >> 8), psid & 0xFF])
    elif psid < 0x200000:
        return bytes([0xC0 | (psid >> 16), (psid >> 8) & 0xFF, psid & 0xFF])
    else:
        return bytes([0xE0 | (psid >> 24), (psid >> 16) & 0xFF,
                      (psid >> 8) & 0xFF, psid & 0xFF])


def decode_psid(data: bytes, offset: int):
    b0 = data[offset]
    if b0 < 0x80:
        return b0, offset + 1
    elif b0 < 0xC0:
        return ((b0 & 0x3F) << 8) | data[offset + 1], offset + 2
    elif b0 < 0xE0:
        return (((b0 & 0x1F) << 16) | (data[offset + 1] << 8) |
                data[offset + 2]), offset + 3
    else:
        return (((b0 & 0x0F) << 24) | (data[offset + 1] << 16) |
                (data[offset + 2] << 8) | data[offset + 3]), offset + 4


def encode_psid_ssp(ps: PsidSsp) -> bytes:
    """
    PsidSsp ::= SEQUENCE {
      psid Psid,
      ssp  ServiceSpecificPermissions OPTIONAL
    }
    ServiceSpecificPermissions CHOICE: opaque [0] OCTET STRING.
    """
    psid_enc = encode_psid(ps.psid)
    if ps.ssp is not None:
        ssp_enc = encode_choice(0, encode_octet_string(ps.ssp))
        has_ssp = True
    else:
        ssp_enc = b''
        has_ssp = False

    # 1-byte bitmap for the single optional field (ssp)
    bitmap = bytes([0x80]) if has_ssp else bytes([0x00])
    result = bitmap + psid_enc
    if has_ssp:
        result += ssp_enc
    return result


def encode_seq_of_psid_ssp(perms: list) -> bytes:
    """SequenceOfPsidSsp: length-prefixed list."""
    items = b''.join(encode_psid_ssp(p) for p in perms)
    return encode_octet_string(items)


def encode_psid_group_permissions(pgp: PsidGroupPermissions) -> bytes:
    """
    PsidGroupPermissions ::= SEQUENCE {
      subjectPermissions SubjectPermissions,
      minChainDepth      INTEGER DEFAULT 1,
      chainDepthRange    INTEGER DEFAULT 0,
      eeType             EndEntityType DEFAULT {app}
    }
    SubjectPermissions CHOICE:
      all      [0]: NULL (grant all PSIDs)
      explicit [1]: SequenceOfPsidSspRange
    We use 'all' for this implementation.

    EndEntityType ::= BIT STRING { app(0), enrol(1) } (SIZE(8))
    COER fixed-size BIT STRING SIZE(8): encoded as 1 octet (no length or unused bits).
    Default = {app} = bit 0 set = 0x80.
    """
    subject_perms = encode_choice(0, b'')          # all
    chain_depth   = encode_uint8(pgp.min_chain_depth)
    depth_range   = encode_uint8(pgp.chain_depth_range)
    # EndEntityType: BIT STRING SIZE(8) → fixed 1 byte in COER
    # ee_type stores the bit pattern: 0x80 = {app}, 0x40 = {enrol}, 0xC0 = {app, enrol}
    ee_type_byte  = pgp.ee_type if pgp.ee_type is not None else 0x80
    return subject_perms + chain_depth + depth_range + bytes([ee_type_byte])


def encode_seq_of_psid_group_permissions(perms: list) -> bytes:
    items = b''.join(encode_psid_group_permissions(p) for p in perms)
    return encode_octet_string(items)


# ── IssuerIdentifier encoding ─────────────────────────────────────────────────

def encode_issuer_identifier(issuer: IssuerIdentifier) -> bytes:
    """
    IssuerIdentifier CHOICE (IEEE 1609.2 clause 6.3.27):
      sha256AndDigest [0]: HashedId8 (8 bytes)
      self            [1]: HashAlgorithm (Uint8)
      sha384AndDigest [2]: HashedId8 (8 bytes)
    """
    if issuer.choice == IssuerChoice.SHA256_AND_DIGEST:
        return encode_choice(0, issuer.digest)
    elif issuer.choice == IssuerChoice.SELF:
        return encode_choice(1, encode_uint8(int(issuer.hash_alg)))
    elif issuer.choice == IssuerChoice.SHA384_AND_DIGEST:
        return encode_choice(2, issuer.digest)
    raise ValueError(f"Unknown IssuerIdentifier choice: {issuer.choice}")


def decode_issuer_identifier(data: bytes, offset: int):
    choice, offset = decode_choice_tag(data, offset)
    if choice == 0:
        digest = data[offset:offset + 8]; offset += 8
        return IssuerIdentifier(IssuerChoice.SHA256_AND_DIGEST, digest=digest), offset
    elif choice == 1:
        alg, offset = decode_uint8(data, offset)
        return IssuerIdentifier(IssuerChoice.SELF, hash_alg=HashAlgorithm(alg)), offset
    elif choice == 2:
        digest = data[offset:offset + 8]; offset += 8
        return IssuerIdentifier(IssuerChoice.SHA384_AND_DIGEST, digest=digest), offset
    raise ValueError(f"Unknown IssuerIdentifier choice: {choice}")


# ── CertificateId encoding ────────────────────────────────────────────────────

def encode_certificate_id(cert_id: CertificateId) -> bytes:
    """
    CertificateId CHOICE (IEEE 1609.2 clause 6.4.3):
      linkageData [0]
      name        [1]: Hostname (VisibleString 0..255)
      binaryId    [2]
      none        [3]: NULL
    """
    if cert_id.choice == CertIdChoice.NAME:
        return encode_choice(1, encode_utf8string(cert_id.name))
    elif cert_id.choice == CertIdChoice.NONE:
        return encode_choice(3, b'')
    raise ValueError(f"Unsupported CertificateId choice: {cert_id.choice}")


def decode_certificate_id(data: bytes, offset: int):
    choice, offset = decode_choice_tag(data, offset)
    if choice == 1:
        name, offset = decode_utf8string(data, offset)
        return CertificateId(CertIdChoice.NAME, name=name), offset
    elif choice == 3:
        return CertificateId(CertIdChoice.NONE), offset
    raise ValueError(f"Unsupported CertificateId choice: {choice}")


# ── VerifyKeyIndicator encoding ───────────────────────────────────────────────

def encode_verify_key_indicator(vk: PublicVerificationKey) -> bytes:
    """
    VerifyKeyIndicator CHOICE (IEEE 1609.2 clause 6.4.7):
      verificationKey    [0]: PublicVerificationKey  (explicit cert)
      reconstructionValue[1]: EccP256CurvePoint      (implicit cert)
    We support explicit certificates (verificationKey).
    """
    return encode_choice(0, encode_public_verification_key(vk))


def decode_verify_key_indicator(data: bytes, offset: int):
    choice, offset = decode_choice_tag(data, offset)
    if choice == 0:
        vk, offset = decode_public_verification_key(data, offset)
        return vk, offset
    elif choice == 1:
        # implicit: reconstruction value (EccP256CurvePoint)
        point, offset = decode_ecc_p256_point(data, offset)
        return point, offset   # caller must handle EccPoint vs PublicVerificationKey
    raise ValueError(f"Unsupported VerifyKeyIndicator choice: {choice}")


# ── ToBeSignedCertificate encoding ────────────────────────────────────────────

def encode_tbs_certificate(tbs: ToBeSignedCertificate,
                           version: EtsiVersion = EtsiVersion.V2_2_1) -> bytes:
    """
    ToBeSignedCertificate SEQUENCE (IEEE 1609.2 clause 6.4.6).

    Mandatory fields (always present):
      id, cracaId, crlSeries, validityPeriod

    V2.2.1 (IEEE 1609.2-2022/2025) — 2-byte presence bitmap, 8 optional fields:
      bit 15: region
      bit 14: assuranceLevel
      bit 13: appPermissions
      bit 12: certIssuePermissions
      bit 11: certRequestPermissions  (always absent)
      bit 10: canRequestRollover      (always absent)
      bit  9: encryptionKey
      bit  8: flags                   (always absent)

    V1.2.1 (IEEE 1609.2-2016) — 1-byte presence bitmap, 7 optional fields:
      bit 7: region
      bit 6: assuranceLevel
      bit 5: appPermissions
      bit 4: certIssuePermissions
      bit 3: certRequestPermissions   (always absent)
      bit 2: canRequestRollover       (always absent)
      bit 1: encryptionKey
      No ``flags`` field.

    verifyKeyIndicator is mandatory (follows after optional fields).
    """
    id_enc  = encode_certificate_id(tbs.id)
    craca   = tbs.craca_id                   # 3 bytes fixed (HashedId3)
    crl_enc = encode_uint16(tbs.crl_series)
    vp_enc  = encode_validity_period(tbs.validity_period)

    # Compute optional field presence
    has_region   = tbs.region is not None
    has_assure   = tbs.assurance_level is not None
    has_app      = bool(tbs.app_permissions)
    has_issue    = bool(tbs.cert_issue_permissions)
    has_enc_key  = tbs.encryption_key is not None

    # Mandatory part
    result = id_enc + craca + crl_enc + vp_enc

    if version == EtsiVersion.V1_2_1:
        # 1-byte bitmap (7 optional fields, IEEE 1609.2-2016)
        bitmap = 0
        if has_region:   bitmap |= 0x80  # bit 7
        if has_assure:   bitmap |= 0x40  # bit 6
        if has_app:      bitmap |= 0x20  # bit 5
        if has_issue:    bitmap |= 0x10  # bit 4
        # bit 3: certRequestPermissions — always absent
        # bit 2: canRequestRollover     — always absent
        if has_enc_key:  bitmap |= 0x02  # bit 1
        result += bytes([bitmap])
    else:
        # 2-byte bitmap (8 optional fields, IEEE 1609.2-2022/2025)
        bitmap = 0
        if has_region:   bitmap |= (1 << 15)
        if has_assure:   bitmap |= (1 << 14)
        if has_app:      bitmap |= (1 << 13)
        if has_issue:    bitmap |= (1 << 12)
        if has_enc_key:  bitmap |= (1 << 9)
        result += bitmap.to_bytes(2, 'big')

    # Optional fields (in order, only if present — same for both versions)
    if has_region:
        result += encode_geographic_region(tbs.region)
    if has_assure:
        level = tbs.assurance_level
        result += bytes([(level.level << 5) | (level.confidence & 0x03)])
    if has_app:
        result += encode_seq_of_psid_ssp(tbs.app_permissions)
    if has_issue:
        result += encode_seq_of_psid_group_permissions(tbs.cert_issue_permissions)
    if has_enc_key:
        result += encode_public_encryption_key(tbs.encryption_key)

    # Mandatory: verifyKeyIndicator
    if tbs.verify_key_indicator is not None:
        result += encode_verify_key_indicator(tbs.verify_key_indicator)
    else:
        raise ValueError("verifyKeyIndicator is required for explicit certificates")

    return result


def decode_tbs_certificate(data: bytes, offset: int,
                           version: EtsiVersion = EtsiVersion.V2_2_1):
    """Decode ToBeSignedCertificate. Returns (tbs, offset)."""
    cert_id, offset = decode_certificate_id(data, offset)
    craca_id = data[offset:offset + 3]; offset += 3
    crl_series, offset = decode_uint16(data, offset)
    vp, offset = decode_validity_period(data, offset)

    region = assurance = app_perms = cert_issue = enc_key = None

    if version == EtsiVersion.V1_2_1:
        # 1-byte presence bitmap (7 optional fields, IEEE 1609.2-2016)
        bitmap = data[offset]; offset += 1
        if bitmap & 0x80:   # bit 7: region
            region, offset = decode_geographic_region(data, offset)
        if bitmap & 0x40:   # bit 6: assuranceLevel
            b = data[offset]; offset += 1
            assurance = SubjectAssurance(level=(b >> 5) & 0x7, confidence=b & 0x03)
        if bitmap & 0x20:   # bit 5: appPermissions
            raw, offset = decode_octet_string(data, offset)
            app_perms = _decode_seq_of_psid_ssp(raw)
        if bitmap & 0x10:   # bit 4: certIssuePermissions
            raw, offset = decode_octet_string(data, offset)
            cert_issue = []
        # bit 3: certRequestPermissions — always absent
        # bit 2: canRequestRollover     — always absent
        if bitmap & 0x02:   # bit 1: encryptionKey
            enc_key, offset = decode_public_encryption_key(data, offset)
    else:
        # 2-byte presence bitmap (8 optional fields, IEEE 1609.2-2022/2025)
        bitmap = int.from_bytes(data[offset:offset + 2], 'big'); offset += 2
        if bitmap & (1 << 15):   # region
            region, offset = decode_geographic_region(data, offset)
        if bitmap & (1 << 14):   # assuranceLevel
            b = data[offset]; offset += 1
            assurance = SubjectAssurance(level=(b >> 5) & 0x7, confidence=b & 0x03)
        if bitmap & (1 << 13):   # appPermissions
            raw, offset = decode_octet_string(data, offset)
            app_perms = _decode_seq_of_psid_ssp(raw)
        if bitmap & (1 << 12):   # certIssuePermissions
            raw, offset = decode_octet_string(data, offset)
            cert_issue = []
        # bits 11, 10: certRequestPermissions, canRequestRollover — always absent
        if bitmap & (1 << 9):    # encryptionKey
            enc_key, offset = decode_public_encryption_key(data, offset)
        # bit 8: flags — always absent in our implementation

    # verifyKeyIndicator (mandatory)
    vki, offset = decode_verify_key_indicator(data, offset)

    return ToBeSignedCertificate(
        id=cert_id,
        craca_id=craca_id,
        crl_series=crl_series,
        validity_period=vp,
        region=region,
        assurance_level=assurance,
        app_permissions=app_perms,
        cert_issue_permissions=cert_issue,
        encryption_key=enc_key,
        verify_key_indicator=vki if isinstance(vki, PublicVerificationKey) else None,
        reconstruction_value=vki if isinstance(vki, EccPoint) else None,
    ), offset


def _decode_seq_of_psid_ssp(raw: bytes) -> list:
    """Decode SequenceOfPsidSsp from raw bytes."""
    perms = []
    i = 0
    while i < len(raw):
        # 1-byte bitmap
        has_ssp = bool(raw[i] & 0x80); i += 1
        # PSID
        psid, i = decode_psid(raw, i)
        ssp = None
        if has_ssp:
            ssp_choice = raw[i]; i += 1    # should be 0 (opaque)
            ssp_len_b = raw[i]
            if ssp_len_b < 0x80:
                ssp_len = ssp_len_b; i += 1
            else:
                nb = ssp_len_b & 0x7F
                ssp_len = int.from_bytes(raw[i + 1:i + 1 + nb], 'big')
                i += 1 + nb
            ssp = raw[i:i + ssp_len]; i += ssp_len
        perms.append(PsidSsp(psid=psid, ssp=ssp))
    return perms


# ── Certificate encoding ──────────────────────────────────────────────────────

def encode_certificate(cert: Certificate,
                       version: EtsiVersion = EtsiVersion.V2_2_1) -> bytes:
    """
    EtsiTs103097Certificate (IEEE 1609.2 clause 6.4.2):
    Certificate ::= SEQUENCE {
      version    Uint8 (3),
      type       CertificateType ENUMERATED { explicit(0), implicit(1) },
      issuer     IssuerIdentifier,
      toBeSigned ToBeSignedCertificate,
      signature  Signature OPTIONAL
    }
    The single optional field (signature) is indicated by a 1-byte bitmap.
    The ``version`` parameter controls the TBS bitmap width (see encode_tbs_certificate).
    """
    version_enc = encode_uint8(cert.version)
    type_enc    = encode_enumerated(int(cert.cert_type))
    issuer_enc  = encode_issuer_identifier(cert.issuer)
    tbs_enc     = encode_tbs_certificate(cert.tbs, version=version)

    has_sig  = cert.signature is not None
    bitmap   = bytes([0x80]) if has_sig else bytes([0x00])
    sig_enc  = encode_signature(cert.signature) if has_sig else b''

    return version_enc + type_enc + issuer_enc + tbs_enc + bitmap + sig_enc


def decode_certificate(data: bytes, offset: int = 0,
                       version: EtsiVersion = EtsiVersion.V2_2_1):
    """
    Decode an EtsiTs103097Certificate from COER bytes. Returns (cert, offset).

    The ``version`` parameter must match the standard version that was used to
    encode the certificate so that the correct TBS bitmap width is applied.
    """
    cert_version, offset  = decode_uint8(data, offset)
    cert_type_raw, offset = decode_uint8(data, offset)    # ENUMERATED encoded as Uint8
    cert_type             = CertificateType(cert_type_raw)
    issuer, offset        = decode_issuer_identifier(data, offset)
    tbs_start             = offset
    tbs, offset           = decode_tbs_certificate(data, offset, version=version)
    tbs_end               = offset

    # 1-byte presence bitmap for the optional signature field
    sig = None
    if offset < len(data):
        bitmap = data[offset]; offset += 1
        if bitmap & 0x80:
            sig, offset = decode_signature(data, offset)

    cert = Certificate(
        version=cert_version,
        cert_type=cert_type,
        issuer=issuer,
        tbs=tbs,
        signature=sig,
    )
    cert.encoded     = data[:offset]
    # Cache the original TBS bytes so verify_certificate_signature can use
    # the exact bytes that were signed (avoids re-encoding discrepancies).
    cert.tbs_encoded = data[tbs_start:tbs_end]
    return cert, offset
