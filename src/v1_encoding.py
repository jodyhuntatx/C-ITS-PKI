"""
Vanetza-compatible binary serialization for ETSI TS 103 097 V1.2.1 certificates.

Implements the wire format used by the vanetza simulator's v2 security module,
conforming to ETSI TS 103 097 V1.2.1 (2015-06), section 6.1 and the C++ struct
definition in vanetza/security/v2/certificate.hpp.

This format is fundamentally different from the COER encoding used by V2.2.1:
  - Custom variable-length coding (not COER)
  - Subject-centric structure: version + SignerInfo + SubjectInfo + SubjectAttributes
    + ValidityRestrictions + Signature
  - No IEEE 1609.2-2022 constructs (cracaId, crlSeries, CertificateType, etc.)
  - Certificate version byte = 0x02

Wire format:
    [0x02]                       version (always 2)
    [SignerInfo]                 signer type + optional 8-byte HashedId8 digest
    [SubjectInfo]                subject type + vanetza_length(name) + name bytes
    [vanetza_length(attrs_sz)]   total byte size of attribute list
    [SubjectAttributes...]       zero or more attributes, in type-ascending order
    [vanetza_length(vr_sz)]      total byte size of validity restriction list
    [ValidityRestrictions...]    one or more validity restrictions
    [Signature]                  algorithm byte + R EccPoint + S (32 bytes)

Signing input (convert_for_signing equivalent) excludes the Signature field;
everything else from version through the validity restriction list is signed.
"""
import hashlib
from .types import (
    Certificate, ToBeSignedCertificate, IssuerIdentifier, CertificateId,
    ValidityPeriod, Duration, GeographicRegion,
    PsidSsp, PublicVerificationKey, PublicEncryptionKey, EcdsaSignature,
    CertificateType, IssuerChoice, CertIdChoice, DurationChoice, RegionChoice,
    PublicKeyAlgorithm, EccPoint, EtsiVersion,
    # Vanetza v2 wire-format constants (defined in types.py alongside other enums)
    V1SubjectType, V1SignerInfoType, V1EccPointType, V1PublicKeyAlgorithm,
    V1SubjectAttributeType, V1ValidityRestrictionType, V1RegionType, V1RegionDictionary,
)


# ── Vanetza duration unit mapping ─────────────────────────────────────────────
# Vanetza Duration (validity_restriction.hpp): 2-byte word
#   bits 15-13 = units:  0=Sec, 1=Min, 2=Hours, 3=60hBlocks, 4=Years
#   bits 12-0  = value

_VANETZA_DURATION_UNITS = {
    DurationChoice.SECONDS:     0,
    DurationChoice.MINUTES:     1,
    DurationChoice.HOURS:       2,
    DurationChoice.SIXTY_HOURS: 3,
    DurationChoice.YEARS:       4,
}


# ── Vanetza length coding (length_coding.hpp) ─────────────────────────────────
# Leading 1-bits in the first byte signal how many additional bytes follow:
#   0xxxxxxx           — 1 byte, values 0–127
#   10xxxxxx xxxxxxxx  — 2 bytes, values 0–16383
#   110xxxxx xxxxxxxx xxxxxxxx — 3 bytes, values 0–2097151
#   1110xxxx ... — 4 bytes

def encode_length(n: int) -> bytes:
    """Encode n using the vanetza custom variable-length coding."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x4000:
        return bytes([0x80 | (n >> 8), n & 0xFF])
    elif n < 0x200000:
        return bytes([0xC0 | (n >> 16), (n >> 8) & 0xFF, n & 0xFF])
    else:
        return bytes([0xE0 | (n >> 24), (n >> 16) & 0xFF,
                      (n >> 8) & 0xFF, n & 0xFF])


def decode_length(data: bytes, offset: int):
    """Decode vanetza length from data at offset. Returns (length, new_offset)."""
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


def encode_intx(value: int) -> bytes:
    """
    IntX: same length coding as encode_length but used for integer values.
    Used to encode ITS-AIDs (PSIDs) in ITS_AID_List / ITS_AID_SSP_List.
    """
    return encode_length(value)


def length_coding_size(n: int) -> int:
    """Return the number of bytes required to encode n with encode_length."""
    if n < 0x80:
        return 1
    elif n < 0x4000:
        return 2
    elif n < 0x200000:
        return 3
    else:
        return 4


# ── ECC point encoding ────────────────────────────────────────────────────────

def encode_ecc_point(point: EccPoint) -> bytes:
    """
    Encode a compressed ECC point for use in VerificationKey / EncryptionKey:
      [EccPointType: 1 byte][x-coordinate: 32 bytes]
    We always use the compressed form: Compressed_Lsb_Y_0 or Compressed_Lsb_Y_1.
    """
    ecc_type = (V1EccPointType.COMPRESSED_LSB_Y_0 if point.y_parity == 0
                else V1EccPointType.COMPRESSED_LSB_Y_1)
    x_bytes = point.compressed[1:]   # strip 0x02/0x03 prefix → 32 bytes
    return bytes([ecc_type]) + x_bytes


def encode_ecc_point_x_only(r_bytes: bytes) -> bytes:
    """
    Encode an x-only ECC point for use in the ECDSA signature R component:
      [EccPointType=0x00 (X_Coordinate_Only)][r: 32 bytes]
    """
    return bytes([V1EccPointType.X_COORDINATE_ONLY]) + r_bytes


# ── Duration encoding ─────────────────────────────────────────────────────────

def encode_duration_v1(duration: Duration) -> bytes:
    """
    Encode a Duration as a 2-byte vanetza word:
      bits 15-13 = units (Sec=0, Min=1, Hours=2, 60hBlocks=3, Years=4)
      bits 12-0  = value
    """
    units = _VANETZA_DURATION_UNITS.get(duration.choice)
    if units is None:
        raise ValueError(
            f"Duration choice {duration.choice!r} is not supported in vanetza format. "
            f"Supported: SECONDS, MINUTES, HOURS, SIXTY_HOURS, YEARS."
        )
    val = duration.value & 0x1FFF   # 13-bit value
    return ((units << 13) | val).to_bytes(2, 'big')


# ── SignerInfo encoding ───────────────────────────────────────────────────────

def encode_signer_info_v1(issuer: IssuerIdentifier) -> bytes:
    """
    Encode vanetza SignerInfo:
      Self:      [0x00]
      Digest:    [0x01][HashedId8: 8 bytes]
    """
    if issuer.choice == IssuerChoice.SELF:
        return bytes([V1SignerInfoType.SELF])
    elif issuer.choice in (IssuerChoice.SHA256_AND_DIGEST,
                           IssuerChoice.SHA384_AND_DIGEST):
        return bytes([V1SignerInfoType.CERTIFICATE_DIGEST_WITH_SHA256]) + issuer.digest
    raise ValueError(
        f"IssuerChoice {issuer.choice!r} is not supported in vanetza format."
    )


# ── SubjectInfo encoding ──────────────────────────────────────────────────────

def encode_subject_info_v1(subject_type: int, name: str) -> bytes:
    """
    Encode vanetza SubjectInfo:
      [SubjectType: 1 byte][vanetza_length(name_len)][name: ASCII bytes]
    Anonymous subjects (AT) pass an empty name string.
    """
    name_bytes = name.encode('ascii') if name else b''
    return bytes([subject_type]) + encode_length(len(name_bytes)) + name_bytes


# ── Subject attribute encoding ────────────────────────────────────────────────

def _encode_verification_key_attr(vk: PublicVerificationKey) -> bytes:
    """
    Verification_Key attribute (type 0x00):
      [0x00][PublicKeyAlgorithm=0x00][EccPointType][x: 32 bytes]
    Fixed size: 1 + 1 + 1 + 32 = 35 bytes.
    """
    return (bytes([V1SubjectAttributeType.VERIFICATION_KEY,
                   V1PublicKeyAlgorithm.ECDSA_NISTP256_WITH_SHA256]) +
            encode_ecc_point(vk.point))


def _encode_encryption_key_attr(ek: PublicEncryptionKey) -> bytes:
    """
    Encryption_Key attribute (type 0x01):
      [0x01][PublicKeyAlgorithm=0x01][SymmetricAlgorithm=0x00][EccPointType][x: 32 bytes]
    Fixed size: 1 + 1 + 1 + 1 + 32 = 36 bytes.
    """
    return (bytes([V1SubjectAttributeType.ENCRYPTION_KEY,
                   V1PublicKeyAlgorithm.ECIES_NISTP256,
                   0x00]) +          # SymmetricAlgorithm = AES128_CCM = 0
            encode_ecc_point(ek.point))


def _encode_its_aid_list_attr(psids: list) -> bytes:
    """
    ITS_AID_List attribute (type 0x20) — used when no PSID has an SSP value:
      [0x20][vanetza_length(aids_size)][IntX(aid1)][IntX(aid2)]...
    """
    aids_bytes = b''.join(encode_intx(ps.psid) for ps in psids)
    return (bytes([V1SubjectAttributeType.ITS_AID_LIST]) +
            encode_length(len(aids_bytes)) + aids_bytes)


def _encode_its_aid_ssp_list_attr(psids: list) -> bytes:
    """
    ITS_AID_SSP_List attribute (type 0x21) — used when at least one PSID has SSP:
      [0x21][vanetza_length(content_size)][IntX(aid1)][vanetza_length(ssp1_size)][ssp1]...
    """
    items = b''
    for ps in psids:
        aid_enc = encode_intx(ps.psid)
        ssp_bytes = ps.ssp if ps.ssp else b''
        items += aid_enc + encode_length(len(ssp_bytes)) + ssp_bytes
    return (bytes([V1SubjectAttributeType.ITS_AID_SSP_LIST]) +
            encode_length(len(items)) + items)


def encode_subject_attributes_v1(vk: PublicVerificationKey,
                                  ek=None,
                                  psids=None) -> bytes:
    """
    Encode all subject attributes in vanetza-required order (ascending type):
      0: Verification_Key (always present)
      1: Encryption_Key (optional — present for EA/AA)
     32: ITS_AID_List or ITS_AID_SSP_List (present when PSIDs are given)

    Returns the concatenated raw attribute bytes (NOT yet length-prefixed).
    The caller wraps this with encode_length(len(result)).
    """
    attrs = b''
    attrs += _encode_verification_key_attr(vk)
    if ek is not None:
        attrs += _encode_encryption_key_attr(ek)
    if psids:
        if any(ps.ssp for ps in psids):
            attrs += _encode_its_aid_ssp_list_attr(psids)
        else:
            attrs += _encode_its_aid_list_attr(psids)
    return attrs


# ── Validity restriction encoding ─────────────────────────────────────────────

# Vanetza Duration.to_seconds() multipliers (validity_restriction.cpp)
_VANETZA_TO_SECONDS = {
    DurationChoice.SECONDS:     1,
    DurationChoice.MINUTES:     60,
    DurationChoice.HOURS:       3600,
    DurationChoice.SIXTY_HOURS: 216000,
    DurationChoice.YEARS:       31556925,
}


def _duration_to_its_seconds(duration: Duration) -> int:
    """
    Convert a Duration to seconds using Vanetza's exact multipliers.
    Matches Duration::to_seconds() in vanetza/security/v2/validity_restriction.cpp.
    """
    multiplier = _VANETZA_TO_SECONDS.get(duration.choice)
    if multiplier is None:
        raise ValueError(f"Unsupported duration choice for v1 encoding: {duration.choice!r}")
    return duration.value * multiplier


def _encode_time_start_and_end(start: int, duration: Duration) -> bytes:
    """
    Time_Start_And_End validity restriction (type 0x01):
      [0x01][start: 4 bytes BE][end: 4 bytes BE]
    Total: 9 bytes.

    The end ITS timestamp is computed as start + duration_in_seconds using the
    same multipliers as Vanetza's Duration::to_seconds() so that the unmodified
    vanetza certify show-certificate tool displays correct validity dates.

    Note: Time_Start_And_Duration (type 2) is NOT used because the certify tool's
    show-certificate.cpp line 208 computes ``time_end = epoch + duration.to_seconds()``
    rather than ``epoch + start + duration.to_seconds()``, producing wrong dates.
    """
    end = start + _duration_to_its_seconds(duration)
    return (bytes([V1ValidityRestrictionType.TIME_START_AND_END]) +
            start.to_bytes(4, 'big') +
            end.to_bytes(4, 'big'))


def _encode_region_vr(region: GeographicRegion) -> bytes:
    """
    Region validity restriction (type 0x03) using a single IdentifiedRegion:
      [0x03][RegionType=0x04][RegionDictionary: 1 byte][region_id: 2 bytes signed][IntX(0)]

    Only the first region ID is encoded (vanetza v2 holds a single IdentifiedRegion,
    not a SequenceOfIdentifiedRegion as in IEEE 1609.2-2022).

    RegionDictionary mapping:
      ISO_3166_1 (0): for IDs in range 1–999 (ISO 3166-1 numeric codes)
      UN_Stats   (1): for all other identifiers

    IDs > 32767 are encoded as a signed int16_t (e.g. 65535 → 0xFFFF = -1).
    """
    if region.choice != RegionChoice.ID or not region.ids:
        raise ValueError("Only IdentifiedRegion (RegionChoice.ID) is supported in vanetza format")

    region_id = region.ids[0]   # vanetza holds a single IdentifiedRegion

    # Choose dictionary
    if 1 <= region_id <= 999:
        dictionary = V1RegionDictionary.ISO_3166_1
    else:
        dictionary = V1RegionDictionary.UN_STATS

    # Encode region_identifier as signed int16_t big-endian
    rid_signed = region_id if region_id <= 32767 else region_id - 65536
    rid_bytes = rid_signed.to_bytes(2, 'big', signed=True)

    # local_region = IntX(0) → encode_length(0) = bytes([0x00])
    local_region = encode_intx(0)

    identified_region = bytes([dictionary]) + rid_bytes + local_region

    return (bytes([V1ValidityRestrictionType.REGION,
                   V1RegionType.ID]) +
            identified_region)


def encode_validity_restrictions_v1(validity_period: ValidityPeriod,
                                     region=None) -> bytes:
    """
    Encode all validity restrictions in vanetza order.
    Returns the concatenated raw VR bytes (NOT yet length-prefixed).
    The caller wraps this with encode_length(len(result)).

    Always produces:
      Time_Start_And_End (type 1): 9 bytes

    Optionally appends:
      Region (type 3): 7 bytes for one IdentifiedRegion
    """
    vr = _encode_time_start_and_end(
        validity_period.start, validity_period.duration
    )
    if region is not None:
        vr += _encode_region_vr(region)
    return vr


# ── Signature encoding ────────────────────────────────────────────────────────

def encode_signature_v1(sig: EcdsaSignature) -> bytes:
    """
    Encode vanetza ECDSA signature:
      [PublicKeyAlgorithm=0x00 (ECDSA_NISTP256_WITH_SHA256)]
      [EccPointType=0x00 (X_Coordinate_Only)]
      [r: 32 bytes]
      [s: 32 bytes]
    Total: 66 bytes.
    """
    return (bytes([V1PublicKeyAlgorithm.ECDSA_NISTP256_WITH_SHA256,
                   V1EccPointType.X_COORDINATE_ONLY]) +
            sig.r + sig.s)


# ── Signing input (convert_for_signing equivalent) ────────────────────────────

def compute_signing_input_v1(signer_info_bytes: bytes,
                              subject_info_bytes: bytes,
                              attrs_bytes: bytes,
                              vr_bytes: bytes) -> bytes:
    """
    Assemble the signing input per vanetza's convert_for_signing():
      [0x02]                          version
      [SignerInfo]
      [SubjectInfo]
      [vanetza_length(attrs_size)][SubjectAttributes]
      [vanetza_length(vr_size)][ValidityRestrictions]
    """
    return (bytes([0x02]) +
            signer_info_bytes +
            subject_info_bytes +
            encode_length(len(attrs_bytes)) + attrs_bytes +
            encode_length(len(vr_bytes)) + vr_bytes)


# ── HashedId8 calculation ─────────────────────────────────────────────────────

# ── Vanetza duration units (reverse mapping for decoder) ─────────────────────

_V1_UNITS_TO_DURATION = {
    0: DurationChoice.SECONDS,
    1: DurationChoice.MINUTES,
    2: DurationChoice.HOURS,
    3: DurationChoice.SIXTY_HOURS,
    4: DurationChoice.YEARS,
}


# ── Vanetza certificate decoder ───────────────────────────────────────────────

def decode_certificate_v1(data: bytes, offset: int = 0):
    """
    Decode a vanetza-format (ETSI TS 103 097 V1.2.1 binary) certificate.
    Returns (Certificate, new_offset).

    Parses: version · SignerInfo · SubjectInfo · SubjectAttributes list ·
    ValidityRestrictions list · Signature.
    """
    from .types import (
        Certificate, ToBeSignedCertificate, CertificateId, ValidityPeriod,
        Duration, IssuerIdentifier, EcdsaSignature, GeographicRegion,
        CertificateType, IssuerChoice, CertIdChoice, DurationChoice,
        RegionChoice, PublicKeyAlgorithm, HashAlgorithm, EccPoint,
        PsidSsp, PublicVerificationKey, PublicEncryptionKey,
    )

    start_offset = offset

    # ── Version byte ──────────────────────────────────────────────────────────
    version_byte = data[offset]; offset += 1
    if version_byte != 0x02:
        raise ValueError(
            f"Expected vanetza certificate version 0x02, got 0x{version_byte:02x}"
        )

    # ── SignerInfo ─────────────────────────────────────────────────────────────
    signer_type = data[offset]; offset += 1
    if signer_type == V1SignerInfoType.SELF:
        issuer = IssuerIdentifier(
            choice=IssuerChoice.SELF,
            hash_alg=HashAlgorithm.SHA256,
        )
    elif signer_type == V1SignerInfoType.CERTIFICATE_DIGEST_WITH_SHA256:
        digest = data[offset:offset + 8]; offset += 8
        issuer = IssuerIdentifier(
            choice=IssuerChoice.SHA256_AND_DIGEST,
            digest=digest,
        )
    else:
        raise ValueError(f"Unsupported V1 SignerInfoType: {signer_type}")

    # ── SubjectInfo ───────────────────────────────────────────────────────────
    subject_type = data[offset]; offset += 1
    name_len, offset = decode_length(data, offset)
    name = data[offset:offset + name_len].decode('ascii', errors='replace')
    offset += name_len

    # ── Subject Attributes ────────────────────────────────────────────────────
    attrs_size, offset = decode_length(data, offset)
    attrs_end = offset + attrs_size

    verify_key = None
    enc_key    = None
    app_permissions = []

    while offset < attrs_end:
        attr_type = data[offset]; offset += 1

        if attr_type == V1SubjectAttributeType.VERIFICATION_KEY:
            # [PublicKeyAlgo: 1][EccPointType: 1][x: 32]
            _algo = data[offset]; offset += 1
            ecc_type = data[offset]; offset += 1
            x_bytes = data[offset:offset + 32]; offset += 32
            if ecc_type == V1EccPointType.COMPRESSED_LSB_Y_1:
                compressed = b'\x03' + x_bytes; y_parity = 1
            else:   # X_COORDINATE_ONLY or COMPRESSED_LSB_Y_0
                compressed = b'\x02' + x_bytes; y_parity = 0
            point = EccPoint(curve='P-256', compressed=compressed, y_parity=y_parity)
            verify_key = PublicVerificationKey(
                algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256, point=point
            )

        elif attr_type == V1SubjectAttributeType.ENCRYPTION_KEY:
            # [PublicKeyAlgo: 1][SymAlgo: 1][EccPointType: 1][x: 32]
            _algo  = data[offset]; offset += 1
            _sym   = data[offset]; offset += 1
            ecc_type = data[offset]; offset += 1
            x_bytes = data[offset:offset + 32]; offset += 32
            if ecc_type == V1EccPointType.COMPRESSED_LSB_Y_1:
                compressed = b'\x03' + x_bytes; y_parity = 1
            else:
                compressed = b'\x02' + x_bytes; y_parity = 0
            point = EccPoint(curve='P-256', compressed=compressed, y_parity=y_parity)
            enc_key = PublicEncryptionKey(
                algorithm=PublicKeyAlgorithm.ECIES_NIST_P256, point=point
            )

        elif attr_type == V1SubjectAttributeType.ASSURANCE_LEVEL:
            _assurance = data[offset]; offset += 1   # skip

        elif attr_type in (V1SubjectAttributeType.ITS_AID_LIST,
                           V1SubjectAttributeType.ITS_AID_SSP_LIST):
            content_size, offset = decode_length(data, offset)
            content_end = offset + content_size
            i = offset
            while i < content_end:
                aid, i = decode_length(data, i)
                ssp = None
                if attr_type == V1SubjectAttributeType.ITS_AID_SSP_LIST:
                    ssp_len, i = decode_length(data, i)
                    ssp = data[i:i + ssp_len]; i += ssp_len
                app_permissions.append(PsidSsp(psid=aid, ssp=ssp))
            offset = content_end

        else:
            # Unknown attribute — stop parsing to avoid corruption
            break

    offset = attrs_end   # advance past any remaining attribute bytes

    # ── Validity Restrictions ─────────────────────────────────────────────────
    vr_size, offset = decode_length(data, offset)
    vr_end = offset + vr_size

    validity_period = None
    region          = None

    while offset < vr_end:
        vr_type = data[offset]; offset += 1

        if vr_type == V1ValidityRestrictionType.TIME_END:
            end_time = int.from_bytes(data[offset:offset + 4], 'big'); offset += 4
            validity_period = ValidityPeriod(
                start=0,
                duration=Duration(DurationChoice.SECONDS, end_time),
            )

        elif vr_type == V1ValidityRestrictionType.TIME_START_AND_END:
            start = int.from_bytes(data[offset:offset + 4], 'big'); offset += 4
            end   = int.from_bytes(data[offset:offset + 4], 'big'); offset += 4
            diff  = max(0, end - start)
            validity_period = ValidityPeriod(
                start=start,
                duration=Duration(DurationChoice.SECONDS, diff),
            )

        elif vr_type == V1ValidityRestrictionType.TIME_START_AND_DURATION:
            start    = int.from_bytes(data[offset:offset + 4], 'big'); offset += 4
            dur_word = int.from_bytes(data[offset:offset + 2], 'big'); offset += 2
            units_v1 = (dur_word >> 13) & 0x07
            val      = dur_word & 0x1FFF
            dur_choice = _V1_UNITS_TO_DURATION.get(units_v1, DurationChoice.SECONDS)
            validity_period = ValidityPeriod(
                start=start,
                duration=Duration(dur_choice, val),
            )

        elif vr_type == V1ValidityRestrictionType.REGION:
            region_type = data[offset]; offset += 1
            if region_type == V1RegionType.ID:
                _dict   = data[offset]; offset += 1
                # region_identifier is int16_t (signed 2 bytes, big-endian)
                rid_signed = int.from_bytes(data[offset:offset + 2], 'big', signed=True)
                offset += 2
                rid = rid_signed if rid_signed >= 0 else rid_signed + 65536
                # Skip local_region: IntX
                _, offset = decode_length(data, offset)
                region = GeographicRegion(choice=RegionChoice.ID, ids=[rid])
            else:
                break   # unknown region type — skip remaining VRs

        else:
            break   # unknown VR type — stop

    offset = vr_end   # advance past all VR bytes

    # ── Signature ──────────────────────────────────────────────────────────────
    _sig_algo  = data[offset]; offset += 1   # PublicKeyAlgorithm byte
    _r_ecc     = data[offset]; offset += 1   # EccPointType byte (X_COORDINATE_ONLY = 0)
    r          = data[offset:offset + 32]; offset += 32
    s          = data[offset:offset + 32]; offset += 32
    signature  = EcdsaSignature(r=r, s=s, algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256)

    # ── Assemble Certificate object ───────────────────────────────────────────
    if validity_period is None:
        validity_period = ValidityPeriod(
            start=0, duration=Duration(DurationChoice.YEARS, 1)
        )

    if name:
        cert_id = CertificateId(CertIdChoice.NAME, name=name)
    else:
        cert_id = CertificateId(CertIdChoice.NONE)

    tbs = ToBeSignedCertificate(
        id=cert_id,
        craca_id=b'\x00\x00\x00',      # not in vanetza format; use zero
        crl_series=0,                   # not in vanetza format; use zero
        validity_period=validity_period,
        region=region,
        app_permissions=app_permissions if app_permissions else None,
        cert_issue_permissions=None,    # not in vanetza v2 format
        encryption_key=enc_key,
        verify_key_indicator=verify_key,
    )

    cert = Certificate(
        version=2,
        cert_type=CertificateType.EXPLICIT,
        issuer=issuer,
        tbs=tbs,
        signature=signature,
    )
    cert.encoded     = data[start_offset:offset]
    # Signing input = full cert bytes minus the trailing 66-byte signature
    # (1 PublicKeyAlgorithm + 1 EccPointType + 32 r + 32 s = 66 bytes).
    cert.tbs_encoded = data[start_offset:offset - 66]
    # Attach subject_type as an extra attribute (not in dataclass, but useful for display)
    cert.subject_type = subject_type

    return cert, offset


def hash_certificate_v1(cert_encoded: bytes) -> bytes:
    """
    Calculate vanetza HashedId8: SHA-256 of the full encoded certificate,
    take the last 8 bytes.  Matches vanetza's calculate_hash(Certificate).
    """
    return hashlib.sha256(cert_encoded).digest()[-8:]


# ── Main entry point: build and sign a certificate ────────────────────────────

def build_and_sign_v1(tbs: ToBeSignedCertificate,
                       issuer: IssuerIdentifier,
                       sign_priv_key,
                       algorithm: PublicKeyAlgorithm,
                       subject_type: int,
                       psids=None) -> Certificate:
    """
    Build a vanetza-format v1.2.1 certificate, sign it, and return a Certificate
    object with ``encoded`` and ``tbs_encoded`` (= signing input) populated.

    Args:
        tbs:          The to-be-signed data (validity period, keys, permissions).
        issuer:       IssuerIdentifier (self or SHA256 digest of issuing CA cert).
        sign_priv_key: Private key of the signing entity (issuer for sub-CAs,
                       subject for self-signed Root CA / TLM).
        algorithm:    Signing algorithm (must be ECDSA_NIST_P256 for vanetza v2).
        subject_type: V1SubjectType constant (ROOT_CA, EA, AA, EC, AT …).
        psids:        Optional override for app_permissions list.  When None,
                      tbs.app_permissions is used.
    """
    if algorithm not in (PublicKeyAlgorithm.ECDSA_NIST_P256,
                         PublicKeyAlgorithm.ECIES_NIST_P256):
        raise ValueError(
            "Vanetza v2 only supports ECDSA/ECIES P-256. "
            f"Got algorithm={algorithm!r}."
        )

    from .crypto import ecdsa_sign

    # Subject name
    name = (tbs.id.name
            if tbs.id.choice == CertIdChoice.NAME and tbs.id.name
            else '')

    # Encode structural pieces
    signer_info_bytes  = encode_signer_info_v1(issuer)
    subject_info_bytes = encode_subject_info_v1(subject_type, name)

    effective_psids = psids if psids is not None else tbs.app_permissions
    attrs_bytes = encode_subject_attributes_v1(
        vk=tbs.verify_key_indicator,
        ek=tbs.encryption_key,
        psids=effective_psids,
    )
    vr_bytes = encode_validity_restrictions_v1(tbs.validity_period, tbs.region)

    # Assemble signing input
    signing_input = compute_signing_input_v1(
        signer_info_bytes, subject_info_bytes, attrs_bytes, vr_bytes
    )

    # ECDSA sign
    r, s = ecdsa_sign(sign_priv_key, signing_input, algorithm)
    signature = EcdsaSignature(r=r, s=s, algorithm=algorithm)

    # Encode full certificate = signing_input + signature
    sig_bytes = encode_signature_v1(signature)
    full_encoded = signing_input + sig_bytes

    # Build Certificate object
    cert = Certificate(
        version=2,                          # vanetza always uses version 2
        cert_type=CertificateType.EXPLICIT,
        issuer=issuer,
        tbs=tbs,
        signature=signature,
    )
    cert.tbs_encoded = signing_input        # used for signature verification
    cert.encoded = full_encoded
    return cert
