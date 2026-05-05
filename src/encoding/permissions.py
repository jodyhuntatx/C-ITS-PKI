"""
PSID and permission structure encoding/decoding.

Covers the COER representations of:
  - Psid / PSID variable-length encoding  (IEEE 1609.2 clause 6.3.23)
  - PsidSsp / SequenceOfPsidSsp           (clause 6.3.28)
  - PsidGroupPermissions                  (clause 6.4.4)
"""
from ..coer import encode_uint8, encode_choice, encode_octet_string
from ..types import PsidSsp, PsidGroupPermissions


# ── PSID variable-length encoding ─────────────────────────────────────────────

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


# ── PsidSsp (appPermissions) encoding ─────────────────────────────────────────

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


# ── PsidGroupPermissions (certIssuePermissions) encoding ──────────────────────

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
