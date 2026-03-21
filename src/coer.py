"""
COER (Canonical Octet Encoding Rules) encoder/decoder for IEEE 1609.2 / ETSI TS 103 097.
Based on ITU-T X.696 and IEEE Std 1609.2-2025 Annex B.
"""
import struct
from typing import Tuple


# ── Length encoding ───────────────────────────────────────────────────────────

def encode_length(n: int) -> bytes:
    """COER definite-length encoding (short or long form)."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82]) + n.to_bytes(2, 'big')
    else:
        return bytes([0x83]) + n.to_bytes(3, 'big')


def decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Return (length, new_offset)."""
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    num_bytes = b & 0x7F
    length = int.from_bytes(data[offset + 1: offset + 1 + num_bytes], 'big')
    return length, offset + 1 + num_bytes


# ── Fixed-width integer types ─────────────────────────────────────────────────

def encode_uint8(v: int) -> bytes:
    return bytes([v & 0xFF])

def encode_uint16(v: int) -> bytes:
    return v.to_bytes(2, 'big')

def encode_uint32(v: int) -> bytes:
    return v.to_bytes(4, 'big')

def encode_uint64(v: int) -> bytes:
    return v.to_bytes(8, 'big')

def decode_uint8(data: bytes, offset: int) -> Tuple[int, int]:
    return data[offset], offset + 1

def decode_uint16(data: bytes, offset: int) -> Tuple[int, int]:
    return int.from_bytes(data[offset:offset+2], 'big'), offset + 2

def decode_uint32(data: bytes, offset: int) -> Tuple[int, int]:
    return int.from_bytes(data[offset:offset+4], 'big'), offset + 4

def decode_uint64(data: bytes, offset: int) -> Tuple[int, int]:
    return int.from_bytes(data[offset:offset+8], 'big'), offset + 8


# ── Variable-length COER-encoded integer ─────────────────────────────────────

def encode_varint(v: int) -> bytes:
    """Encode non-negative integer with COER length prefix."""
    if v == 0:
        return bytes([0x01, 0x00])
    n = (v.bit_length() + 7) // 8
    return encode_length(n) + v.to_bytes(n, 'big')


def decode_varint(data: bytes, offset: int) -> Tuple[int, int]:
    length, offset = decode_length(data, offset)
    v = int.from_bytes(data[offset:offset+length], 'big')
    return v, offset + length


# ── Octet strings ─────────────────────────────────────────────────────────────

def encode_octet_string(data: bytes) -> bytes:
    return encode_length(len(data)) + data

def decode_octet_string(data: bytes, offset: int) -> Tuple[bytes, int]:
    length, offset = decode_length(data, offset)
    return data[offset:offset+length], offset + length

def encode_fixed_octet_string(data: bytes) -> bytes:
    """Fixed-length octet string (no length prefix)."""
    return data

def decode_fixed_octet_string(data: bytes, offset: int, length: int) -> Tuple[bytes, int]:
    return data[offset:offset+length], offset + length


# ── UTF8String ────────────────────────────────────────────────────────────────

def encode_utf8string(s: str) -> bytes:
    encoded = s.encode('utf-8')
    return encode_length(len(encoded)) + encoded

def decode_utf8string(data: bytes, offset: int) -> Tuple[str, int]:
    raw, offset = decode_octet_string(data, offset)
    return raw.decode('utf-8'), offset


# ── CHOICE encoding (open type, index-tagged) ────────────────────────────────

def encode_choice(index: int, value: bytes) -> bytes:
    """
    COER CHOICE: single-byte tag (0-based index) followed by encoded alternative.
    For alternatives 0-127 the tag fits in one byte.
    """
    if index < 0x80:
        return bytes([index]) + value
    raise ValueError(f"CHOICE index {index} >= 128 not supported")

def decode_choice_tag(data: bytes, offset: int) -> Tuple[int, int]:
    return data[offset], offset + 1


# ── SEQUENCE with optional-field presence bitmap ─────────────────────────────

def encode_sequence(mandatory: list[bytes], optional: list[tuple[bool, bytes]]) -> bytes:
    """
    Encode a SEQUENCE.
    mandatory: list of already-encoded mandatory field bytes.
    optional:  list of (present: bool, encoded_bytes) for optional/default fields.
    The presence bitmap is prepended when there are optional fields.
    Bitmap format: bit 7 of first byte = first optional field, etc.
    """
    result = b''
    if optional:
        # Build bitmap
        num_optional = len(optional)
        num_bytes = (num_optional + 7) // 8
        bitmap = 0
        for i, (present, _) in enumerate(optional):
            if present:
                bitmap |= (1 << (num_bytes * 8 - 1 - i))
        result += bitmap.to_bytes(num_bytes, 'big')

    for field in mandatory:
        result += field
    for present, enc in optional:
        if present:
            result += enc
    return result


# ── Enumerated ────────────────────────────────────────────────────────────────

def encode_enumerated(v: int) -> bytes:
    """COER ENUMERATED: encode as Uint8 for values 0-127."""
    return bytes([v])

def decode_enumerated(data: bytes, offset: int) -> Tuple[int, int]:
    return data[offset], offset + 1


# ── Bit string (used for flags) ───────────────────────────────────────────────

def encode_bit_string(bits: int, num_bits: int) -> bytes:
    """Encode a bit string with given number of bits."""
    num_bytes = (num_bits + 7) // 8
    unused = num_bytes * 8 - num_bits
    value = bits << unused
    return encode_length(num_bytes + 1) + bytes([unused]) + value.to_bytes(num_bytes, 'big')

def decode_bit_string(data: bytes, offset: int) -> Tuple[Tuple[int, int], int]:
    """Returns (bits, num_bits), new_offset."""
    length, offset = decode_length(data, offset)
    unused = data[offset]
    raw = int.from_bytes(data[offset+1:offset+length], 'big')
    num_bits = (length - 1) * 8 - unused
    bits = raw >> unused
    return (bits, num_bits), offset + length


# ── NULL ──────────────────────────────────────────────────────────────────────

def encode_null() -> bytes:
    return b''
