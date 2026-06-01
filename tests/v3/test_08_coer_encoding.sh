#!/usr/bin/env bash
# Test 08 — COER Encoding Correctness (NFR-INT-01, AC-12 — ETSI TS 103 097 V2.2.1)
# Covers: NFR-INT-01, NFR-INT-04, AC-11, AC-12

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 08 — COER Encoding${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "COER primitive encoding"

assert_python_ok "Uint8 encoding" "
from src.coer import encode_uint8, decode_uint8
for v in [0, 1, 127, 255]:
    enc = encode_uint8(v)
    assert len(enc) == 1
    dec, _ = decode_uint8(enc, 0)
    assert dec == v, f'v={v}: dec={dec}'
print('Uint8 OK')
"

assert_python_ok "Uint16 encoding" "
from src.coer import encode_uint16, decode_uint16
for v in [0, 1, 256, 65535]:
    enc = encode_uint16(v)
    assert len(enc) == 2
    dec, _ = decode_uint16(enc, 0)
    assert dec == v
print('Uint16 OK')
"

assert_python_ok "Uint32 encoding (Time32)" "
from src.coer import encode_uint32, decode_uint32
for v in [0, 1, 0xDEADBEEF, 0xFFFFFFFF]:
    enc = encode_uint32(v)
    assert len(enc) == 4
    dec, _ = decode_uint32(enc, 0)
    assert dec == v
print('Uint32 OK')
"

assert_python_ok "Length encoding (short and long form)" "
from src.coer import encode_length, decode_length
for n in [0, 1, 127, 128, 255, 256, 65535]:
    enc = encode_length(n)
    dec, _ = decode_length(enc, 0)
    assert dec == n, f'n={n}: dec={dec}'
print('Length encoding OK')
"

assert_python_ok "PSID variable-length encoding" "
from src.encoding import encode_psid, decode_psid
for psid in [36, 37, 617, 622, 623, 0x4000, 0x200000]:
    enc = encode_psid(psid)
    dec, _ = decode_psid(enc, 0)
    assert dec == psid, f'psid={psid}: dec={dec}'
print('PSID encoding OK')
"

assert_python_ok "CHOICE encoding (single-byte tag)" "
from src.coer import encode_choice, decode_choice_tag
for idx in [0, 1, 2, 3, 127]:
    payload = b'\\x01\\x02\\x03'
    enc = encode_choice(idx, payload)
    tag, offset = decode_choice_tag(enc, 0)
    assert tag == idx
    assert enc[offset:] == payload
print('CHOICE encoding OK')
"

section "Certificate structure encoding roundtrip (AC-12)"

assert_python_ok "AC-12: Full certificate COER encode/decode roundtrip" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.encoding import encode_certificate, decode_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('RoundtripCA', priv, pub, version=EtsiVersion.V2_2_1)
# Re-decode from COER bytes
decoded, consumed = decode_certificate(cert.encoded)
assert consumed == len(cert.encoded), f'Not all bytes consumed: {consumed} vs {len(cert.encoded)}'
assert decoded.version == cert.version
assert decoded.cert_type == cert.cert_type
assert decoded.issuer.choice == cert.issuer.choice
assert decoded.tbs.id.name == 'RoundtripCA'
assert decoded.tbs.craca_id == b'\\x00\\x00\\x00'
assert decoded.tbs.crl_series == 0
print('AC-12 PASSED: Certificate COER roundtrip OK')
"

assert_python_ok "Certificate with encryptionKey roundtrip" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
from src.encoding import decode_certificate
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
decoded, _ = decode_certificate(ea.encoded)
decoded.encoded = ea.encoded
assert decoded.tbs.encryption_key is not None
assert decoded.tbs.encryption_key.point.compressed is not None
assert len(decoded.tbs.encryption_key.point.compressed) == 33
print('EA with encryptionKey roundtrip OK')
"

section "ITS time encoding"

assert_python_ok "ITS time epoch: 2004-01-01 = unix 1072915200" "
from src.types import unix_to_its_time32, its_time32_to_unix
its_epoch_unix = 1072915200  # 2004-01-01T00:00:00Z
assert unix_to_its_time32(its_epoch_unix) == 0
assert its_time32_to_unix(0) == its_epoch_unix
# 1 year after epoch
assert unix_to_its_time32(its_epoch_unix + 365 * 86400) == 365 * 86400
print('ITS epoch OK')
"

assert_python_ok "Duration choice encoding" "
from src.encoding import encode_duration, decode_duration
from src.types import Duration, DurationChoice
for (choice, val) in [(DurationChoice.YEARS, 10), (DurationChoice.HOURS, 168), (DurationChoice.SECONDS, 3600)]:
    d = Duration(choice, val)
    enc = encode_duration(d)
    dec, _ = decode_duration(enc, 0)
    assert dec.choice == choice and dec.value == val
print('Duration encoding OK')
"

section "NFR-INT-01: All structures use COER"

assert_python_ok "Certificate bytes are pure binary (COER, not PEM/DER)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('TestCA', priv, pub, version=EtsiVersion.V2_2_1)
# Version byte must be 3
assert cert.encoded[0] == 3, f'First byte must be version 3, got {cert.encoded[0]}'
# Not PEM (no '-----BEGIN')
assert b'-----' not in cert.encoded
print('COER binary format OK')
"

print_summary
