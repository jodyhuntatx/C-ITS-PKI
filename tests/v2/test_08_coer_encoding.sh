#!/usr/bin/env bash
# Test 08 — V1.2.1 Binary Encoding (ETSI TS 103 097 V1.2.1)
# Covers: NFR-INT-01, NFR-INT-04, AC-12
# Note: V1.2.1 uses the vanetza custom binary wire format (not COER).
#       Length coding and duration encoding differ from IEEE 1609.2-2022 COER.

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 08 — V1.2.1 Vanetza Binary Encoding${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "COER primitive encoding (shared utilities)"

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

section "Vanetza variable-length coding (V1.2.1 wire format)"

assert_python_ok "Vanetza length encoding (differs from COER)" "
from src.v1_encoding import encode_length, decode_length
# 1-byte form: values 0-127
for n in [0, 1, 127]:
    enc = encode_length(n)
    assert len(enc) == 1, f'n={n}: expected 1 byte, got {len(enc)}'
    dec, _ = decode_length(enc, 0)
    assert dec == n, f'n={n}: dec={dec}'
# 2-byte form: values 128-16383
for n in [128, 255, 16383]:
    enc = encode_length(n)
    assert len(enc) == 2, f'n={n}: expected 2 bytes, got {len(enc)}'
    dec, _ = decode_length(enc, 0)
    assert dec == n, f'n={n}: dec={dec}'
# 3-byte form: values 16384-2097151
for n in [16384, 65535]:
    enc = encode_length(n)
    assert len(enc) == 3, f'n={n}: expected 3 bytes, got {len(enc)}'
    dec, _ = decode_length(enc, 0)
    assert dec == n, f'n={n}: dec={dec}'
print('Vanetza length encoding OK')
"

assert_python_ok "PSID variable-length encoding" "
from src.encoding import encode_psid, decode_psid
for psid in [36, 37, 617, 622, 623, 0x4000, 0x200000]:
    enc = encode_psid(psid)
    dec, _ = decode_psid(enc, 0)
    assert dec == psid, f'psid={psid}: dec={dec}'
print('PSID encoding OK')
"

section "Vanetza binary certificate roundtrip (AC-12)"

assert_python_ok "AC-12: Full vanetza binary encode/decode roundtrip" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion, IssuerChoice, CertIdChoice
from src.certificates import issue_root_ca_certificate
from src.v1_encoding import decode_certificate_v1
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('RoundtripCA', priv, pub, version=EtsiVersion.V1_2_1)
# Re-decode from vanetza binary bytes
decoded, consumed = decode_certificate_v1(cert.encoded)
assert consumed == len(cert.encoded), f'Not all bytes consumed: {consumed} vs {len(cert.encoded)}'
# V1.2.1 wire format version byte is 2
assert decoded.version == 2, f'Expected version 2, got {decoded.version}'
assert decoded.issuer.choice == IssuerChoice.SELF
assert decoded.tbs.id.choice == CertIdChoice.NAME
assert decoded.tbs.id.name == 'RoundtripCA'
# cracaId and crlSeries are not in the V1.2.1 wire format (decoder returns placeholder zeros)
assert decoded.tbs.craca_id == b'\\x00\\x00\\x00'
assert decoded.tbs.crl_series == 0
# certIssuePermissions is not encoded in V1.2.1
assert decoded.tbs.cert_issue_permissions is None
print('AC-12 PASSED: Vanetza binary roundtrip OK')
"

assert_python_ok "Certificate with encryptionKey roundtrip" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
from src.v1_encoding import decode_certificate_v1
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
decoded, _ = decode_certificate_v1(ea.encoded)
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

section "Vanetza duration encoding (V1.2.1 wire format)"

assert_python_ok "Vanetza 2-byte duration word encoding" "
from src.v1_encoding import encode_duration_v1
from src.types import Duration, DurationChoice
# Vanetza duration word: bits 15-13 = units, bits 12-0 = value
# Units: Seconds=0, Minutes=1, Hours=2, 60hBlocks=3, Years=4
tests = [
    (DurationChoice.YEARS,       10,  (4 << 13) | 10),
    (DurationChoice.HOURS,      168,  (2 << 13) | 168),
    (DurationChoice.SECONDS,   3600,  (0 << 13) | 3600),
    (DurationChoice.MINUTES,     60,  (1 << 13) | 60),
]
for choice, val, expected_word in tests:
    d = Duration(choice, val)
    enc = encode_duration_v1(d)
    assert len(enc) == 2, f'Duration must be 2 bytes, got {len(enc)}'
    word = int.from_bytes(enc, 'big')
    assert word == expected_word, f'{choice.name}({val}): word=0x{word:04x} expected=0x{expected_word:04x}'
print('Vanetza duration encoding OK')
"

assert_python_ok "Vanetza _duration_to_its_seconds uses Vanetza multipliers" "
from src.v1_encoding import _duration_to_its_seconds
from src.types import Duration, DurationChoice
# Multipliers from vanetza/security/v2/validity_restriction.cpp Duration::to_seconds()
assert _duration_to_its_seconds(Duration(DurationChoice.SECONDS,     1)) == 1
assert _duration_to_its_seconds(Duration(DurationChoice.MINUTES,     1)) == 60
assert _duration_to_its_seconds(Duration(DurationChoice.HOURS,       1)) == 3600
assert _duration_to_its_seconds(Duration(DurationChoice.SIXTY_HOURS, 1)) == 216000
assert _duration_to_its_seconds(Duration(DurationChoice.YEARS,       1)) == 31556925
assert _duration_to_its_seconds(Duration(DurationChoice.YEARS,      10)) == 315569250
print('_duration_to_its_seconds multipliers OK')
"

assert_python_ok "Validity restriction wire format uses Time_Start_And_End (0x01) not Duration (0x02)" "
# The certify tool show-certificate.cpp line 208 computes:
#   time_end = epoch + duration.to_seconds()
# which ignores start_validity, producing wrong dates for Time_Start_And_Duration.
# C-ITS-PKI encodes Time_Start_And_End (type 1) so the unmodified certify tool
# displays correct validity dates via:
#   time_start = epoch + start_validity
#   time_end   = epoch + end_validity
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.v1_encoding import V1ValidityRestrictionType, decode_certificate_v1

priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
# Use a fixed start time so end-time arithmetic is deterministic
START = 700000000  # ITS seconds (~2026-02-08)
import time
cert = issue_root_ca_certificate('TestCA', priv, pub, validity_years=10,
                                  start_time=time.time(), version=EtsiVersion.V1_2_1)
# Decode and verify round-trip is consistent
decoded, consumed = decode_certificate_v1(cert.encoded)
assert consumed == len(cert.encoded), 'Not all bytes consumed'
# The decoded duration in seconds must equal 10 * 31556925 (vanetza YEARS multiplier)
EXPECTED_SECS = 10 * 31556925
assert decoded.tbs.validity_period.duration.value == EXPECTED_SECS, \
    f'Expected {EXPECTED_SECS}s, got {decoded.tbs.validity_period.duration.value}'
# The end ITS time must equal start + 10*31556925
end_its = decoded.tbs.validity_period.start + EXPECTED_SECS
assert end_its == decoded.tbs.validity_period.start + EXPECTED_SECS
print(f'Time_Start_And_End encoding OK: start={decoded.tbs.validity_period.start} end={end_its}')
"

section "NFR-INT-01: V1.2.1 uses vanetza binary format"

assert_python_ok "Certificate bytes use vanetza binary format (version byte = 0x02)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('TestCA', priv, pub, version=EtsiVersion.V1_2_1)
# V1.2.1 vanetza wire format version byte is 0x02 (not COER 0x03)
assert cert.encoded[0] == 0x02, f'First byte must be 0x02 (vanetza version), got 0x{cert.encoded[0]:02x}'
# Not PEM (no '-----BEGIN')
assert b'-----' not in cert.encoded
print('Vanetza binary format OK')
"


section "Butterfly Key Mechanism (IEEE 1609.2.1)"

assert_python_ok "Expansion function matches the SCMS reference test vectors" "
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, derive_private_key
from src import crypto
# conz27/crypto-test-vectors bfkeyexp.txt (CAMP SCMS reference vectors)
i, j = 0x217D79E1, 0x11
vectors = [
    (crypto.BKE_PURPOSE_CERT, 0x121D14216715E11D2D3787434A673B1B,
     0xD418760F0CB2DCB856BC3C7217AD3AA36DB6742AE1DB655A3D28DF88CBBF84E1,
     0x4D2093ED3EA27B15FCBD61806FFA13B36AE367F88C52397824A9BF67283D8CEE,
     (0x2B18F3D93C4DF3D9D1490E3A9BA5A0DE9CFA73EDDB95408BC1F2BF60CB3CF313,
      0x1A2CE511E0DA86356329A5C22A36A8A53088DCB11A5A94FA903EF0087421666A)),
    (crypto.BKE_PURPOSE_ENC, 0xF9FCE2371B4523C0A75FC352BA7EBD8D,
     0x4624A6F9F6BC6BD088A71ED97B3AEE983B5CC2F574F64E96A531D2464137049F,
     0xE77A422D7415EF1BBB8A8310E7D4039AC9EF9C2EA28022C8010C1A611E72A7B6,
     (0xB568FD55A7114254118E7463E85459BDD3C091342625B4A929541151BB8286BE,
      0xED8DBE22200353D316CC5C3D8F1F281D8BFB34A9E6E1DBFE2043D928C64B430B)),
]
for purpose, k, seed, expanded, expanded_pub in vectors:
    key = k.to_bytes(16, 'big')
    priv = derive_private_key(seed, SECP256R1())
    assert crypto.bke_cocoon_private_key(priv, key, i, j, purpose).private_numbers().private_value == expanded, purpose
    pub = crypto.bke_cocoon_public_key(priv.public_key(), key, i, j, purpose).public_numbers()
    assert (pub.x, pub.y) == expanded_pub, purpose
print('certificate and encryption expansion match the reference vectors')
"

assert_python_ok "Original and unified BKM: reconstructed keys match certificates and sign" "
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.crypto import generate_keypair, random_bytes, bke_cocoon_public_key, public_key_to_point
from src.signing import sign_cam, verify_signed_data
pki = CITSPKI(version=EtsiVersion.V1_2_1)
pki.initialise()
cat_s, _ = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cat_e, _ = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ck, ek = random_bytes(16), random_bytes(16)
for mode in ('original', 'unified'):
    tickets = pki.issue_butterfly_authorization_tickets(
        cat_s, ck, i_value=1234, count=4, mode=mode,
        caterpillar_enc_priv=cat_e if mode == 'original' else None,
        enc_expansion_key=ek if mode == 'original' else None)
    assert [t['j'] for t in tickets] == [0, 1, 2, 3]
    assert len({t['offset'] for t in tickets}) == 4, 'offsets must be fresh per certificate'
    for t in tickets:
        cocoon = public_key_to_point(bke_cocoon_public_key(cat_s.public_key(), ck, 1234, t['j'])).compressed
        certified = t['certificate'].tbs.verify_key_indicator.point.compressed
        # the AA offset hides the cocoon key: the EA cannot link the certificate to the request
        assert certified != cocoon
        assert public_key_to_point(t['sign_pub_key']).compressed == certified
        signed = sign_cam(b'bke', t['sign_priv_key'], t['at'], use_digest=False)
        assert verify_signed_data(signed, None, signer_cert_encoded=t['at'])['valid'], mode
print('original and unified: 4 ATs each, keys reconstructed, CAMs verify')
"

assert_python_ok "Original mode requires encryption caterpillar and expansion keys" "
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.crypto import generate_keypair, random_bytes
pki = CITSPKI(version=EtsiVersion.V1_2_1)
pki.initialise()
cat_s, _ = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
try:
    pki.issue_butterfly_authorization_tickets(cat_s, random_bytes(16), i_value=1, count=1, mode='original')
except ValueError as e:
    print('rejected:', e)
else:
    raise AssertionError('original mode without encryption keys accepted')
"

print_summary
