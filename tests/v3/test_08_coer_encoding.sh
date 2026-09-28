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
# COER: preamble (signature present) first, then version 3, type explicit(0),
# issuer CHOICE tag 0x81 (self) with HashAlgorithm sha256(0)
assert cert.encoded[:5] == bytes([0x80, 0x03, 0x00, 0x81, 0x00]), cert.encoded[:5].hex()
# Not PEM (no '-----BEGIN')
assert b'-----' not in cert.encoded
print('COER binary format OK')
"

section "Conformance with vanetza's ASN.1 schema (IEEE 1609.2-2016 / TS 103 097 v1.3.1)"

assert_python_ok "Full chain decodes with the schema and re-encodes byte-identically" "
from src.pki import CITSPKI
from src.types import EtsiVersion
from src.encoding import asn1_codec
pki = CITSPKI(version=EtsiVersion.V2_2_1)
pki.initialise()
at = pki.issue_authorization_ticket()['certificate']
for name, cert in [('root', pki.root_ca.certificate), ('tlm', pki.tlm.certificate),
                   ('ea', pki.ea.certificate), ('aa', pki.aa.certificate), ('at', at)]:
    value = asn1_codec.decode('EtsiTs103097Certificate', cert.encoded)
    assert asn1_codec.encode('EtsiTs103097Certificate', value) == cert.encoded, name
    assert value['version'] == 3 and 'signature' in value, name
print('all certificates conform')
"

assert_python_ok "Legacy non-COER encoding (index CHOICE tags, trailing bitmap) is rejected" "
from src.encoding import decode_certificate
legacy = bytes.fromhex('0300010001') + b'\\x0dC-ITS-Root-CA' + bytes(5) + bytes.fromhex('2ac217a506000a')
try:
    decode_certificate(legacy)
except ValueError as e:
    print('rejected:', str(e)[:80])
else:
    raise AssertionError('legacy encoding accepted')
"

assert_python_ok "Signatures use the IEEE 1609.2 input Hash(Hash(tbs) || Hash(issuer))" "
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from src.pki import CITSPKI
from src.types import EtsiVersion
from src.encoding import decode_certificate
pki = CITSPKI(version=EtsiVersion.V2_2_1)
pki.initialise()
root, aa = pki.root_ca.certificate, pki.aa.certificate
def check(cert, issuer_pub, issuer_encoded):
    decoded, _ = decode_certificate(cert.encoded)
    data = hashlib.sha256(decoded.tbs_encoded).digest() + hashlib.sha256(issuer_encoded).digest()
    sig = encode_dss_signature(int.from_bytes(decoded.signature.r, 'big'), int.from_bytes(decoded.signature.s, 'big'))
    issuer_pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
check(root, pki.root_ca.sign_pub_key, b'')              # self-signed: empty issuer input
check(aa, pki.root_ca.sign_pub_key, root.encoded)
at = pki.issue_authorization_ticket()['certificate']
check(at, pki.aa.sign_pub_key, aa.encoded)
print('root, AA and AT signatures match IEEE 1609.2 clause 5.3.1.2.2')
"

assert_python_ok "Butterfly ATs are conformant v3 certificates issued by the AA" "
from src.pki import CITSPKI
from src.types import EtsiVersion
from src.crypto import generate_keypair, random_bytes, hash_certificate
from src.types import PublicKeyAlgorithm, IssuerChoice, CertIdChoice
from src.encoding import decode_certificate, asn1_codec
from src.verification import verify_certificate_signature
pki = CITSPKI(version=EtsiVersion.V2_2_1)
pki.initialise()
cat_priv, _ = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
tickets = pki.issue_butterfly_authorization_tickets(cat_priv, random_bytes(16), i_value=1000, count=3, mode='unified')
aa = pki.aa.certificate
for t in tickets:
    cert, _ = decode_certificate(t['at'])
    asn1_codec.decode('EtsiTs103097Certificate', t['at'])
    assert cert.issuer.choice == IssuerChoice.SHA256_AND_DIGEST
    assert cert.issuer.digest == hash_certificate(aa.encoded, PublicKeyAlgorithm.ECDSA_NIST_P256)
    assert cert.tbs.id.choice == CertIdChoice.NONE and not cert.tbs.cert_issue_permissions
    assert verify_certificate_signature(cert, aa)
    # the expanded private key belongs to the certified public key
    from src.crypto import public_key_to_point
    assert public_key_to_point(t['sign_pub_key']).compressed == cert.tbs.verify_key_indicator.point.compressed
print(f'{len(tickets)} butterfly ATs conform and chain to the AA')
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
pki = CITSPKI(version=EtsiVersion.V2_2_1)
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
pki = CITSPKI(version=EtsiVersion.V2_2_1)
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
