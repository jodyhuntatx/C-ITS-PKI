#!/usr/bin/env bash
# Test 05 — Message Signing (Profiles 8.1, 8.2 — ETSI TS 103 097 V1.2.1)
# Covers: FR-SN-01 through FR-SN-07, AC-06, AC-07

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 05 — Message Signing (CAM/DENM/Generic)${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "FR-SN-01/02: EtsiTs103097Data-Signed structure"

assert_python_ok "CAM signed data structure creation" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V1_2_1)
cam_payload = b'CAM_PAYLOAD_v1_test'
signed = sign_cam(cam_payload, at_priv, at.encoded)
assert signed is not None and len(signed) > 100
print(f'Signed CAM: {len(signed)} bytes')
"

section "AC-06: CAM signed with AT passes verification"

assert_python_ok "AC-06: Full CAM sign and verify roundtrip" "
from src.crypto import generate_keypair, load_public_key_from_compressed
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam, verify_signed_data
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V1_2_1)
cam_payload = b'AC-06 CAM test payload'
signed = sign_cam(cam_payload, at_priv, at.encoded, use_digest=True)
# Verify using AT public key
vk = at.tbs.verify_key_indicator
at_pub_key = load_public_key_from_compressed(vk.point.curve, vk.point.compressed)
result = verify_signed_data(signed, at_pub_key, PublicKeyAlgorithm.ECDSA_NIST_P256, signer_cert_encoded=at.encoded)
assert result['valid'], f'Verification failed: {result.get(\"error\")}'
assert result['psid'] == ItsAid.CAM, f'PSID mismatch: {result[\"psid\"]}'
assert result['payload'] == cam_payload, 'Payload mismatch'
print('AC-06 PASSED: CAM sign+verify OK')
"

section "AC-07: DENM includes generationLocation and signer=certificate"

assert_python_ok "AC-07: DENM contains generationLocation" "
from src.crypto import generate_keypair, load_public_key_from_compressed
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_denm, verify_signed_data
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V1_2_1)
denm_payload = b'AC-07 DENM test payload'
# Berlin coordinates in 0.1 microdegree units
lat = int(52.5200 * 10_000_000)
lon = int(13.4050 * 10_000_000)
signed = sign_denm(denm_payload, at_priv, at.encoded, (lat, lon, 340))
vk = at.tbs.verify_key_indicator
at_pub_key = load_public_key_from_compressed(vk.point.curve, vk.point.compressed)
result = verify_signed_data(signed, at_pub_key, PublicKeyAlgorithm.ECDSA_NIST_P256)
assert result['valid'], f'DENM verification failed: {result.get(\"error\")}'
assert result['psid'] == ItsAid.DENM, f'PSID mismatch'
assert result['generation_location'] is not None, 'generationLocation must be present'
assert result['signer']['type'] == 'certificate', 'DENM signer must be certificate'
print('AC-07 PASSED: DENM generationLocation + signer=certificate OK')
"

section "FR-SN-05: generationTime always present"

assert_python_ok "generationTime present in signed data" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam, verify_signed_data
from src.crypto import load_public_key_from_compressed
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V1_2_1)
signed = sign_cam(b'test', at_priv, at.encoded)
vk = at.tbs.verify_key_indicator
pub_key = load_public_key_from_compressed(vk.point.curve, vk.point.compressed)
result = verify_signed_data(signed, pub_key, signer_cert_encoded=at.encoded)
assert result['generation_time_us'] > 0, 'generationTime must be present and > 0'
print(f'generationTime OK: {result[\"generation_time_us\"]}')
"

section "FR-SN-07: External payload signing"

assert_python_ok "EtsiTs103097Data-SignedExternalPayload" "
from src.crypto import generate_keypair, sha256
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_data_external_payload
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V1_2_1)
external_data = b'large_external_payload_data'
payload_hash = sha256(external_data)
# v2 generic profile (clause 7.3): non-CAM/DENM ITS-AID, generation_location required
signed = sign_data_external_payload(payload_hash, 623, at_priv, at.encoded, generation_location=(525200000, 134050000, 340))
assert signed is not None and len(signed) > 80
print(f'External payload signed: {len(signed)} bytes')
"

section "Verification negative cases"

assert_python_ok "Digest-signed message needs the signer certificate" "
from src.crypto import generate_keypair, load_public_key_from_compressed, sha256
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam, sign_denm, sign_data_external_payload, verify_signed_data
V = EtsiVersion.V1_2_1
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=V)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=V)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=V)
signed = sign_cam(b'payload', at_priv, at.encoded, use_digest=True)
result = verify_signed_data(signed, at_pub)
assert not result['valid'] and 'certificate is required' in result['error'], result
print('rejected without certificate:', result['error'])
"

assert_python_ok "Tampered payload, wrong AT and wrong digest are rejected" "
from src.crypto import generate_keypair, load_public_key_from_compressed, sha256
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam, sign_denm, sign_data_external_payload, verify_signed_data
V = EtsiVersion.V1_2_1
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=V)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=V)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=V)
signed = sign_cam(b'payload', at_priv, at.encoded, use_digest=False)
tampered = bytearray(signed); tampered[signed.find(b'payload')] ^= 1
assert not verify_signed_data(bytes(tampered), at_pub)['valid'], 'tampered payload accepted'
other_priv, other_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
other = issue_authorization_ticket(other_priv, other_pub, aa, aa_s_priv, version=V)
assert not verify_signed_data(signed, other_pub)['valid'], 'wrong public key accepted'
assert not verify_signed_data(signed, None, signer_cert_encoded=other.encoded)['valid'], 'wrong --at-cert accepted'
digest_signed = sign_cam(b'payload', at_priv, at.encoded, use_digest=True)
assert not verify_signed_data(digest_signed, None, signer_cert_encoded=other.encoded)['valid'], 'wrong digest accepted'
print('all negative cases rejected')
"

assert_python_ok "External payload signature verifies" "
from src.crypto import generate_keypair, load_public_key_from_compressed, sha256
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam, sign_denm, sign_data_external_payload, verify_signed_data
V = EtsiVersion.V1_2_1
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=V)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=V)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=V)
signed = sign_data_external_payload(sha256(b'external'), 623, at_priv, at.encoded, generation_location=(525200000, 134050000, 340))
result = verify_signed_data(signed, None, signer_cert_encoded=at.encoded, external_payload_hash=sha256(b'external'))
assert result['valid'] and result['payload'] == sha256(b'external'), result
assert not verify_signed_data(signed, None, external_payload_hash=sha256(b'other'))['valid'], 'wrong external data accepted'
print('external payload OK')
"

section "Conformance with TS 103 097 v1.2.1 SecuredMessage (vanetza v2)"

assert_python_ok "v2 certificates produce a v2 SecuredMessage signed over convert_for_signing" "
from src.crypto import generate_keypair, load_public_key_from_compressed, sha256
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam, sign_denm, sign_data_external_payload, verify_signed_data
V = EtsiVersion.V1_2_1
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=V)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=V)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=V)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
signed = sign_cam(b'cam', at_priv, at.encoded, use_digest=True)
assert signed[0] == 2, 'protocol version must be 2'
# trailer: length(67) | type Signature(1) | ECDSA_NISTP256_With_SHA256(0) | x-only(0) | R.x | s
assert signed[-68:-64] == bytes([67, 1, 0, 0]), signed[-68:-64].hex()
signing_input = signed[:-66]  # up to and including the signature trailer type
r, s = signed[-64:-32], signed[-32:]
at_pub.verify(encode_dss_signature(int.from_bytes(r, 'big'), int.from_bytes(s, 'big')),
              signing_input, ec.ECDSA(hashes.SHA256()))
print('v2 SecuredMessage layout and signing input OK')
"


section "TS 103 097 V1.2.1 clauses 5.2 and 7.3 (KD-3, KD-4)"

assert_python_ok "KD-3: signed_external carries no payload data; signature covers the external data" "
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from src.pki import CITSPKI
from src.types import EtsiVersion
from src.crypto import sha256
from src.signing import sign_data_external_payload, v2_parse
from src.v1_encoding import encode_length
pki = CITSPKI(version=EtsiVersion.V1_2_1); pki.initialise(); at = pki.issue_authorization_ticket()
ext = sha256(b'external data')
m = sign_data_external_payload(ext, 623, at['sign_priv_key'], at['at'], generation_location=(525200000, 134050000, 340))
p = v2_parse(m)
assert p['payload_type'] == 3 and p['payload'] == b'', 'payload data must be absent (clause 5.2)'
start = p['payload_start']
# independent signing input: external data at the position of a non-external payload
signing_input = m[:start] + bytes([3]) + encode_length(len(ext)) + ext + m[start + 2:p['trailer_start'] + 1]
r, s = m[-64:-32], m[-32:]
at['sign_pub_key'].verify(encode_dss_signature(int.from_bytes(r, 'big'), int.from_bytes(s, 'big')),
                          signing_input, ec.ECDSA(hashes.SHA256()))
print('empty wire payload, signature over external data verified independently')
"

assert_python_ok "KD-4: generic v2 profile enforces certificate signer and generation_location" "
from src.pki import CITSPKI
from src.types import EtsiVersion
from src.crypto import sha256
from src.signing import sign_data, sign_data_external_payload, v2_parse
pki = CITSPKI(version=EtsiVersion.V1_2_1); pki.initialise(); at = pki.issue_authorization_ticket()
k, c = at['sign_priv_key'], at['at']
m = v2_parse(sign_data(b'generic', 623, k, c, use_digest=True, generation_location=(525200000, 134050000, 340)))
assert m['signer_cert'] is not None and m['signer_digest'] is None, 'generic signer must be certificate'
assert m['generation_location'] == (525200000, 134050000, 340)
for bad in (lambda: sign_data(b'x', 623, k, c),
            lambda: sign_data_external_payload(sha256(b'x'), 623, k, c),
            lambda: sign_data_external_payload(sha256(b'x'), 36, k, c, generation_location=(525200000, 134050000, 340))):
    try:
        bad()
    except ValueError:
        continue
    raise AssertionError('profile violation accepted')
# CAM/DENM keep their own profiles (digest allowed, no location)
cam = v2_parse(sign_data(b'cam', 36, k, c, use_digest=True))
assert cam['signer_digest'] is not None and cam['generation_location'] is None
print('generic profile enforced; CAM profile unchanged')
"

print_summary
