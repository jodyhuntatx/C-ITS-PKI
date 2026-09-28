#!/usr/bin/env bash
# Test 05 — Message Signing (Profiles 10.1, 10.2 — ETSI TS 103 097 V2.2.1)
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
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V2_2_1)
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
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V2_2_1)
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
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V2_2_1)
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
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V2_2_1)
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
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V2_2_1)
external_data = b'large_external_payload_data'
payload_hash = sha256(external_data)
signed = sign_data_external_payload(payload_hash, 36, at_priv, at.encoded)
assert signed is not None and len(signed) > 80
print(f'External payload signed: {len(signed)} bytes')
"

section "Verification negative cases"

assert_python_ok "Digest-signed message needs the signer certificate" "
from src.crypto import generate_keypair, load_public_key_from_compressed, sha256
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam, sign_denm, sign_data_external_payload, verify_signed_data
V = EtsiVersion.V2_2_1
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
V = EtsiVersion.V2_2_1
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
V = EtsiVersion.V2_2_1
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=V)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=V)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=V)
signed = sign_data_external_payload(sha256(b'external'), 36, at_priv, at.encoded)
result = verify_signed_data(signed, None, signer_cert_encoded=at.encoded)
assert result['valid'] and result['payload'] == sha256(b'external'), result
print('external payload OK')
"

section "Conformance with IEEE 1609.2-2016 / TS 103 097 v1.3.1 (vanetza v3)"

assert_python_ok "Signed CAM/DENM are canonical COER EtsiTs103097Data" "
from src.crypto import generate_keypair, load_public_key_from_compressed, sha256
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam, sign_denm, sign_data_external_payload, verify_signed_data
V = EtsiVersion.V2_2_1
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=V)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=V)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=V)
from src.encoding import asn1_codec
for signed in (sign_cam(b'cam', at_priv, at.encoded, use_digest=True),
               sign_cam(b'cam', at_priv, at.encoded, use_digest=False),
               sign_denm(b'denm', at_priv, at.encoded, (525200000, 134050000, 340))):
    value = asn1_codec.decode('EtsiTs103097Data', signed)
    assert asn1_codec.encode('EtsiTs103097Data', value) == signed, 'not canonical'
    kind, sd = value['content']
    assert kind == 'signedData' and sd['hashId'] == 'sha256'
    assert set(sd['tbsData']['headerInfo']) <= {'psid', 'generationTime', 'generationLocation'}
print('CAM (digest and certificate signer) and DENM conform')
"

assert_python_ok "Message signature uses Hash(Hash(tbsData) || Hash(signer certificate))" "
from src.crypto import generate_keypair, load_public_key_from_compressed, sha256
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.signing import sign_cam, sign_denm, sign_data_external_payload, verify_signed_data
V = EtsiVersion.V2_2_1
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=V)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=V)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=V)
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from src.encoding import asn1_codec
signed = sign_cam(b'cam', at_priv, at.encoded, use_digest=True)
sd = asn1_codec.decode('EtsiTs103097Data', signed)['content'][1]
tbs = asn1_codec.encode('ToBeSignedData', sd['tbsData'])
data = hashlib.sha256(tbs).digest() + hashlib.sha256(at.encoded).digest()
sig = sd['signature'][1]
at_pub.verify(encode_dss_signature(int.from_bytes(sig['rSig'][1], 'big'), int.from_bytes(sig['sSig'], 'big')),
              data, ec.ECDSA(hashes.SHA256()))
print('signature matches IEEE 1609.2 clause 5.3.1.2.2')
"

print_summary
