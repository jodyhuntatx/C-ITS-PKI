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
result = verify_signed_data(signed, at_pub_key, PublicKeyAlgorithm.ECDSA_NIST_P256)
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
result = verify_signed_data(signed, pub_key)
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
signed = sign_data_external_payload(payload_hash, 36, at_priv, at.encoded)
assert signed is not None and len(signed) > 80
print(f'External payload signed: {len(signed)} bytes')
"

print_summary
