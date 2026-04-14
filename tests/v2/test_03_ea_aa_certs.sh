#!/usr/bin/env bash
# Test 03 — EA and AA Subordinate CA Certificates (Profiles 9.2, 9.3 — ETSI TS 103 097 V2.2.1)
# Covers: FR-CI-02, FR-CI-03, AC-02, AC-03

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 03 — EA and AA Certificates (Profiles 9.2, 9.3)${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "Common setup: Root CA"

section "FR-CI-02: EA certificate (Profile 9.2)"

assert_python_ok "EA certificate issuance signed by Root CA" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
assert ea is not None and len(ea.encoded) > 50
print(f'EA cert: {len(ea.encoded)} bytes')
"

assert_python_ok "EA has encryptionKey (profile 9.2 requirement)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
assert ea.tbs.encryption_key is not None, 'EA must have encryptionKey'
print('EA encryptionKey present OK')
"

assert_python_ok "AC-02: EA certificate signature verifiable against Root CA" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
from src.verification import verify_certificate_signature
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
valid = verify_certificate_signature(ea, rca)
assert valid, 'EA signature verification failed'
print('AC-02 PASSED: EA signature valid')
"

section "FR-CI-03: AA certificate (Profile 9.3)"

assert_python_ok "AA certificate issuance signed by Root CA" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
assert aa is not None and len(aa.encoded) > 50
print(f'AA cert: {len(aa.encoded)} bytes')
"

assert_python_ok "AA has encryptionKey (profile 9.3 requirement)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
assert aa.tbs.encryption_key is not None, 'AA must have encryptionKey'
print('AA encryptionKey present OK')
"

assert_python_ok "AC-03: AA certificate signature verifiable against Root CA" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate
from src.verification import verify_certificate_signature
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
valid = verify_certificate_signature(aa, rca)
assert valid, 'AA signature verification failed'
print('AC-03 PASSED: AA signature valid')
"

section "EA/AA: certIssuePermissions present"

assert_python_ok "EA certIssuePermissions present" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
assert ea.tbs.cert_issue_permissions, 'EA must have certIssuePermissions'
print('EA certIssuePermissions OK')
"

section "EA/AA issuer digest matches Root CA"

assert_python_ok "EA issuer digest matches Root CA SHA-256" "
from src.crypto import generate_keypair, hash_certificate
from src.types import PublicKeyAlgorithm, IssuerChoice, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
assert ea.issuer.choice == IssuerChoice.SHA256_AND_DIGEST
expected = hash_certificate(rca.encoded, PublicKeyAlgorithm.ECDSA_NIST_P256)
assert ea.issuer.digest == expected, 'Issuer digest mismatch'
print('Issuer digest matches Root CA OK')
"

print_summary
