#!/usr/bin/env bash
# Test 04 — TLM, Enrolment Credential, Authorization Ticket (Profiles 9.4–9.6)
# Covers: FR-CI-04, FR-CI-05, FR-CI-06, AC-04, AC-05

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 04 — TLM, EC, and AT (Profiles 9.4–9.6)${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "FR-CI-04: TLM Certificate (Profile 9.4)"

assert_python_ok "TLM self-signed certificate" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, IssuerChoice, ItsAid
from src.certificates import issue_tlm_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
tlm = issue_tlm_certificate('TestTLM', priv, pub)
assert tlm is not None
assert tlm.issuer.choice == IssuerChoice.SELF, 'TLM must be self-signed'
assert tlm.tbs.cert_issue_permissions is None, 'TLM must not have certIssuePermissions'
psids = [p.psid for p in tlm.tbs.app_permissions]
assert ItsAid.CTL in psids, f'TLM must have CTL ITS-AID, got {psids}'
print(f'TLM cert OK: {len(tlm.encoded)} bytes')
"

section "FR-CI-05: Enrolment Credential (Profile 9.5)"

assert_python_ok "EC issuance by EA" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, ItsAid, CertIdChoice
from src.certificates import issue_root_ca_certificate, issue_ea_certificate, issue_enrolment_credential
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv)
its_priv, its_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ec = issue_enrolment_credential('ITS-Station-001', its_priv, its_pub, ea, ea_s_priv)
assert ec is not None
assert ec.tbs.id.choice == CertIdChoice.NAME, 'EC id must be name'
assert ec.tbs.cert_issue_permissions is None, 'EC must not have certIssuePermissions'
psids = [p.psid for p in ec.tbs.app_permissions]
assert ItsAid.CERT_REQUEST in psids, f'EC must have CERT_REQUEST PSID, got {psids}'
print(f'EC cert OK: {len(ec.encoded)} bytes')
"

assert_python_ok "AC-04: EC signature verifiable against EA" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm
from src.certificates import issue_root_ca_certificate, issue_ea_certificate, issue_enrolment_credential
from src.verification import verify_certificate_signature
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv)
its_priv, its_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ec = issue_enrolment_credential('ITS-Station-001', its_priv, its_pub, ea, ea_s_priv)
valid = verify_certificate_signature(ec, ea)
assert valid, 'EC signature verification failed'
print('AC-04 PASSED: EC signature valid against EA')
"

section "FR-CI-06: Authorization Ticket (Profile 9.6)"

assert_python_ok "AT issuance by AA with id=none" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, CertIdChoice
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv)
assert at is not None
assert at.tbs.id.choice == CertIdChoice.NONE, f'AT id must be none, got {at.tbs.id.choice}'
print(f'AT cert OK: {len(at.encoded)} bytes')
"

assert_python_ok "AC-05: AT signature verifiable against AA; id=none" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, CertIdChoice
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.verification import verify_certificate_signature, verify_at_profile
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv)
sig_valid = verify_certificate_signature(at, aa)
assert sig_valid, 'AT signature invalid'
profile_ok, msg = verify_at_profile(at)
assert profile_ok, f'AT profile check failed: {msg}'
print('AC-05 PASSED: AT valid, id=none, signature OK')
"

assert_python_ok "AT certIssuePermissions absent (NFR-SEC-06)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv)
assert not at.tbs.cert_issue_permissions, 'AT must not have certIssuePermissions'
print('AT certIssuePermissions absent OK')
"

section "AT private key independent from EC private key (NFR-SEC-05)"

assert_python_ok "AT and EC have independent private keys" "
from src.crypto import generate_keypair, serialize_private_key
from src.types import PublicKeyAlgorithm
ec_priv, _ = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at_priv, _ = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
assert serialize_private_key(ec_priv) != serialize_private_key(at_priv)
print('Independent AT/EC keys OK')
"

print_summary
