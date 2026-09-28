#!/usr/bin/env bash
# Test 04 — TLM, Enrolment Credential, Authorization Ticket (Profiles 7.4–7.6 — ETSI TS 103 097 V1.2.1)
# Covers: FR-CI-04, FR-CI-05, FR-CI-06, AC-04, AC-05

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 04 — TLM, EC, and AT (Profiles 7.4–7.6)${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "FR-CI-04: TLM Certificate (Profile 7.4)"

assert_python_ok "TLM self-signed certificate" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, IssuerChoice, ItsAid, EtsiVersion
from src.certificates import issue_tlm_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
tlm = issue_tlm_certificate('TestTLM', priv, pub, version=EtsiVersion.V1_2_1)
assert tlm is not None
assert tlm.issuer.choice == IssuerChoice.SELF, 'TLM must be self-signed'
assert tlm.tbs.cert_issue_permissions is None, 'TLM must not have certIssuePermissions'
psids = [p.psid for p in tlm.tbs.app_permissions]
assert ItsAid.CTL in psids, f'TLM must have CTL ITS-AID, got {psids}'
print(f'TLM cert OK: {len(tlm.encoded)} bytes')
"

section "FR-CI-05: Enrolment Credential (Profile 7.5)"

assert_python_ok "EC issuance by EA" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, ItsAid, CertIdChoice, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate, issue_enrolment_credential
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
its_priv, its_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ec = issue_enrolment_credential('ITS-Station-001', its_priv, its_pub, ea, ea_s_priv, version=EtsiVersion.V1_2_1)
assert ec is not None
assert ec.tbs.id.choice == CertIdChoice.NAME, 'EC id must be name'
assert ec.tbs.cert_issue_permissions is None, 'EC must not have certIssuePermissions'
psids = [p.psid for p in ec.tbs.app_permissions]
assert ItsAid.CERT_REQUEST in psids, f'EC must have CERT_REQUEST PSID, got {psids}'
print(f'EC cert OK: {len(ec.encoded)} bytes')
"

assert_python_ok "AC-04: EC signature verifiable against EA" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate, issue_enrolment_credential
from src.verification import verify_certificate_signature
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
its_priv, its_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ec = issue_enrolment_credential('ITS-Station-001', its_priv, its_pub, ea, ea_s_priv, version=EtsiVersion.V1_2_1)
valid = verify_certificate_signature(ec, ea)
assert valid, 'EC signature verification failed'
print('AC-04 PASSED: EC signature valid against EA')
"

section "FR-CI-06: Authorization Ticket (Profile 7.6)"

assert_python_ok "AT issuance by AA with id=none" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, CertIdChoice, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V1_2_1)
assert at is not None
assert at.tbs.id.choice == CertIdChoice.NONE, f'AT id must be none, got {at.tbs.id.choice}'
print(f'AT cert OK: {len(at.encoded)} bytes')
"

assert_python_ok "AC-05: AT signature verifiable against AA; id=none" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, CertIdChoice, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
from src.verification import verify_certificate_signature, verify_at_profile
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V1_2_1)
sig_valid = verify_certificate_signature(at, aa)
assert sig_valid, 'AT signature invalid'
profile_ok, msg = verify_at_profile(at)
assert profile_ok, f'AT profile check failed: {msg}'
print('AC-05 PASSED: AT valid, id=none, signature OK')
"

assert_python_ok "AT certIssuePermissions absent (NFR-SEC-06)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_aa_certificate, issue_authorization_ticket
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V1_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V1_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V1_2_1)
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


section "TS 103 097 V1.2.1 clause 7.4 (KD-1, KD-2)"

assert_python_ok "KD-1: every v2 certificate carries assurance_level (default 0)" "
from src.pki import CITSPKI
from src.types import EtsiVersion
from src.v1_encoding import decode_certificate_v1
pki = CITSPKI(version=EtsiVersion.V1_2_1); pki.initialise()
certs = {'root': pki.root_ca.certificate, 'tlm': pki.tlm.certificate, 'ea': pki.ea.certificate,
         'aa': pki.aa.certificate, 'ec': pki.enrol_its_station('S1')['certificate'],
         'at': pki.issue_authorization_ticket()['certificate']}
for name, cert in certs.items():
    d, _ = decode_certificate_v1(cert.encoded)
    a = d.tbs.assurance_level
    assert a is not None and (a.level, a.confidence) == (0, 0), name
print('assurance_level 0 present in root, tlm, ea, aa, ec, at')
"

assert_python_ok "KD-2: EC and AT use its_aid_ssp_list, CA certificates its_aid_list" "
from src.pki import CITSPKI
from src.types import EtsiVersion
pki = CITSPKI(version=EtsiVersion.V1_2_1); pki.initialise()
def aid_attr_type(encoded):
    # walk the subject attributes of a v2 certificate and return the ITS-AID attribute type
    from src.v1_encoding import decode_length
    off = 1
    off += 1 if encoded[off] == 0 else 9                  # signer_info
    off += 1; n, off = decode_length(encoded, off); off += n  # subject_info
    size, off = decode_length(encoded, off); end = off + size
    while off < end:
        t = encoded[off]
        if t in (0x20, 0x21):
            return t
        off += {0: 35, 1: 36, 2: 2}[t]
    return None
ec = pki.enrol_its_station('S1')['certificate']; at = pki.issue_authorization_ticket()['certificate']
assert aid_attr_type(ec.encoded) == 0x21, 'EC must use its_aid_ssp_list (clause 7.4.3)'
assert aid_attr_type(at.encoded) == 0x21, 'AT must use its_aid_ssp_list (clause 7.4.2)'
for ca in (pki.ea.certificate, pki.aa.certificate):
    assert aid_attr_type(ca.encoded) == 0x20, 'CA must use its_aid_list (clause 7.4.4)'
print('EC/AT: its_aid_ssp_list, EA/AA: its_aid_list')
"

print_summary
