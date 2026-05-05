#!/usr/bin/env bash
# Test 07 — Full PKI Hierarchy Initialisation via CLI (ETSI TS 103 097 V1.2.1)
# Covers: Appendix A.1 (PKI Initialisation Sequence), AC-01 through AC-05
# Note: V1.2.1 uses the vanetza binary wire format; use decode_certificate_v1 to
#       round-trip encoded bytes back to Certificate objects.

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 07 — Full PKI Hierarchy Initialisation${NC}"

TMPDIR=$(make_tmpdir)
PKI_DIR="$TMPDIR/pki"
trap "cleanup_tmpdir $TMPDIR" EXIT

section "PKI Initialisation via CITSPKI class (Appendix A.1)"

assert_python_ok "Full PKI initialise() produces all 4 certificates" "
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm, EtsiVersion
pki = CITSPKI(algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256, region_ids=[65535], version=EtsiVersion.V1_2_1)
certs = pki.initialise(start_time=1700000000.0)
assert 'root_ca' in certs and len(certs['root_ca']) > 50
assert 'tlm'     in certs and len(certs['tlm'])     > 50
assert 'ea'      in certs and len(certs['ea'])       > 50
assert 'aa'      in certs and len(certs['aa'])       > 50
print(f'root_ca={len(certs[\"root_ca\"])}B tlm={len(certs[\"tlm\"])}B ea={len(certs[\"ea\"])}B aa={len(certs[\"aa\"])}B')
"

section "PKI save and file output"

assert_python_ok "PKI save() creates expected files" "
import os, tempfile
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm, EtsiVersion
pki = CITSPKI(algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256, version=EtsiVersion.V1_2_1)
pki.initialise()
with tempfile.TemporaryDirectory() as d:
    pki.save(d)
    for fname in ['root_ca.cert','tlm.cert','ea.cert','aa.cert',
                  'root_ca_sign.key','ea_sign.key','ea_enc.key',
                  'aa_sign.key','aa_enc.key','pki_meta.json']:
        p = os.path.join(d, fname)
        assert os.path.exists(p), f'Missing: {fname}'
    print('All expected files present')
"

section "ITS-Station Enrolment (Appendix A.2)"

assert_python_ok "enrol_its_station() issues valid EC" "
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm, CertIdChoice, EtsiVersion
from src.verification import verify_certificate_signature
from src.v1_encoding import decode_certificate_v1
pki = CITSPKI(algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256, version=EtsiVersion.V1_2_1)
pki.initialise()
result = pki.enrol_its_station('ITS-Station-007')
assert 'ec' in result and len(result['ec']) > 50
# V1.2.1 encoded bytes must be decoded with the vanetza binary decoder
ec, _ = decode_certificate_v1(result['ec'])
ec.encoded = result['ec']
ec.tbs_encoded = ec.tbs_encoded  # already set by decoder
assert ec.tbs.id.choice == CertIdChoice.NAME
assert ec.tbs.id.name == 'ITS-Station-007'
sig_ok = verify_certificate_signature(ec, pki.ea.certificate)
assert sig_ok, 'EC signature invalid'
print('EC issued and verified OK')
"

section "Authorization Ticket Provisioning (Appendix A.3)"

assert_python_ok "issue_authorization_ticket() issues valid AT" "
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm, CertIdChoice, EtsiVersion
from src.verification import verify_certificate_signature, verify_at_profile
from src.v1_encoding import decode_certificate_v1
pki = CITSPKI(algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256, version=EtsiVersion.V1_2_1)
pki.initialise()
result = pki.issue_authorization_ticket()
assert 'at' in result and len(result['at']) > 50
# V1.2.1 encoded bytes must be decoded with the vanetza binary decoder
at, _ = decode_certificate_v1(result['at'])
at.encoded = result['at']
at.tbs_encoded = at.tbs_encoded  # already set by decoder
assert at.tbs.id.choice == CertIdChoice.NONE, 'AT id must be none'
sig_ok = verify_certificate_signature(at, pki.aa.certificate)
assert sig_ok, 'AT signature invalid'
# certIssuePermissions is not in the V1.2.1 wire format; verify_at_profile checks it is absent
profile_ok, msg = verify_at_profile(at)
assert profile_ok, f'AT profile: {msg}'
print('AT issued and verified OK')
"

section "Region constraint: EU-27 (AC-10, FR-VF-06)"

assert_python_ok "AC-10: EU-27 region ID (65535) accepted" "
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm, RegionChoice, EtsiVersion
from src.verification import verify_region_constraint
pki = CITSPKI(algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256, region_ids=[65535], version=EtsiVersion.V1_2_1)
pki.initialise()
rca = pki.root_ca.certificate
assert rca.tbs.region is not None
ok, msg = verify_region_constraint(rca)
assert ok, f'Region constraint failed: {msg}'
assert 65535 in rca.tbs.region.ids, 'EU-27 (65535) not in region IDs'
print(f'AC-10 PASSED: region IDs = {rca.tbs.region.ids}')
"

section "PKI certificate chain verification"

assert_python_ok "Full chain: EA cert verifies against Root CA" "
from src.pki import CITSPKI
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.verification import verify_certificate_chain
pki = CITSPKI(algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256, version=EtsiVersion.V1_2_1)
pki.initialise()
result = verify_certificate_chain(
    leaf_cert=pki.ea.certificate,
    intermediate_certs=[],
    root_cert=pki.root_ca.certificate,
    algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256,
)
assert result['valid'], f'Chain invalid: {result[\"errors\"]}'
print('Certificate chain validation OK')
"

print_summary
