#!/usr/bin/env bash
# Test 02 — Root CA Certificate (Profile 7.1 — ETSI TS 103 097 V1.2.1)
# Covers: FR-CI-01, FR-CI-07, FR-CI-08, FR-CI-09, AC-01
# Note: V1.2.1 uses the vanetza binary wire format, not COER.
#       cracaId/crlSeries/certIssuePermissions are not encoded in the v1 wire format.

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 02 — Root CA Certificate (Profile 7.1)${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "FR-CI-01: Root CA self-signed certificate generation"

assert_python_ok "Root CA certificate issuance (P-256)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V1_2_1)
assert cert is not None
assert len(cert.encoded) > 50
print(f'Root CA cert: {len(cert.encoded)} bytes')
"

section "FR-CI-07: Vanetza binary encoding"

assert_python_ok "Root CA vanetza binary encoding and decoding roundtrip" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.v1_encoding import decode_certificate_v1
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V1_2_1)
decoded, _ = decode_certificate_v1(cert.encoded)
assert decoded.version == 2, f'V1 wire format version must be 2, got {decoded.version}'
assert decoded.tbs.id.name == 'Test-Root-CA', f'name mismatch: {decoded.tbs.id.name}'
print('Vanetza binary roundtrip OK')
"

section "V1 wire format: version byte and signer info encoding"

assert_python_ok "Root CA vanetza wire format: version=0x02, signer=self" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.v1_encoding import V1SignerInfoType
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V1_2_1)
# V1.2.1 vanetza wire format: first byte is version = 0x02
assert cert.encoded[0] == 0x02, f'V1 version byte must be 0x02, got 0x{cert.encoded[0]:02x}'
# Second byte is SignerInfoType: 0x00 = SELF for a Root CA
assert cert.encoded[1] == V1SignerInfoType.SELF, \
    f'Root CA signer must be SELF (0x00), got 0x{cert.encoded[1]:02x}'
# cracaId and crlSeries are not encoded in the V1.2.1 wire format
print('V1 wire format version=0x02 and signer=SELF OK')
"

section "FR-CI-09: appPermissions present (certIssuePermissions absent in V1.2.1 wire format)"

assert_python_ok "Root CA has appPermissions; certIssuePermissions absent in decoded cert" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.v1_encoding import decode_certificate_v1
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V1_2_1)
# appPermissions are encoded in the V1 ITS_AID_List attribute
assert cert.tbs.app_permissions, 'appPermissions must be present on issued cert'
psids = [p.psid for p in cert.tbs.app_permissions]
assert ItsAid.CRL in psids, f'CRL ITS-AID missing: {psids}'
assert ItsAid.CTL in psids, f'CTL ITS-AID missing: {psids}'
# certIssuePermissions is NOT encoded in the V1.2.1 wire format
decoded, _ = decode_certificate_v1(cert.encoded)
assert decoded.tbs.cert_issue_permissions is None, \
    'V1.2.1 wire format does not carry certIssuePermissions'
print(f'appPermissions OK: PSIDs={psids}; certIssuePermissions absent in wire OK')
"

section "Profile 7.1: Self-signed (issuer=self)"

assert_python_ok "Root CA issuer is 'self'" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, IssuerChoice, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V1_2_1)
assert cert.issuer.choice == IssuerChoice.SELF, f'Expected SELF, got {cert.issuer.choice}'
print('issuer=self OK')
"

section "AC-01: Root CA passes vanetza decode and self-signature verification"

assert_python_ok "AC-01: Full profile 7.1 compliance check" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, IssuerChoice, CertificateType, CertIdChoice, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.v1_encoding import decode_certificate_v1
from src.verification import verify_certificate_signature
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V1_2_1)
# Decode using the vanetza binary decoder
decoded, consumed = decode_certificate_v1(cert.encoded)
assert consumed == len(cert.encoded), f'Not all bytes consumed: {consumed} vs {len(cert.encoded)}'
decoded.encoded = cert.encoded
decoded.tbs_encoded = cert.tbs_encoded
# Profile 7.1 checks: version=2, self-signed, name-based id
assert decoded.version == 2
assert decoded.issuer.choice == IssuerChoice.SELF
assert decoded.tbs.id.choice == CertIdChoice.NAME
# certIssuePermissions is not encoded in V1.2.1 wire format
assert decoded.tbs.cert_issue_permissions is None
# Self-signature must verify
sig_ok = verify_certificate_signature(cert, None)
assert sig_ok, 'Self-signature invalid'
print('AC-01 PASSED')
"

section "V1.2.1 algorithm constraint: only P-256 supported"

assert_python_ok "P-384 rejected (V1.2.1 vanetza format supports P-256 only)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P384)
try:
    cert = issue_root_ca_certificate('Test-Root-CA-384', priv, pub,
                                     algorithm=PublicKeyAlgorithm.ECDSA_NIST_P384,
                                     version=EtsiVersion.V1_2_1)
    assert False, 'Should have raised ValueError for P-384 in V1.2.1'
except ValueError as e:
    print(f'P-384 correctly rejected: {e}')
"

print_summary
