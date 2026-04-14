#!/usr/bin/env bash
# Test 02 — Root CA Certificate (Profile 9.1 — ETSI TS 103 097 V2.2.1)
# Covers: FR-CI-01, FR-CI-07, FR-CI-08, FR-CI-09, FR-CI-10, AC-01, AC-11

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 02 — Root CA Certificate (Profile 9.1)${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "FR-CI-01: Root CA self-signed certificate generation"

assert_python_ok "Root CA certificate issuance (P-256)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V2_2_1)
assert cert is not None
assert len(cert.encoded) > 50
print(f'Root CA cert: {len(cert.encoded)} bytes')
"

section "FR-CI-07: COER encoding"

assert_python_ok "Root CA COER encoding and decoding roundtrip" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.encoding import decode_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V2_2_1)
decoded, _ = decode_certificate(cert.encoded)
assert decoded.version == 3, 'version must be 3'
assert decoded.tbs.id.name == 'Test-Root-CA', f'name mismatch: {decoded.tbs.id.name}'
print('COER roundtrip OK')
"

section "FR-CI-10: cracaId = 000000H, crlSeries = 0"

assert_python_ok "Root CA cracaId and crlSeries constraints (AC-11)" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V2_2_1)
assert cert.tbs.craca_id == b'\x00\x00\x00', f'cracaId={cert.tbs.craca_id.hex()}'
assert cert.tbs.crl_series == 0, f'crlSeries={cert.tbs.crl_series}'
print('cracaId=000000 crlSeries=0 OK')
"

section "FR-CI-09: Permissions present"

assert_python_ok "Root CA has appPermissions and certIssuePermissions" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V2_2_1)
assert cert.tbs.app_permissions, 'appPermissions must be present'
assert cert.tbs.cert_issue_permissions, 'certIssuePermissions must be present'
psids = [p.psid for p in cert.tbs.app_permissions]
assert ItsAid.CRL in psids, f'CRL ITS-AID missing: {psids}'
assert ItsAid.CTL in psids, f'CTL ITS-AID missing: {psids}'
print(f'Permissions OK: PSIDs={psids}')
"

section "Profile 9.1: Self-signed (issuer=self)"

assert_python_ok "Root CA issuer is 'self'" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, IssuerChoice, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V2_2_1)
assert cert.issuer.choice == IssuerChoice.SELF, f'Expected SELF, got {cert.issuer.choice}'
print('issuer=self OK')
"

section "AC-01: Root CA passes COER decode and profile check"

assert_python_ok "AC-01: Full profile 9.1 compliance check" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, IssuerChoice, CertificateType, CertIdChoice, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.encoding import decode_certificate
from src.verification import verify_certificate_signature, verify_craca_and_crl_series, verify_permissions_constraints
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('Test-Root-CA', priv, pub, version=EtsiVersion.V2_2_1)
# Decode
decoded, _ = decode_certificate(cert.encoded)
decoded.encoded = cert.encoded
# Profile checks
assert decoded.cert_type == CertificateType.EXPLICIT
assert decoded.issuer.choice == IssuerChoice.SELF
assert decoded.tbs.id.choice == CertIdChoice.NAME
craca_ok, msg = verify_craca_and_crl_series(decoded)
assert craca_ok, msg
perm_ok, msg = verify_permissions_constraints(decoded)
assert perm_ok, msg
sig_ok = verify_certificate_signature(decoded, None)
assert sig_ok, 'Self-signature invalid'
print('AC-01 PASSED')
"

section "Root CA P-384 variant"

assert_python_ok "Root CA certificate with P-384" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P384)
cert = issue_root_ca_certificate('Test-Root-CA-384', priv, pub, algorithm=PublicKeyAlgorithm.ECDSA_NIST_P384, version=EtsiVersion.V2_2_1)
assert len(cert.encoded) > 50
print(f'P-384 Root CA: {len(cert.encoded)} bytes')
"

print_summary
