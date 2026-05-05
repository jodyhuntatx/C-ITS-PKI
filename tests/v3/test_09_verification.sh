#!/usr/bin/env bash
# Test 09 — Certificate Verification (FR-VF-01 through FR-VF-06 — ETSI TS 103 097 V2.2.1)
# Covers: FR-VF-01..06, AC-02..05

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 09 — Certificate Verification${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "FR-VF-01: ECDSA signature verification"

assert_python_ok "ECDSA sign and verify (P-256)" "
from src.crypto import generate_keypair, ecdsa_sign, ecdsa_verify
from src.types import PublicKeyAlgorithm
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
data = b'Test data for ECDSA signing'
r, s = ecdsa_sign(priv, data, PublicKeyAlgorithm.ECDSA_NIST_P256)
valid = ecdsa_verify(pub, data, r, s, PublicKeyAlgorithm.ECDSA_NIST_P256)
assert valid, 'ECDSA P-256 verify failed'
print('ECDSA P-256 verify OK')
"

assert_python_ok "ECDSA sign and verify (P-384)" "
from src.crypto import generate_keypair, ecdsa_sign, ecdsa_verify
from src.types import PublicKeyAlgorithm
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P384)
data = b'Test data for ECDSA P-384 signing'
r, s = ecdsa_sign(priv, data, PublicKeyAlgorithm.ECDSA_NIST_P384)
valid = ecdsa_verify(pub, data, r, s, PublicKeyAlgorithm.ECDSA_NIST_P384)
assert valid, 'ECDSA P-384 verify failed'
print('ECDSA P-384 verify OK')
"

assert_python_ok "ECDSA signature fails for wrong key" "
from src.crypto import generate_keypair, ecdsa_sign, ecdsa_verify
from src.types import PublicKeyAlgorithm
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
priv2, pub2 = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
data = b'Test data'
r, s = ecdsa_sign(priv, data, PublicKeyAlgorithm.ECDSA_NIST_P256)
# Verify with wrong key
valid = ecdsa_verify(pub2, data, r, s, PublicKeyAlgorithm.ECDSA_NIST_P256)
assert not valid, 'Should have failed with wrong key'
print('Wrong-key rejection OK')
"

assert_python_ok "ECDSA signature fails for tampered data" "
from src.crypto import generate_keypair, ecdsa_sign, ecdsa_verify
from src.types import PublicKeyAlgorithm
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
data = b'Original data'
r, s = ecdsa_sign(priv, data, PublicKeyAlgorithm.ECDSA_NIST_P256)
valid = ecdsa_verify(pub, b'Tampered data', r, s, PublicKeyAlgorithm.ECDSA_NIST_P256)
assert not valid, 'Should have failed with tampered data'
print('Tamper detection OK')
"

section "FR-VF-02: Certificate validity period check"

assert_python_ok "Certificate within validity period" "
import time
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.verification import verify_certificate_validity_period
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('TestCA', priv, pub, validity_years=10, version=EtsiVersion.V2_2_1)
assert verify_certificate_validity_period(cert), 'Certificate should be valid now'
print('Validity period check OK')
"

assert_python_ok "Expired certificate detected" "
import time
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.verification import verify_certificate_validity_period
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
# Issue cert that started in the past and has 0-second validity
cert = issue_root_ca_certificate('ExpiredCA', priv, pub, validity_years=1,
                                  start_time=time.time() - 400 * 86400,
                                  version=EtsiVersion.V2_2_1)
# Check at a time well after expiry
future_time = time.time() + 5 * 365 * 86400  # 5 years from now
valid = verify_certificate_validity_period(cert, future_time)
assert not valid, 'Should detect expired certificate'
print('Expired certificate detected OK')
"

section "FR-VF-04: Hash ID-based revocation"

assert_python_ok "Certificate revocation by hash ID" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.verification import check_revocation_by_hash
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('TestCA', priv, pub, version=EtsiVersion.V2_2_1)
from src.crypto import hash_certificate
cert_hash = hash_certificate(cert.encoded, PublicKeyAlgorithm.ECDSA_NIST_P256)
# Not revoked initially
assert not check_revocation_by_hash(cert.encoded, [], PublicKeyAlgorithm.ECDSA_NIST_P256)
# Revoked
assert check_revocation_by_hash(cert.encoded, [cert_hash], PublicKeyAlgorithm.ECDSA_NIST_P256)
print('Hash ID revocation OK')
"

section "FR-VF-06: Region constraint (EU-27 = 65535)"

assert_python_ok "EU-27 region ID (65535) accepted" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
from src.verification import verify_region_constraint
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('EU-CA', priv, pub, region_ids=[65535], version=EtsiVersion.V2_2_1)
ok, msg = verify_region_constraint(cert)
assert ok, f'EU-27 should be accepted: {msg}'
assert 65535 in cert.tbs.region.ids
print(f'EU-27 accepted: {msg}')
"

section "Issuer digest verification (FR-VF-04)"

assert_python_ok "EA issuer digest matches Root CA" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
from src.verification import verify_issuer_digest
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
ok = verify_issuer_digest(ea, rca, PublicKeyAlgorithm.ECDSA_NIST_P256)
assert ok, 'Issuer digest verification failed'
print('Issuer digest OK')
"

section "HashedId8 computation"

assert_python_ok "HashedId8 is last 8 bytes of SHA-256(cert)" "
import hashlib
from src.crypto import generate_keypair, hash_certificate
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
cert = issue_root_ca_certificate('TestCA', priv, pub, version=EtsiVersion.V2_2_1)
expected = hashlib.sha256(cert.encoded).digest()[-8:]
actual = hash_certificate(cert.encoded, PublicKeyAlgorithm.ECDSA_NIST_P256)
assert actual == expected, f'HashedId8 mismatch: {actual.hex()} vs {expected.hex()}'
print(f'HashedId8 = {actual.hex()}')
"

print_summary
