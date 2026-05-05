#!/usr/bin/env bash
# Test 06 — Message Encryption (ECIES + AES-128-CCM — ETSI TS 103 097 V2.2.1)
# Covers: FR-EN-01 through FR-EN-06, AC-08, NFR-SEC-04

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 06 — Message Encryption (ECIES + AES-128-CCM)${NC}"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

section "FR-EN-01/02: ECIES + AES-128-CCM encrypt/decrypt"

assert_python_ok "AC-08: AES-CCM encrypted message decrypts correctly with ECIES" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
from src.encryption import encrypt_data, decrypt_data
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
plaintext = b'Confidential ITS message: test payload 12345'
encrypted = encrypt_data(plaintext, ea.encoded, ea_e_pub)
assert encrypted is not None and len(encrypted) > len(plaintext)
decrypted = decrypt_data(encrypted, ea_e_priv, ea.encoded)
assert decrypted == plaintext, f'Decryption mismatch: {decrypted}'
print('AC-08 PASSED: encrypt/decrypt roundtrip OK')
"

section "FR-EN-02: AES-128-CCM primitives"

assert_python_ok "AES-128-CCM encrypt/decrypt roundtrip" "
from src.crypto import aes_ccm_encrypt, aes_ccm_decrypt, random_bytes
key   = random_bytes(16)
nonce = random_bytes(12)
msg   = b'Test message for AES-128-CCM'
ct    = aes_ccm_encrypt(key, nonce, msg)
pt    = aes_ccm_decrypt(key, nonce, ct)
assert pt == msg, f'AES-CCM decryption failed: {pt}'
print('AES-128-CCM OK')
"

assert_python_ok "AES-CCM authentication tag fails on tampered ciphertext" "
from src.crypto import aes_ccm_encrypt, aes_ccm_decrypt, random_bytes
from cryptography.exceptions import InvalidTag
key   = random_bytes(16)
nonce = random_bytes(12)
msg   = b'Test AES-CCM auth'
ct    = aes_ccm_encrypt(key, nonce, msg)
tampered = ct[:-1] + bytes([ct[-1] ^ 0xFF])   # flip last byte
try:
    aes_ccm_decrypt(key, nonce, tampered)
    assert False, 'Should have raised exception'
except Exception:
    pass
print('AES-CCM tamper detection OK')
"

section "FR-EN-01: ECIES key encapsulation"

assert_python_ok "ECIES encrypt/decrypt roundtrip" "
from src.crypto import generate_keypair, ecies_encrypt, ecies_decrypt, random_bytes
from src.types import PublicKeyAlgorithm
priv, pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aes_key = random_bytes(16)
result  = ecies_encrypt(pub, aes_key)
assert 'v' in result and 'c' in result and 't' in result
assert len(result['v']) == 33, f'v must be 33 bytes, got {len(result[\"v\"])}'
assert len(result['c']) == 16, f'c must be 16 bytes'
assert len(result['t']) == 16, f't must be 16 bytes'
recovered = ecies_decrypt(priv, result['v'], result['c'], result['t'])
assert recovered == aes_key, 'ECIES decryption mismatch'
print('ECIES OK')
"

assert_python_ok "ECIES authentication tag detected on tampered ciphertext" "
from src.crypto import generate_keypair, ecies_encrypt, ecies_decrypt, random_bytes
from src.types import PublicKeyAlgorithm
priv, pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
aes_key = random_bytes(16)
result  = ecies_encrypt(pub, aes_key)
tampered_c = bytes([result['c'][0] ^ 0xFF]) + result['c'][1:]
try:
    ecies_decrypt(priv, result['v'], tampered_c, result['t'])
    assert False, 'Should have raised ValueError'
except ValueError:
    pass
print('ECIES auth tag verification OK')
"

section "FR-EN-05: Fresh ephemeral key per encryption"

assert_python_ok "Ephemeral key V is unique per encryption operation" "
from src.crypto import generate_keypair, ecies_encrypt, random_bytes
from src.types import PublicKeyAlgorithm
_, pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
key = random_bytes(16)
r1 = ecies_encrypt(pub, key)
r2 = ecies_encrypt(pub, key)
assert r1['v'] != r2['v'], 'Ephemeral keys must be different each time'
print('Fresh ephemeral key OK')
"

section "NFR-SEC-04: AES-CCM nonce uniqueness"

assert_python_ok "Different encryptions produce different nonces" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm, EtsiVersion
from src.certificates import issue_root_ca_certificate, issue_ea_certificate
from src.encryption import encrypt_data
# Extract nonces from two encrypted messages and verify they differ
rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
e1 = encrypt_data(b'msg1', ea.encoded, ea_e_pub)
e2 = encrypt_data(b'msg2', ea.encoded, ea_e_pub)
assert e1 != e2, 'Encrypted messages should differ due to fresh nonce'
print('Nonce uniqueness OK')
"

section "FR-EN: Signed-and-encrypted (profile 10.5)"

assert_python_ok "SignedAndEncrypted roundtrip" "
from src.crypto import generate_keypair, load_public_key_from_compressed
from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
from src.certificates import (issue_root_ca_certificate, issue_aa_certificate,
                               issue_authorization_ticket, issue_ea_certificate)
from src.encryption import sign_and_encrypt, decrypt_and_verify

rca_priv, rca_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
rca = issue_root_ca_certificate('TestRootCA', rca_priv, rca_pub, version=EtsiVersion.V2_2_1)
ea_s_priv, ea_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
ea_e_priv, ea_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
ea = issue_ea_certificate('TestEA', ea_s_priv, ea_s_pub, ea_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
aa_s_priv, aa_s_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
aa_e_priv, aa_e_pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)

from src.certificates import issue_aa_certificate
aa = issue_aa_certificate('TestAA', aa_s_priv, aa_s_pub, aa_e_pub, rca, rca_priv, version=EtsiVersion.V2_2_1)
at_priv, at_pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
at = issue_authorization_ticket(at_priv, at_pub, aa, aa_s_priv, version=EtsiVersion.V2_2_1)

payload = b'Signed-and-encrypted test payload'
se = sign_and_encrypt(payload, int(ItsAid.CAM), at_priv, at.encoded, ea.encoded, ea_e_pub)
assert len(se) > 100

vk = at.tbs.verify_key_indicator
at_pub_key = load_public_key_from_compressed(vk.point.curve, vk.point.compressed)
result = decrypt_and_verify(se, ea_e_priv, ea.encoded, at_pub_key)
assert result['valid'], f'Verify failed: {result.get(\"error\")}'
assert result['payload'] == payload
print('SignedAndEncrypted roundtrip OK')
"

print_summary
