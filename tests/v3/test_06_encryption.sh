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
result = decrypt_and_verify(se, ea_e_priv, ea.encoded, at_pub_key, signer_cert_encoded=at.encoded)
assert result['valid'], f'Verify failed: {result.get(\"error\")}'
assert result['payload'] == payload
print('SignedAndEncrypted roundtrip OK')
"


section "ECIES (IEEE 1609.2 clause 5.3.5)"

assert_python_ok "ECIES matches the SCMS reference test vectors" "
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, derive_private_key
from src.crypto import ecies_encrypt, ecies_decrypt
H = bytes.fromhex
# conz27/crypto-test-vectors ecies.py / ecies.txt (fixed ephemeral key v)
eph = derive_private_key(0x1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42, SECP256R1())
for k, p1, r, C, T in [
    ('9169155B08B07674CBADF75FB46A7B0D', 'A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9',
     0x060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085, 'A6342013D623AD6C5F6882469673AE33', '80e1d85d30f1bae4ecf1a534a89a0786'),
    ('687E9757DEBFD87B0C267330C183C7B6', '05BED5F867B89F30FE5552DF414B65B9DD4073FC385D14921C641A145AA12051',
     0xDA5E1D853FCC5D0C162A245B9F29D38EB6059F0DB172FB7FDA6663B925E8C744, '1F6346EDAEAF57561FC9604FEBEFF44E', '373c0fa7c52a0798ec36eadfe387c3ef')]:
    recipient = derive_private_key(r, SECP256R1())
    out = ecies_encrypt(recipient.public_key(), H(k), H(p1), ephemeral_priv_key=eph)
    assert (out['c'], out['t']) == (H(C), H(T))
    assert ecies_decrypt(recipient, out['v'], out['c'], out['t'], H(p1)) == H(k)
print('both reference vectors match')
"

section "Encrypted message negative cases"

assert_python_ok "Wrong recipient, tampered ciphertext and mixed versions are rejected" "
from src.pki import CITSPKI
from src.types import EtsiVersion, PublicKeyAlgorithm
from src.crypto import load_public_key_from_compressed
from src.encryption import encrypt_data, decrypt_data, sign_and_encrypt, decrypt_and_verify
pki = CITSPKI(version=EtsiVersion.V2_2_1)
pki.initialise()
ea_cert = pki.ea.certificate.encoded
ea_pub, ea_priv = pki.ea.enc_pub_key, pki.ea.enc_priv_key
at = pki.issue_authorization_ticket()
enc = encrypt_data(b'secret', ea_cert, ea_pub)
aa_cert, aa_enc_priv = pki.aa.certificate.encoded, pki.aa.enc_priv_key
for bad, what in [((enc, aa_enc_priv, aa_cert), 'other recipient'),
                  ((enc[:-1] + bytes([enc[-1] ^ 1]), ea_priv, ea_cert), 'tampered ciphertext')]:
    try:
        decrypt_data(*bad)
    except Exception:
        pass
    else:
        raise AssertionError(what + ' accepted')
other = CITSPKI(version=EtsiVersion.V1_2_1); other.initialise()
try:
    sign_and_encrypt(b'x', 36, at['sign_priv_key'], at['at'], other.ea.certificate.encoded, other.ea.enc_pub_key)
except ValueError as e:
    print('mixed versions rejected:', e)
else:
    raise AssertionError('mixed-version sign_and_encrypt accepted')
print('negative cases rejected')
"

section "Conformance: EtsiTs103097Data-Encrypted (TS 103 097 v1.3.1 / IEEE 1609.2-2016)"

assert_python_ok "Encrypted and signed-and-encrypted data are canonical COER with certRecipInfo" "
from src.pki import CITSPKI
from src.types import EtsiVersion, PublicKeyAlgorithm
from src.crypto import load_public_key_from_compressed
from src.encryption import encrypt_data, decrypt_data, sign_and_encrypt, decrypt_and_verify
pki = CITSPKI(version=EtsiVersion.V2_2_1)
pki.initialise()
ea_cert = pki.ea.certificate.encoded
ea_pub, ea_priv = pki.ea.enc_pub_key, pki.ea.enc_priv_key
at = pki.issue_authorization_ticket()
import hashlib
from src.encoding import asn1_codec
from src.crypto import hash_certificate, ecies_decrypt
for message in (encrypt_data(b'payload', ea_cert, ea_pub),
                sign_and_encrypt(b'payload', 623, at['sign_priv_key'], at['at'], ea_cert, ea_pub)):
    value = asn1_codec.decode('EtsiTs103097Data', message)
    assert asn1_codec.encode('EtsiTs103097Data', value) == message, 'not canonical'
    kind, enc = value['content']
    assert kind == 'encryptedData' and len(enc['recipients']) == 1
    rkind, info = enc['recipients'][0]
    assert rkind == 'certRecipInfo'
    assert info['recipientId'] == hash_certificate(ea_cert, PublicKeyAlgorithm.ECDSA_NIST_P256)
    ckind, ct = enc['ciphertext']
    assert ckind == 'aes128ccm' and len(ct['nonce']) == 12
    # ECIES P1 = SHA-256(recipient certificate) for certRecipInfo; the empty P1 must fail
    key = info['encKey'][1]
    v = bytes([0x02 if key['v'][0] == 'compressed-y-0' else 0x03]) + key['v'][1]
    ecies_decrypt(ea_priv, v, key['c'], key['t'], hashlib.sha256(ea_cert).digest())
    try:
        ecies_decrypt(ea_priv, v, key['c'], key['t'], b'')
        raise AssertionError('empty P1 accepted for certRecipInfo')
    except ValueError:
        pass
r = decrypt_and_verify(sign_and_encrypt(b'payload', 623, at['sign_priv_key'], at['at'], ea_cert, ea_pub),
                       ea_priv, ea_cert, None, signer_cert_encoded=at['at'])
assert r['valid'] and r['payload'] == b'payload' and r['format'] == 'v3'
print('v3 encrypted structures conform, P1 = SHA-256(recipient certificate)')
"

assert_python_ok "Legacy non-COER encrypted data is rejected" "
from src.pki import CITSPKI
from src.types import EtsiVersion, PublicKeyAlgorithm
from src.crypto import load_public_key_from_compressed
from src.encryption import encrypt_data, decrypt_data, sign_and_encrypt, decrypt_and_verify
pki = CITSPKI(version=EtsiVersion.V2_2_1)
pki.initialise()
ea_cert = pki.ea.certificate.encoded
ea_pub, ea_priv = pki.ea.enc_pub_key, pki.ea.enc_priv_key
at = pki.issue_authorization_ticket()
legacy = bytes([3, 3]) + bytes(40)   # old encoder: raw CHOICE index 3 without tag or preamble
try:
    decrypt_data(legacy, ea_priv, ea_cert)
except ValueError as e:
    print('rejected:', str(e)[:70])
else:
    raise AssertionError('legacy encoding accepted')
"

print_summary
