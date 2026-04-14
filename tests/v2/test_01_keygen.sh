#!/usr/bin/env bash
# Test 01 — Key Pair Generation
# Covers: FR-KG-01 through FR-KG-05

source "$(dirname "$0")/helpers.sh"
echo -e "${BOLD}Test 01 — Key Pair Generation${NC}"
section "FR-KG-01/02: P-256 and P-384 key generation"

TMPDIR=$(make_tmpdir)
trap "cleanup_tmpdir $TMPDIR" EXIT

# FR-KG-01: Generate P-256 keypair
assert_python_ok "P-256 keypair generation" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
assert priv is not None
assert pub is not None
print('P-256 OK')
"

# FR-KG-02: Generate P-384 keypair
assert_python_ok "P-384 keypair generation" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm
priv, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P384)
assert priv is not None
assert pub is not None
print('P-384 OK')
"

# FR-KG-03: Private key uses CSPRNG (check key is random — two keys differ)
assert_python_ok "P-256 key pairs are distinct (CSPRNG)" "
from src.crypto import generate_keypair, serialize_private_key
from src.types import PublicKeyAlgorithm
p1, _ = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
p2, _ = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
assert serialize_private_key(p1) != serialize_private_key(p2), 'Keys must be distinct'
print('Randomness OK')
"

# FR-KG-04: Public key in compressed form (33 bytes for P-256)
assert_python_ok "P-256 public key compressed format (33 bytes)" "
from src.crypto import generate_keypair, public_key_to_point
from src.types import PublicKeyAlgorithm
_, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
pt = public_key_to_point(pub)
assert len(pt.compressed) == 33, f'Expected 33 bytes, got {len(pt.compressed)}'
assert pt.compressed[0] in (0x02, 0x03), f'Expected 0x02 or 0x03 prefix'
print('Compressed OK')
"

# FR-KG-04: P-384 compressed point is 49 bytes
assert_python_ok "P-384 public key compressed format (49 bytes)" "
from src.crypto import generate_keypair, public_key_to_point
from src.types import PublicKeyAlgorithm
_, pub = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P384)
pt = public_key_to_point(pub)
assert len(pt.compressed) == 49, f'Expected 49 bytes, got {len(pt.compressed)}'
print('P-384 compressed OK')
"

# FR-KG-05: Separate signing and encryption keypairs are independent
assert_python_ok "Separate signing and encryption keypairs" "
from src.crypto import generate_keypair, serialize_private_key
from src.types import PublicKeyAlgorithm
sign_priv, _ = generate_keypair(PublicKeyAlgorithm.ECDSA_NIST_P256)
enc_priv, _  = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
assert serialize_private_key(sign_priv) != serialize_private_key(enc_priv)
print('Independent keys OK')
"

section "ECIES key generation"

# ECIES P-256 key generation
assert_python_ok "ECIES P-256 keypair generation" "
from src.crypto import generate_keypair
from src.types import PublicKeyAlgorithm
priv, pub = generate_keypair(PublicKeyAlgorithm.ECIES_NIST_P256)
assert priv is not None and pub is not None
print('ECIES P-256 OK')
"

print_summary
