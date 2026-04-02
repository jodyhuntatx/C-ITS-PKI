"""Convert a PEM PKCS#8 EC private key to the 32-byte raw format Vanetza
expects."""

import sys
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def convert(pem_path: str, out_path: str):
    pem = open(pem_path, 'rb').read()
    priv = load_pem_private_key(pem, password=None)
    # Raw private key scalar: 32 bytes big-endian
    scalar = priv.private_numbers().private_value.to_bytes(32, 'big')
    open(out_path, 'wb').write(scalar)
    print(f'Wrote {len(scalar)} bytes → {out_path}')

if __name__ == '__main__':
    convert(sys.argv[1], sys.argv[2])