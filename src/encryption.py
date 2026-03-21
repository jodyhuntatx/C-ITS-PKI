"""
Message encryption per ETSI TS 103 097 V2.2.1 clause 5.3.
Produces EtsiTs103097Data-Encrypted structures using ECIES + AES-128-CCM.
"""
import os
from typing import Optional, List

from .types import PublicKeyAlgorithm, RecipientChoice
from .coer import (
    encode_uint8, encode_octet_string, encode_choice, encode_length
)
from .crypto import (
    ecies_encrypt, ecies_decrypt,
    aes_ccm_encrypt, aes_ccm_decrypt,
    random_bytes, hash_certificate
)
from .signing import _make_ieee1609dot2_data


# ── RecipientInfo encoding ────────────────────────────────────────────────────

def _encode_cert_recip_info(cert: bytes,
                             algorithm: PublicKeyAlgorithm,
                             ecies_result: dict) -> bytes:
    """
    certRecipInfo [2]:
    PKRecipientInfo ::= SEQUENCE {
      recipientId  HashedId8,        -- last 8 bytes of cert hash (SHA-256)
      encKey       EncryptedDataEncryptionKey
    }
    EncryptedDataEncryptionKey CHOICE:
      eciesNistP256EncryptedKey [0]: EciesP256EncryptedKey
    EciesP256EncryptedKey ::= SEQUENCE {
      v    EccP256CurvePoint,  -- compressed (33 bytes: choice tag + 32 byte x)
      c    OCTET STRING (SIZE(16)),
      t    OCTET STRING (SIZE(16))
    }
    """
    recip_id = hash_certificate(cert, algorithm)  # 8 bytes

    # Encode v (ephemeral public key) as compressed EccP256CurvePoint
    v = ecies_result['v']       # 33 bytes (prefix + x)
    c = ecies_result['c']       # 16 bytes
    t = ecies_result['t']       # 16 bytes

    # Compressed point: prefix 0x02 -> y0 (choice 2), 0x03 -> y1 (choice 3)
    prefix = v[0]
    y_tag = 2 if prefix == 0x02 else 3
    v_enc = encode_choice(y_tag, v[1:])   # x-coordinate only (32 bytes)

    ecies_key = v_enc + c + t  # EciesP256EncryptedKey fields (fixed sizes, no length prefix)
    enc_key = encode_choice(0, ecies_key)  # eciesNistP256EncryptedKey

    pk_recip_info = recip_id + enc_key
    return encode_choice(RecipientChoice.CERT_RECIP_INFO, pk_recip_info)


def _decode_ecies_recip_info(data: bytes, offset: int) -> tuple:
    """
    Decode a certRecipInfo entry.
    Returns (recip_id: bytes, v: bytes, c: bytes, t: bytes, new_offset: int).
    """
    recip_id = data[offset:offset+8]; offset += 8

    # EncryptedDataEncryptionKey CHOICE
    enc_key_choice = data[offset]; offset += 1  # should be 0 (eciesNistP256)

    # EciesP256EncryptedKey
    # v: EccP256CurvePoint (compressed)
    v_choice = data[offset]; offset += 1  # 2 or 3
    x = data[offset:offset+32]; offset += 32
    prefix = 0x02 if v_choice == 2 else 0x03
    v = bytes([prefix]) + x

    c = data[offset:offset+16]; offset += 16
    t = data[offset:offset+16]; offset += 16

    return recip_id, v, c, t, offset


# ── SymmetricCiphertext encoding ─────────────────────────────────────────────

def _encode_aes128ccm_ciphertext(nonce: bytes, ciphertext: bytes) -> bytes:
    """
    SymmetricCiphertext CHOICE:
      aes128ccm [0]: AesCcmCiphertext ::= SEQUENCE {
        nonce  OCTET STRING (SIZE(12)),
        ccmCiphertext OPAQUE (variable)
      }
    """
    aes_ccm_ct = nonce + encode_octet_string(ciphertext)
    return encode_choice(0, aes_ccm_ct)


def _decode_aes128ccm_ciphertext(data: bytes, offset: int) -> tuple:
    """Returns (nonce, ciphertext, new_offset)."""
    sym_choice = data[offset]; offset += 1  # should be 0
    nonce = data[offset:offset+12]; offset += 12
    ct_len_b = data[offset]
    if ct_len_b < 0x80:
        ct_len = ct_len_b; offset += 1
    else:
        nb = ct_len_b & 0x7F
        ct_len = int.from_bytes(data[offset+1:offset+1+nb], 'big')
        offset += 1 + nb
    ciphertext = data[offset:offset+ct_len]; offset += ct_len
    return nonce, ciphertext, offset


# ── EncryptedData / EtsiTs103097Data-Encrypted ───────────────────────────────

def encrypt_data(plaintext: bytes,
                 recipient_cert_encoded: bytes,
                 recipient_enc_pub_key,
                 algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256) -> bytes:
    """
    Encrypt data for a single recipient (EtsiTs103097Data-Encrypted-Unicast).

    Process per IEEE 1609.2 §5.3.5 / ETSI TS 103 097 clause 5.3:
      1. Generate random 16-byte AES key A and 12-byte nonce n.
      2. Encrypt plaintext with AES-128-CCM(A, n).
      3. Encrypt A using ECIES with recipient's public encryption key.
      4. Pack into EncryptedData structure.

    Args:
        plaintext: Data to encrypt (bytes).
        recipient_cert_encoded: COER-encoded recipient certificate.
        recipient_enc_pub_key: Recipient's ECIES public key (cryptography key object).
        algorithm: Determines hash for recipient ID (P-256 → SHA-256).

    Returns:
        COER-encoded EtsiTs103097Data-Encrypted bytes.
    """
    # Step 1: Generate symmetric key and nonce
    aes_key = random_bytes(16)  # AES-128 key
    nonce = random_bytes(12)    # CCM nonce (unique per encryption, NFR-SEC-04)

    # Step 2: AES-128-CCM encrypt
    ciphertext = aes_ccm_encrypt(aes_key, nonce, plaintext)  # ct || 16-byte tag

    # Step 3: ECIES encrypt AES key
    ecies_result = ecies_encrypt(recipient_enc_pub_key, aes_key)

    # Step 4: Build EncryptedData structure
    # recipients: SequenceOfRecipientInfo (exactly one for unicast)
    recipient_enc = _encode_cert_recip_info(recipient_cert_encoded, algorithm, ecies_result)
    recipients_enc = encode_octet_string(recipient_enc)  # SequenceOf wrapper

    # ciphertext: SymmetricCiphertext
    sym_ct = _encode_aes128ccm_ciphertext(nonce, ciphertext)

    # EncryptedData ::= SEQUENCE { recipients, ciphertext }
    encrypted_data = recipients_enc + sym_ct

    # EtsiTs103097Data content = encryptedData (choice 3)
    return _make_ieee1609dot2_data(encode_choice(3, encrypted_data))


def decrypt_data(encrypted_data_bytes: bytes,
                 recipient_enc_priv_key,
                 my_cert_encoded: bytes,
                 algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256) -> bytes:
    """
    Decrypt an EtsiTs103097Data-Encrypted structure.

    Args:
        encrypted_data_bytes: COER-encoded encrypted message.
        recipient_enc_priv_key: Recipient's ECIES private key.
        my_cert_encoded: COER-encoded recipient certificate (to match recipient ID).
        algorithm: Determines hash for recipient ID matching.

    Returns:
        Decrypted plaintext bytes.
    """
    offset = 0

    # Parse Ieee1609Dot2Data header
    version = encrypted_data_bytes[offset]; offset += 1  # 3
    content_choice = encrypted_data_bytes[offset]; offset += 1  # 3 = encryptedData

    if content_choice != 3:
        raise ValueError(f"Expected encryptedData (3), got {content_choice}")

    # Parse EncryptedData
    # recipients: SequenceOfRecipientInfo (length-prefixed)
    recipients_len_b = encrypted_data_bytes[offset]
    if recipients_len_b < 0x80:
        recipients_len = recipients_len_b; offset += 1
    else:
        nb = recipients_len_b & 0x7F
        recipients_len = int.from_bytes(encrypted_data_bytes[offset+1:offset+1+nb], 'big')
        offset += 1 + nb

    recipients_end = offset + recipients_len
    recipients_data = encrypted_data_bytes[offset:recipients_end]
    offset = recipients_end

    # Parse recipients to find matching RecipientInfo
    my_hash = hash_certificate(my_cert_encoded, algorithm)
    aes_key = None
    r_offset = 0
    while r_offset < len(recipients_data):
        recip_choice = recipients_data[r_offset]; r_offset += 1
        if recip_choice == RecipientChoice.CERT_RECIP_INFO:
            recip_id, v, c, t, r_offset = _decode_ecies_recip_info(recipients_data, r_offset)
            if recip_id == my_hash:
                aes_key = ecies_decrypt(recipient_enc_priv_key, v, c, t)
                break

    if aes_key is None:
        raise ValueError("No matching recipient found in EncryptedData")

    # Parse SymmetricCiphertext
    nonce, ciphertext_with_tag, _ = _decode_aes128ccm_ciphertext(encrypted_data_bytes, offset)

    # Decrypt
    return aes_ccm_decrypt(aes_key, nonce, ciphertext_with_tag)


# ── Signed-and-Encrypted ─────────────────────────────────────────────────────

def sign_and_encrypt(payload: bytes,
                     psid: int,
                     signer_priv_key,
                     signer_cert_encoded: bytes,
                     recipient_cert_encoded: bytes,
                     recipient_enc_pub_key,
                     algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
                     use_digest: bool = True) -> bytes:
    """
    Create EtsiTs103097Data-SignedAndEncrypted:
    An EtsiTs103097Data-Encrypted wrapping an EtsiTs103097Data-Signed.

    Per profile 10.5: sign first, then encrypt the signed structure.
    """
    from .signing import sign_data
    signed = sign_data(
        payload=payload,
        psid=psid,
        signer_priv_key=signer_priv_key,
        signer_cert_encoded=signer_cert_encoded,
        algorithm=algorithm,
        use_digest=use_digest,
    )
    return encrypt_data(
        plaintext=signed,
        recipient_cert_encoded=recipient_cert_encoded,
        recipient_enc_pub_key=recipient_enc_pub_key,
        algorithm=algorithm,
    )


def decrypt_and_verify(encrypted_signed_bytes: bytes,
                       recipient_enc_priv_key,
                       my_cert_encoded: bytes,
                       signer_pub_key,
                       algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256) -> dict:
    """
    Decrypt an EtsiTs103097Data-SignedAndEncrypted and verify the signature.
    Returns dict with 'valid', 'payload', and other parsed fields.
    """
    from .signing import verify_signed_data
    signed_bytes = decrypt_data(
        encrypted_data_bytes=encrypted_signed_bytes,
        recipient_enc_priv_key=recipient_enc_priv_key,
        my_cert_encoded=my_cert_encoded,
        algorithm=algorithm,
    )
    return verify_signed_data(signed_bytes, signer_pub_key, algorithm)
