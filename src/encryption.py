"""
Message encryption for the two formats vanetza supports, chosen by the recipient
certificate (like signing.py chooses by the signer certificate):

  v3 — EtsiTs103097Data-Encrypted (ETSI TS 103 097 v1.3.1 clause 5.3 / IEEE 1609.2-2016),
       canonical COER via asn1tools: encryptedData { recipients: [certRecipInfo],
       ciphertext: aes128ccm }. ECIES P1 = SHA-256 of the recipient certificate
       (IEEE 1609.2 clause 6.3.34, certRecipInfo).
       Signed-and-encrypted = EtsiTs103097Data-Encrypted containing an
       EtsiTs103097Data-Signed (TS 103 097 clause 5.1).

  v2 — SecuredMessage (ETSI TS 103 097 v1.2.1), vanetza binary format: header fields
       encryption_parameters (AES-128-CCM + nonce) and recipient_info (ECIES NIST P-256),
       payload type encrypted, or signed_and_encrypted with a signature trailer over
       the whole message including the ciphertext. ECIES P1 = empty string.

AES-128-CCM uses a 12-byte nonce and a 16-byte tag in both formats; ECIES wraps the
fresh 16-byte AES key (crypto.ecies_encrypt / ecies_decrypt).
"""
import hashlib
from typing import Optional

from .types import PublicKeyAlgorithm, now_its_time64
from .crypto import (
    ecies_encrypt, ecies_decrypt,
    aes_ccm_encrypt, aes_ccm_decrypt,
    random_bytes, hash_certificate,
)
from .encoding import asn1_codec as codec
from . import signing
from . import v1_encoding as v2enc


_V3_DATA_TYPE = 'EtsiTs103097Data'


def _require_p256(algorithm: PublicKeyAlgorithm) -> None:
    if algorithm != PublicKeyAlgorithm.ECDSA_NIST_P256:
        raise ValueError("vanetza encrypted messages (v2 and v3) are NIST P-256 only")


def _wrap_key(recipient_enc_pub_key, p1: bytes):
    """Fresh AES-128 key and nonce; returns (aes_key, nonce, ecies result)."""
    aes_key = random_bytes(16)
    nonce = random_bytes(12)   # unique per encryption (NFR-SEC-04)
    return aes_key, nonce, ecies_encrypt(recipient_enc_pub_key, aes_key, p1)


# ── v3: EtsiTs103097Data-Encrypted (COER) ────────────────────────────────────

def _v3_encrypt(plaintext: bytes, recipient_cert_encoded: bytes, recipient_enc_pub_key) -> bytes:
    p1 = hashlib.sha256(recipient_cert_encoded).digest()   # certRecipInfo
    aes_key, nonce, wrapped = _wrap_key(recipient_enc_pub_key, p1)
    v = wrapped['v']
    return codec.encode(_V3_DATA_TYPE, {
        'protocolVersion': 3,
        'content': ('encryptedData', {
            'recipients': [('certRecipInfo', {
                'recipientId': hash_certificate(recipient_cert_encoded, PublicKeyAlgorithm.ECDSA_NIST_P256),
                'encKey': ('eciesNistP256', {
                    'v': ('compressed-y-0' if v[0] == 0x02 else 'compressed-y-1', v[1:]),
                    'c': wrapped['c'],
                    't': wrapped['t'],
                }),
            })],
            'ciphertext': ('aes128ccm', {
                'nonce': nonce,
                'ccmCiphertext': aes_ccm_encrypt(aes_key, nonce, plaintext),
            }),
        }),
    })


def _v3_decrypt(message: bytes, recipient_enc_priv_key, my_cert_encoded: bytes) -> bytes:
    try:
        value = codec.decode(_V3_DATA_TYPE, message)
        if codec.encode(_V3_DATA_TYPE, value) != message:
            raise ValueError("re-encoding differs")
    except Exception as e:
        raise ValueError(f"not a canonical COER EtsiTs103097Data: {e}") from None
    kind, encrypted = value['content']
    if kind != 'encryptedData':
        raise ValueError(f"expected encryptedData, got {kind}")

    my_id = hash_certificate(my_cert_encoded, PublicKeyAlgorithm.ECDSA_NIST_P256)
    for recip_kind, info in encrypted['recipients']:
        if recip_kind == 'certRecipInfo' and info['recipientId'] == my_id:
            key_kind, key = info['encKey']
            if key_kind != 'eciesNistP256':
                raise ValueError(f"unsupported encKey {key_kind}")
            point_kind, x = key['v']
            prefix = {'compressed-y-0': 0x02, 'compressed-y-1': 0x03}.get(point_kind)
            if prefix is not None:
                v = bytes([prefix]) + x
            elif point_kind == 'uncompressedP256':
                v = b'\x04' + x['x'] + x['y']
            else:
                raise ValueError(f"unsupported ECIES ephemeral key {point_kind}")
            aes_key = ecies_decrypt(recipient_enc_priv_key, v, key['c'], key['t'],
                                    hashlib.sha256(my_cert_encoded).digest())
            break
    else:
        raise ValueError("No matching certRecipInfo recipient found in EncryptedData")

    ct_kind, ct = encrypted['ciphertext']
    if ct_kind != 'aes128ccm':
        raise ValueError(f"unsupported symmetric ciphertext {ct_kind}")
    return aes_ccm_decrypt(aes_key, ct['nonce'], ct['ccmCiphertext'])


# ── v2: SecuredMessage (TS 103 097 v1.2.1) ───────────────────────────────────

def _v2_encryption_fields(recipient_cert_encoded: bytes, recipient_enc_pub_key):
    """encryption_parameters + recipient_info header fields; returns (fields, aes_key, nonce)."""
    aes_key, nonce, wrapped = _wrap_key(recipient_enc_pub_key, b'')   # v1.2.1: P1 empty
    enc_params = (bytes([signing._V2_HEADER_ENCRYPTION_PARAMETERS, signing._V2_AES128_CCM]) + nonce)
    recipient = (v2enc.hash_certificate_v1(recipient_cert_encoded)
                 + bytes([signing._V2_ECIES_NISTP256])
                 + wrapped['v']                       # EccPoint: type 0x02/0x03 + x
                 + wrapped['c'] + wrapped['t'])
    recipients = (bytes([signing._V2_HEADER_RECIPIENT_INFO])
                  + v2enc.encode_length(len(recipient)) + recipient)
    return enc_params + recipients, aes_key, nonce


def _v2_encrypt(plaintext: bytes, recipient_cert_encoded: bytes, recipient_enc_pub_key,
                generation_time_us: int) -> bytes:
    extra, aes_key, nonce = _v2_encryption_fields(recipient_cert_encoded, recipient_enc_pub_key)
    fields = signing._v2_header_fields(None, True, None, generation_time_us, None, None, extra)
    ciphertext = aes_ccm_encrypt(aes_key, nonce, plaintext)
    # unsigned: empty trailer field list
    return signing._v2_message_prefix(fields, signing._V2_PAYLOAD_ENCRYPTED, ciphertext) + b'\x00'


def _v2_decrypt(message: bytes, recipient_enc_priv_key, my_cert_encoded: bytes) -> bytes:
    msg = signing.v2_parse(message)
    if msg['payload_type'] not in (signing._V2_PAYLOAD_ENCRYPTED, signing._V2_PAYLOAD_SIGNED_AND_ENCRYPTED):
        raise ValueError(f"payload type {msg['payload_type']} is not encrypted")
    if msg['nonce'] is None:
        raise ValueError("missing encryption_parameters header field")
    my_id = v2enc.hash_certificate_v1(my_cert_encoded)
    for recipient in msg['recipients']:
        if recipient['cert_id'] == my_id:
            aes_key = ecies_decrypt(recipient_enc_priv_key, recipient['v'], recipient['c'], recipient['t'], b'')
            break
    else:
        raise ValueError("No matching recipient found in recipient_info")
    return aes_ccm_decrypt(aes_key, msg['nonce'], msg['payload'])


# ── Public API ───────────────────────────────────────────────────────────────

def encrypt_data(plaintext: bytes,
                 recipient_cert_encoded: bytes,
                 recipient_enc_pub_key,
                 algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
                 generation_time_us: Optional[int] = None) -> bytes:
    """
    Encrypt data for a single recipient: EtsiTs103097Data-Encrypted-Unicast (v3
    recipient certificate) or an encrypted v2 SecuredMessage (v2 certificate).

    Args:
        plaintext: Data to encrypt.
        recipient_cert_encoded: Encoded recipient certificate (selects the format).
        recipient_enc_pub_key: The certificate's ECIES public encryption key.
        algorithm: must be NIST P-256.
        generation_time_us: v2 only, generation_time header (defaults to now).
    """
    _require_p256(algorithm)
    if signing.cert_format(recipient_cert_encoded) == 'v2':
        return _v2_encrypt(plaintext, recipient_cert_encoded, recipient_enc_pub_key,
                           generation_time_us or now_its_time64())
    return _v3_encrypt(plaintext, recipient_cert_encoded, recipient_enc_pub_key)


def decrypt_data(encrypted_data_bytes: bytes,
                 recipient_enc_priv_key,
                 my_cert_encoded: bytes,
                 algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256) -> bytes:
    """
    Decrypt an encrypted message addressed to my_cert_encoded (v3 EtsiTs103097Data-Encrypted
    or v2 SecuredMessage). Returns the plaintext: for v3 signed-and-encrypted data this is
    the inner EtsiTs103097Data-Signed, for v2 the payload of the message. Raises ValueError
    if the message is malformed, not addressed to this certificate, or fails authentication.
    """
    _require_p256(algorithm)
    if signing.message_format(encrypted_data_bytes) == 'v2':
        return _v2_decrypt(encrypted_data_bytes, recipient_enc_priv_key, my_cert_encoded)
    return _v3_decrypt(encrypted_data_bytes, recipient_enc_priv_key, my_cert_encoded)


def sign_and_encrypt(payload: bytes,
                     psid: int,
                     signer_priv_key,
                     signer_cert_encoded: bytes,
                     recipient_cert_encoded: bytes,
                     recipient_enc_pub_key,
                     algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
                     use_digest: bool = True,
                     generation_location: Optional[tuple] = None) -> bytes:
    """
    Sign, then encrypt for one recipient.

    v3: EtsiTs103097Data-SignedAndEncrypted-Unicast — an EtsiTs103097Data-Encrypted
        whose plaintext is an EtsiTs103097Data-Signed.
    v2: one SecuredMessage with payload type signed_and_encrypted; the signature
        covers the headers and the ciphertext (TS 103 097 v1.2.1 clause 5.6).
        The generic profile applies (clause 7.3): the signer is always the
        certificate, generation_location is required, and CAM/DENM ITS-AIDs are
        rejected (CAMs/DENMs shall not be encrypted, clauses 7.1/7.2).
    Signer and recipient certificates must be of the same version.
    """
    _require_p256(algorithm)
    signer_fmt = signing.cert_format(signer_cert_encoded)
    if signer_fmt != signing.cert_format(recipient_cert_encoded):
        raise ValueError("signer and recipient certificates must both be v2 or both be v3")

    if signer_fmt == 'v3':
        signed = signing.sign_data(
            payload=payload, psid=psid, signer_priv_key=signer_priv_key,
            signer_cert_encoded=signer_cert_encoded, algorithm=algorithm, use_digest=use_digest,
            generation_location=generation_location)
        return _v3_encrypt(signed, recipient_cert_encoded, recipient_enc_pub_key)

    signing._v2_generic_profile(psid, generation_location, 'signed_and_encrypted message')
    extra, aes_key, nonce = _v2_encryption_fields(recipient_cert_encoded, recipient_enc_pub_key)
    ciphertext = aes_ccm_encrypt(aes_key, nonce, payload)
    prefix = signing._v2_signing_prefix(
        signer_cert_encoded, False, psid, now_its_time64(), generation_location, None,
        signing._V2_PAYLOAD_SIGNED_AND_ENCRYPTED, ciphertext, extra_fields=extra)
    return signing._v2_sign(prefix, signer_priv_key)


def decrypt_and_verify(encrypted_signed_bytes: bytes,
                       recipient_enc_priv_key,
                       my_cert_encoded: bytes,
                       signer_pub_key,
                       algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
                       signer_cert_encoded=None) -> dict:
    """
    Decrypt a signed-and-encrypted message and verify its signature.
    signer_cert_encoded is required when the message is digest-signed.
    Returns the verify_signed_data() dict with 'payload' set to the plaintext.
    """
    _require_p256(algorithm)
    if signing.message_format(encrypted_signed_bytes) == 'v3':
        signed_bytes = _v3_decrypt(encrypted_signed_bytes, recipient_enc_priv_key, my_cert_encoded)
        return signing.verify_signed_data(signed_bytes, signer_pub_key, algorithm,
                                          signer_cert_encoded=signer_cert_encoded)

    # v2: the signature covers the ciphertext, so verify first, then decrypt
    result = signing.verify_signed_data(encrypted_signed_bytes, signer_pub_key, algorithm,
                                        signer_cert_encoded=signer_cert_encoded)
    if result.get('valid'):
        result['payload'] = _v2_decrypt(encrypted_signed_bytes, recipient_enc_priv_key, my_cert_encoded)
    return result
