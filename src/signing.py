"""
Secure message signing per ETSI TS 103 097 V2.2.1 clause 5.2.
Produces EtsiTs103097Data-Signed structures.
"""
import time
from typing import Optional

from .types import (
    PublicKeyAlgorithm, ItsAid, SignerChoice,
    now_its_time64, unix_to_its_time64
)
from .coer import (
    encode_uint8, encode_uint16, encode_uint32, encode_uint64,
    encode_length, encode_octet_string, encode_choice, encode_enumerated
)
from .crypto import (
    ecdsa_sign, ecdsa_verify, hash_certificate, hash_data,
    public_key_to_point, sha256, sha384
)
from .encoding import encode_signature, decode_signature, encode_psid, decode_psid


# ── ITS message types (per profile) ──────────────────────────────────────────

PSID_CAM  = ItsAid.CAM
PSID_DENM = ItsAid.DENM


def _encode_generation_time(ts_us: int) -> bytes:
    """Encode Time64 (microseconds since ITS epoch) as 8 bytes."""
    return ts_us.to_bytes(8, 'big')


# ── HeaderInfo encoding ───────────────────────────────────────────────────────

def encode_header_info(psid: int,
                       generation_time_us: int,
                       generation_location: Optional[tuple] = None,
                       expiry_time_us: Optional[int] = None,
                       encryption_key=None,
                       inline_p2pcd: Optional[bytes] = None,
                       requested_cert: Optional[bytes] = None) -> bytes:
    """
    HeaderInfo SEQUENCE (IEEE 1609.2 clause 6.3.9):
      psid                  Psid,
      generationTime        Time64 OPTIONAL,
      expiryTime            Time64 OPTIONAL,
      generationLocation    ThreeDLocation OPTIONAL,
      p2pcdLearningRequest  HashedId3 OPTIONAL,       -- always absent
      missingCrlIdentifier  MissingCrlIdentifier OPTIONAL, -- always absent
      encryptionKey         EncryptionKey OPTIONAL,
      inlineP2pcdRequest    SequenceOfHashedId3 OPTIONAL,
      requestedCertificate  Certificate OPTIONAL,
    """
    psid_enc = encode_psid(psid)
    gen_time_enc = _encode_generation_time(generation_time_us)

    # Optional fields bitmask: generationTime(0) expiry(1) location(2) encKey(6) p2pcd(7) reqCert(8)
    # We track: genTime, expiryTime, genLocation, encKey, inlineP2pcd, requestedCert
    has_expiry = expiry_time_us is not None
    has_location = generation_location is not None
    has_enc_key = encryption_key is not None
    has_p2pcd = inline_p2pcd is not None
    has_req_cert = requested_cert is not None

    # 2-byte presence bitmap for 9 optional fields
    bitmap = 0
    bitmap |= (1 << 15)  # generationTime always present
    if has_expiry:
        bitmap |= (1 << 14)
    if has_location:
        bitmap |= (1 << 13)
    # bits 12, 11: p2pcdLearningRequest, missingCrlIdentifier always absent
    if has_enc_key:
        bitmap |= (1 << 10)
    if has_p2pcd:
        bitmap |= (1 << 9)
    if has_req_cert:
        bitmap |= (1 << 8)

    result = psid_enc + bitmap.to_bytes(2, 'big') + gen_time_enc

    if has_expiry:
        result += _encode_generation_time(expiry_time_us)
    if has_location:
        lat, lon, elev = generation_location
        result += lat.to_bytes(4, 'big', signed=True)
        result += lon.to_bytes(4, 'big', signed=True)
        result += elev.to_bytes(2, 'big', signed=True)
    if has_p2pcd:
        result += encode_octet_string(inline_p2pcd)
    if has_req_cert:
        result += encode_octet_string(requested_cert)

    return result


# ── SignerIdentifier encoding ─────────────────────────────────────────────────

def encode_signer_digest(cert_hash: bytes) -> bytes:
    """SignerIdentifier: digest (HashedId8 = 8 bytes)."""
    return encode_choice(SignerChoice.DIGEST, cert_hash)  # tag=0


def encode_signer_certificate(cert_encoded: bytes) -> bytes:
    """SignerIdentifier: certificate (full EtsiTs103097Certificate)."""
    return encode_choice(SignerChoice.CERTIFICATE, encode_octet_string(cert_encoded))  # tag=1


# ── SignedData / EtsiTs103097Data-Signed ─────────────────────────────────────

def sign_data(payload: bytes,
              psid: int,
              signer_priv_key,
              signer_cert_encoded: bytes,
              algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
              use_digest: bool = True,
              generation_time_us: Optional[int] = None,
              generation_location: Optional[tuple] = None,
              expiry_time_us: Optional[int] = None) -> bytes:
    """
    Create an EtsiTs103097Data-Signed structure.

    Args:
        payload: The plaintext data to sign.
        psid: ITS-AID for this message type.
        signer_priv_key: ECDSA private key of the signer (AT or EC).
        signer_cert_encoded: COER-encoded signer certificate.
        algorithm: ECDSA algorithm.
        use_digest: If True, signer field = digest(cert); else full certificate.
        generation_time_us: Time64 microseconds. Defaults to now.
        generation_location: Optional (lat, lon, elev) tuple (0.1 microdegree units).
        expiry_time_us: Optional expiry Time64.

    Returns:
        COER-encoded EtsiTs103097Data-Signed bytes.
    """
    gen_time = generation_time_us or now_its_time64()

    # Build HeaderInfo
    header = encode_header_info(
        psid=psid,
        generation_time_us=gen_time,
        generation_location=generation_location,
        expiry_time_us=expiry_time_us,
    )

    # Payload encoding: SignedDataPayload { data: EtsiTs103097Data-Unsecured }
    # EtsiTs103097Data version=3, content=unsecuredData
    inner_data = _make_unsecured_data(payload)
    payload_enc = encode_choice(0, encode_octet_string(inner_data))  # data choice

    # ToBeSignedData ::= SEQUENCE { payload, headerInfo }
    tbs_data = payload_enc + header

    # hashId: sha256=0, sha384=1
    hash_id = encode_uint8(0 if algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256 else 1)

    # Compute signer identifier
    cert_hash = hash_certificate(signer_cert_encoded, algorithm)
    if use_digest:
        signer_enc = encode_signer_digest(cert_hash)
    else:
        signer_enc = encode_signer_certificate(signer_cert_encoded)

    # Sign ToBeSignedData
    r, s = ecdsa_sign(signer_priv_key, tbs_data, algorithm)
    from .types import EcdsaSignature
    sig = EcdsaSignature(r=r, s=s, algorithm=algorithm)
    sig_enc = encode_signature(sig)

    # SignedData ::= SEQUENCE { hashId, tbsData, signer, signature }
    signed_data = hash_id + tbs_data + signer_enc + sig_enc

    # EtsiTs103097Data ::= Ieee1609Dot2Data
    # content = signedData (choice index 1)
    return _make_ieee1609dot2_data(encode_choice(1, signed_data))


def sign_data_external_payload(payload_hash: bytes,
                                psid: int,
                                signer_priv_key,
                                signer_cert_encoded: bytes,
                                algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
                                use_digest: bool = True,
                                generation_time_us: Optional[int] = None) -> bytes:
    """
    Create EtsiTs103097Data-SignedExternalPayload (external payload by hash).
    Per FR-SN-07.
    """
    gen_time = generation_time_us or now_its_time64()
    header = encode_header_info(psid=psid, generation_time_us=gen_time)

    # Payload: extDataHash choice (SHA-256 hash of external payload)
    # extDataHash CHOICE sha256HashedData [0]: 32 bytes
    ext_hash_enc = encode_choice(1, encode_choice(0, payload_hash))  # extDataHash

    tbs_data = ext_hash_enc + header

    hash_id = encode_uint8(0 if algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256 else 1)

    cert_hash = hash_certificate(signer_cert_encoded, algorithm)
    signer_enc = encode_signer_digest(cert_hash) if use_digest else \
        encode_signer_certificate(signer_cert_encoded)

    r, s = ecdsa_sign(signer_priv_key, tbs_data, algorithm)
    from .types import EcdsaSignature
    sig = EcdsaSignature(r=r, s=s, algorithm=algorithm)
    sig_enc = encode_signature(sig)

    signed_data = hash_id + tbs_data + signer_enc + sig_enc
    return _make_ieee1609dot2_data(encode_choice(1, signed_data))


# ── CAM signing (profile 10.1) ────────────────────────────────────────────────

def sign_cam(cam_payload: bytes,
             at_priv_key,
             at_cert_encoded: bytes,
             algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
             use_digest: bool = True,
             include_full_cert_now: bool = False) -> bytes:
    """
    Sign a CAM per ETSI TS 103 097 V2.2.1 profile 10.1.

    signer: digest by default; full certificate included per the standard's
            once-per-second rule (set include_full_cert_now=True).
    generationTime: always present.
    generationLocation: absent (CAM profile).
    """
    return sign_data(
        payload=cam_payload,
        psid=int(ItsAid.CAM),
        signer_priv_key=at_priv_key,
        signer_cert_encoded=at_cert_encoded,
        algorithm=algorithm,
        use_digest=not include_full_cert_now,
    )


# ── DENM signing (profile 10.2) ───────────────────────────────────────────────

def sign_denm(denm_payload: bytes,
              at_priv_key,
              at_cert_encoded: bytes,
              generation_location: tuple,
              algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256) -> bytes:
    """
    Sign a DENM per ETSI TS 103 097 V2.2.1 profile 10.2.

    signer: certificate (full AT always).
    generationLocation: always present.
    """
    return sign_data(
        payload=denm_payload,
        psid=int(ItsAid.DENM),
        signer_priv_key=at_priv_key,
        signer_cert_encoded=at_cert_encoded,
        algorithm=algorithm,
        use_digest=False,   # DENM always includes full certificate
        generation_location=generation_location,
    )


# ── Verification ──────────────────────────────────────────────────────────────

def verify_signed_data(signed_data_bytes: bytes,
                       signer_pub_key,
                       algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256) -> dict:
    """
    Verify an EtsiTs103097Data-Signed structure.

    Returns dict with 'valid' bool and parsed fields.
    """
    try:
        # Parse outer Ieee1609Dot2Data
        offset = 0
        version = signed_data_bytes[offset]; offset += 1  # version=3
        content_choice = signed_data_bytes[offset]; offset += 1  # should be 1 (signedData)

        if content_choice != 1:
            return {'valid': False, 'error': f'Expected signedData (1), got {content_choice}'}

        # Parse SignedData
        hash_id = signed_data_bytes[offset]; offset += 1

        # The remaining bytes before signer and signature form the tbs_data.
        # We need to identify the boundary. This requires parsing the tbs_data.
        # For verification, we reconstruct tbs_data from known offsets.
        tbs_start = offset

        # Parse payload (SignedDataPayload)
        payload_choice = signed_data_bytes[offset]; offset += 1
        if payload_choice == 0:  # data
            inner_len_b = signed_data_bytes[offset]
            if inner_len_b < 0x80:
                inner_len = inner_len_b; offset += 1
            else:
                nb = inner_len_b & 0x7F
                inner_len = int.from_bytes(signed_data_bytes[offset+1:offset+1+nb], 'big')
                offset += 1 + nb
            inner_data = signed_data_bytes[offset:offset+inner_len]; offset += inner_len
            payload = _parse_unsecured_data(inner_data)
        else:
            return {'valid': False, 'error': f'Unsupported payload choice {payload_choice}'}

        # Parse HeaderInfo: psid (variable), then bitmap, then gen_time
        psid, offset = decode_psid(signed_data_bytes, offset)
        bitmap = int.from_bytes(signed_data_bytes[offset:offset+2], 'big'); offset += 2
        gen_time = int.from_bytes(signed_data_bytes[offset:offset+8], 'big'); offset += 8

        gen_location = None
        if bitmap & (1 << 13):
            lat = int.from_bytes(signed_data_bytes[offset:offset+4], 'big', signed=True); offset += 4
            lon = int.from_bytes(signed_data_bytes[offset:offset+4], 'big', signed=True); offset += 4
            elev = int.from_bytes(signed_data_bytes[offset:offset+2], 'big', signed=True); offset += 2
            gen_location = (lat, lon, elev)

        tbs_end = offset
        tbs_data = signed_data_bytes[tbs_start:tbs_end]

        # Parse signer
        signer_choice = signed_data_bytes[offset]; offset += 1
        signer_info = {}
        if signer_choice == 0:  # digest
            cert_hash = signed_data_bytes[offset:offset+8]; offset += 8
            signer_info = {'type': 'digest', 'hash': cert_hash.hex()}
        elif signer_choice == 1:  # certificate
            cert_len_b = signed_data_bytes[offset]
            if cert_len_b < 0x80:
                cert_len = cert_len_b; offset += 1
            else:
                nb = cert_len_b & 0x7F
                cert_len = int.from_bytes(signed_data_bytes[offset+1:offset+1+nb], 'big')
                offset += 1 + nb
            cert_bytes = signed_data_bytes[offset:offset+cert_len]; offset += cert_len
            signer_info = {'type': 'certificate', 'cert_len': cert_len}

        # Parse signature
        sig, _ = decode_signature(signed_data_bytes, offset)

        # Verify
        valid = ecdsa_verify(signer_pub_key, tbs_data, sig.r, sig.s, algorithm)

        return {
            'valid': valid,
            'psid': psid,
            'generation_time_us': gen_time,
            'generation_location': gen_location,
            'signer': signer_info,
            'payload': payload,
        }

    except Exception as e:
        return {'valid': False, 'error': str(e)}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _make_unsecured_data(payload: bytes) -> bytes:
    """
    EtsiTs103097Data-Unsecured:
    version=3, content=unsecuredData[0](payload)
    """
    return bytes([3]) + encode_choice(0, encode_octet_string(payload))


def _parse_unsecured_data(data: bytes) -> bytes:
    """Parse EtsiTs103097Data-Unsecured and return inner payload bytes."""
    version = data[0]  # 3
    content_choice = data[1]  # 0 = unsecuredData
    if content_choice != 0:
        return data[2:]  # fallback
    # Decode octet string
    offset = 2
    length_b = data[offset]
    if length_b < 0x80:
        length = length_b; offset += 1
    else:
        nb = length_b & 0x7F
        length = int.from_bytes(data[offset+1:offset+1+nb], 'big')
        offset += 1 + nb
    return data[offset:offset+length]


def _make_ieee1609dot2_data(content: bytes) -> bytes:
    """Ieee1609Dot2Data wrapper: version=3 + content."""
    return bytes([3]) + content


