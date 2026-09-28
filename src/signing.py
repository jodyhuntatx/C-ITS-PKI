"""
Secure message signing for the two formats vanetza supports:

  v3 — EtsiTs103097Data (ETSI TS 103 097 v1.3.1 / IEEE 1609.2-2016), canonical COER,
       encoded with asn1tools against vanetza's ASN.1 modules (see encoding/asn1_codec.py).
       Signature over Hash(Hash(tbsData) || Hash(signer certificate)), IEEE 1609.2
       clause 5.3.1.2.2.

  v2 — SecuredMessage (ETSI TS 103 097 v1.2.1), vanetza's custom binary format
       (vanetza/security/v2/secured_message.cpp). Signature over the message up to
       and including the signature trailer type (TS 103 097 v1.2.1 clause 5.6).

The format is chosen from the signer certificate: a v2 certificate (version byte 2)
produces a v2 SecuredMessage, a v3 certificate produces EtsiTs103097Data.

Profiles (TS 103 097 v1.2.1 clause 7 / v1.3.1 clause 7.1):
  CAM  — psid 36, generationTime, signer = digest (certificate when requested)
  DENM — psid 37, generationTime + generationLocation, signer = certificate
"""
from typing import Optional

from .types import PublicKeyAlgorithm, ItsAid, now_its_time64
from .crypto import (
    ecdsa_sign, ecdsa_verify, hash_certificate, ieee1609_signing_input,
    load_public_key_from_compressed,
)
from .encoding import asn1_codec as codec
from . import v1_encoding as v2enc


# ── ITS message types (per profile) ──────────────────────────────────────────

PSID_CAM  = ItsAid.CAM
PSID_DENM = ItsAid.DENM

_V3_DATA_TYPE = 'EtsiTs103097Data'
_V3_TBS_TYPE = 'ToBeSignedData'


# ── Format detection ─────────────────────────────────────────────────────────

def cert_format(cert_encoded: bytes) -> str:
    """Return 'v2' for vanetza v2 certificates (version byte 2), 'v3' for COER certificates."""
    if cert_encoded[:1] == b'\x02':
        return 'v2'
    return 'v3'


def message_format(message: bytes) -> str:
    """Return 'v2' for a SecuredMessage (protocol version 2), 'v3' for Ieee1609Dot2Data (3)."""
    if message[:1] == b'\x02':
        return 'v2'
    if message[:1] == b'\x03':
        return 'v3'
    raise ValueError(f"Unknown secured message protocol version: {message[:1].hex()}")


def _require_p256(algorithm: PublicKeyAlgorithm) -> None:
    if algorithm != PublicKeyAlgorithm.ECDSA_NIST_P256:
        raise ValueError("vanetza secured messages (v2 and v3) are ECDSA NIST P-256 only")


def _elevation_u16(elev_dm: int) -> int:
    """ElevInt: -4096..61439 decimeters, negative values as 16-bit two's complement."""
    return max(-4096, min(61439, elev_dm)) & 0xFFFF


def _elevation_from_u16(raw: int) -> int:
    return raw - 0x10000 if raw >= 0xF000 else raw


# ── v3: EtsiTs103097Data (COER) ──────────────────────────────────────────────

def _v3_header_info(psid, generation_time_us, generation_location, expiry_time_us) -> dict:
    header = {'psid': int(psid), 'generationTime': generation_time_us}
    if expiry_time_us is not None:
        header['expiryTime'] = expiry_time_us
    if generation_location is not None:
        lat, lon, elev = generation_location
        header['generationLocation'] = {
            'latitude': lat, 'longitude': lon, 'elevation': _elevation_u16(elev)}
    return header


def _v3_sign(tbs: dict, signer_priv_key, signer_cert_encoded: bytes,
             use_digest: bool) -> bytes:
    tbs_encoded = codec.encode(_V3_TBS_TYPE, tbs)
    signing_input = ieee1609_signing_input(tbs_encoded, signer_cert_encoded,
                                           PublicKeyAlgorithm.ECDSA_NIST_P256)
    r, s = ecdsa_sign(signer_priv_key, signing_input, PublicKeyAlgorithm.ECDSA_NIST_P256)

    if use_digest:
        signer = ('digest', hash_certificate(signer_cert_encoded, PublicKeyAlgorithm.ECDSA_NIST_P256))
    else:
        signer = ('certificate', [codec.decode('Certificate', signer_cert_encoded)])

    return codec.encode(_V3_DATA_TYPE, {
        'protocolVersion': 3,
        'content': ('signedData', {
            'hashId': 'sha256',
            'tbsData': tbs,
            'signer': signer,
            'signature': ('ecdsaNistP256Signature', {'rSig': ('x-only', r), 'sSig': s}),
        }),
    })


def _v3_verify(message: bytes, signer_pub_key, signer_cert_encoded: Optional[bytes]) -> dict:
    try:
        value = codec.decode(_V3_DATA_TYPE, message)
        if codec.encode(_V3_DATA_TYPE, value) != message:
            raise ValueError("re-encoding differs")
    except Exception as e:
        return {'valid': False, 'format': 'v3', 'error': f'not a canonical COER EtsiTs103097Data: {e}'}

    kind, signed = value['content']
    if kind != 'signedData':
        return {'valid': False, 'format': 'v3', 'error': f'expected signedData, got {kind}'}
    if signed['hashId'] != 'sha256':
        return {'valid': False, 'format': 'v3', 'error': f"unsupported hashId {signed['hashId']}"}

    tbs = signed['tbsData']
    header = tbs['headerInfo']
    payload_value = tbs['payload']
    if 'data' in payload_value:
        inner_kind, payload = payload_value['data']['content']
        if inner_kind != 'unsecuredData':
            return {'valid': False, 'format': 'v3', 'error': f'unsupported inner content {inner_kind}'}
    elif 'extDataHash' in payload_value:
        payload = payload_value['extDataHash'][1]
    else:
        return {'valid': False, 'format': 'v3', 'error': 'empty SignedDataPayload'}

    # the signing input covers the full signer certificate, also for digest signers
    signer_kind, signer_value = signed['signer']
    if signer_kind == 'certificate':
        if len(signer_value) != 1:
            return {'valid': False, 'format': 'v3', 'error': 'signer must be exactly one certificate'}
        embedded = codec.encode('Certificate', signer_value[0])
        if signer_cert_encoded is not None and embedded != signer_cert_encoded:
            return {'valid': False, 'format': 'v3', 'error': 'embedded signer certificate differs from --at-cert'}
        signer_cert = embedded
        signer_info = {'type': 'certificate', 'cert_len': len(embedded)}
    elif signer_kind == 'digest':
        if signer_cert_encoded is None:
            return {'valid': False, 'format': 'v3',
                    'error': 'message is signed with a certificate digest; the signer certificate is required'}
        expected = hash_certificate(signer_cert_encoded, PublicKeyAlgorithm.ECDSA_NIST_P256)
        if signer_value != expected:
            return {'valid': False, 'format': 'v3', 'error': 'signer digest does not match the AT certificate'}
        signer_cert = signer_cert_encoded
        signer_info = {'type': 'digest', 'hash': signer_value.hex()}
    else:
        return {'valid': False, 'format': 'v3', 'error': f'unsupported signer {signer_kind}'}

    if signer_pub_key is None:
        from .encoding import decode_certificate
        cert, _ = decode_certificate(signer_cert)
        vk = cert.tbs.verify_key_indicator
        signer_pub_key = load_public_key_from_compressed(vk.point.curve, vk.point.compressed)

    sig_kind, sig = signed['signature']
    if sig_kind != 'ecdsaNistP256Signature' or sig['rSig'][0] not in ('x-only', 'compressed-y-0', 'compressed-y-1'):
        return {'valid': False, 'format': 'v3', 'error': f'unsupported signature {sig_kind}'}

    signing_input = ieee1609_signing_input(codec.encode(_V3_TBS_TYPE, tbs), signer_cert,
                                           PublicKeyAlgorithm.ECDSA_NIST_P256)
    valid = ecdsa_verify(signer_pub_key, signing_input, sig['rSig'][1], sig['sSig'],
                         PublicKeyAlgorithm.ECDSA_NIST_P256)

    location = None
    if 'generationLocation' in header:
        loc = header['generationLocation']
        location = (loc['latitude'], loc['longitude'], _elevation_from_u16(loc['elevation']))
    return {
        'valid': valid,
        'format': 'v3',
        'psid': header['psid'],
        'generation_time_us': header.get('generationTime'),
        'generation_location': location,
        'signer': signer_info,
        'payload': payload,
    }


# ── v2: SecuredMessage (TS 103 097 v1.2.1, vanetza binary) ───────────────────

_V2_HEADER_GENERATION_TIME = 0
_V2_HEADER_EXPIRATION = 2
_V2_HEADER_GENERATION_LOCATION = 3
_V2_HEADER_ITS_AID = 5
_V2_HEADER_SIGNER_INFO = 128
_V2_HEADER_ENCRYPTION_PARAMETERS = 129
_V2_HEADER_RECIPIENT_INFO = 130
_V2_SIGNER_DIGEST = 1
_V2_SIGNER_CERTIFICATE = 2
_V2_PAYLOAD_SIGNED = 1
_V2_PAYLOAD_ENCRYPTED = 2
_V2_PAYLOAD_SIGNED_EXTERNAL = 3
_V2_PAYLOAD_SIGNED_AND_ENCRYPTED = 4
_V2_TRAILER_SIGNATURE = 1
_V2_ECDSA_NISTP256_WITH_SHA256 = 0
_V2_ECIES_NISTP256 = 1
_V2_AES128_CCM = 0
_V2_ECC_X_COORDINATE_ONLY = 0
_V2_SIGNATURE_TRAILER_SIZE = 1 + 1 + 1 + 32 + 32   # type, algorithm, point type, R.x, s
_V2_RECIPIENT_INFO_SIZE = 8 + 1 + 33 + 16 + 16       # cert_id, pk alg, compressed V, c, t


_V2_PROFILE_PSIDS = (int(ItsAid.CAM), int(ItsAid.DENM))


def _v2_generic_profile(psid, generation_location, what: str) -> None:
    """
    TS 103 097 V1.2.1 clause 7.3 (generic signed messages, i.e. PSIDs other than
    CAM/DENM): signer_info shall be a certificate and generation_location shall be
    present. CAM/DENM payloads shall be of type signed and not encrypted (7.1, 7.2).
    """
    if int(psid) in _V2_PROFILE_PSIDS:
        raise ValueError(f"v2 {what} is not allowed for CAM/DENM (ITS-AID {int(psid)}): "
                         "TS 103 097 V1.2.1 clauses 7.1/7.2 require payload type signed, not encrypted")
    if generation_location is None:
        raise ValueError(f"v2 {what} needs generation_location "
                         "(TS 103 097 V1.2.1 clause 7.3 generic security profile)")


def _v2_header_fields(signer_cert_encoded, use_digest, psid, generation_time_us,
                      generation_location, expiry_time_us, extra_fields=b'') -> bytes:
    """
    Header field list (without length prefix) in TS 103 097 v1.2.1 clause 7 order:
    signer_info first (if any), then ascending type. extra_fields holds already
    encoded fields with types > its_aid (encryption_parameters, recipient_info).
    """
    fields = b''
    if signer_cert_encoded is not None:
        if use_digest:
            signer_info = bytes([_V2_SIGNER_DIGEST]) + v2enc.hash_certificate_v1(signer_cert_encoded)
        else:
            signer_info = bytes([_V2_SIGNER_CERTIFICATE]) + signer_cert_encoded
        fields += bytes([_V2_HEADER_SIGNER_INFO]) + signer_info
    fields += bytes([_V2_HEADER_GENERATION_TIME]) + generation_time_us.to_bytes(8, 'big')
    if expiry_time_us is not None:
        fields += bytes([_V2_HEADER_EXPIRATION]) + (expiry_time_us // 1_000_000).to_bytes(4, 'big')
    if generation_location is not None:
        lat, lon, elev = generation_location
        fields += (bytes([_V2_HEADER_GENERATION_LOCATION]) + lat.to_bytes(4, 'big', signed=True)
                   + lon.to_bytes(4, 'big', signed=True) + _elevation_u16(elev).to_bytes(2, 'big'))
    if psid is not None:
        fields += bytes([_V2_HEADER_ITS_AID]) + v2enc.encode_intx(int(psid))
    return fields + extra_fields


def _v2_message_prefix(header_fields: bytes, payload_type: int, payload: bytes) -> bytes:
    """Serialize protocol version, header field list and payload (vanetza serialize order)."""
    return (bytes([2]) + v2enc.encode_length(len(header_fields)) + header_fields
            + bytes([payload_type]) + v2enc.encode_length(len(payload)) + payload)


def _v2_signing_prefix(signer_cert_encoded, use_digest, psid, generation_time_us,
                       generation_location, expiry_time_us, payload_type, payload,
                       extra_fields=b'') -> bytes:
    fields = _v2_header_fields(signer_cert_encoded, use_digest, psid, generation_time_us,
                               generation_location, expiry_time_us, extra_fields)
    return _v2_message_prefix(fields, payload_type, payload)


def _v2_sign(prefix: bytes, signer_priv_key) -> bytes:
    # signing input: everything up to and including the signature trailer type
    trailer_head = v2enc.encode_length(_V2_SIGNATURE_TRAILER_SIZE) + bytes([_V2_TRAILER_SIGNATURE])
    r, s = ecdsa_sign(signer_priv_key, prefix + trailer_head, PublicKeyAlgorithm.ECDSA_NIST_P256)
    return (prefix + trailer_head + bytes([_V2_ECDSA_NISTP256_WITH_SHA256, _V2_ECC_X_COORDINATE_ONLY])
            + r + s)


def v2_parse(message: bytes) -> dict:
    """
    Parse a v2 SecuredMessage. Returns a dict with header values, payload_type,
    payload, trailer and trailer_start (offset of the trailer length). Raises
    ValueError on malformed input. Signer certificates are returned undecoded.
    """
    try:
        if message[:1] != b'\x02':
            raise ValueError('protocol version must be 2')
        offset = 1
        header_len, offset = v2enc.decode_length(message, offset)
        header_end = offset + header_len
        out = {'psid': None, 'generation_time_us': None, 'generation_location': None,
               'signer_digest': None, 'signer_cert': None, 'nonce': None, 'recipients': []}
        while offset < header_end:
            ftype = message[offset]; offset += 1
            if ftype == _V2_HEADER_SIGNER_INFO:
                stype = message[offset]; offset += 1
                if stype == _V2_SIGNER_DIGEST:
                    out['signer_digest'] = message[offset:offset + 8]; offset += 8
                elif stype == _V2_SIGNER_CERTIFICATE:
                    _, end = v2enc.decode_certificate_v1(message, offset)
                    out['signer_cert'] = message[offset:end]; offset = end
                else:
                    raise ValueError(f'unsupported signer_info type {stype}')
            elif ftype == _V2_HEADER_GENERATION_TIME:
                out['generation_time_us'] = int.from_bytes(message[offset:offset + 8], 'big'); offset += 8
            elif ftype == _V2_HEADER_EXPIRATION:
                offset += 4
            elif ftype == _V2_HEADER_GENERATION_LOCATION:
                lat = int.from_bytes(message[offset:offset + 4], 'big', signed=True)
                lon = int.from_bytes(message[offset + 4:offset + 8], 'big', signed=True)
                elev = _elevation_from_u16(int.from_bytes(message[offset + 8:offset + 10], 'big'))
                out['generation_location'] = (lat, lon, elev); offset += 10
            elif ftype == _V2_HEADER_ITS_AID:
                out['psid'], offset = v2enc.decode_length(message, offset)
            elif ftype == _V2_HEADER_ENCRYPTION_PARAMETERS:
                if message[offset] != _V2_AES128_CCM:
                    raise ValueError(f'unsupported symmetric algorithm {message[offset]}')
                out['nonce'] = message[offset + 1:offset + 13]; offset += 13
            elif ftype == _V2_HEADER_RECIPIENT_INFO:
                list_len, offset = v2enc.decode_length(message, offset)
                list_end = offset + list_len
                while offset < list_end:
                    cert_id = message[offset:offset + 8]; offset += 8
                    if message[offset] != _V2_ECIES_NISTP256:
                        raise ValueError(f'unsupported recipient pk algorithm {message[offset]}')
                    point_type = message[offset + 1]
                    if point_type not in (2, 3):
                        raise ValueError(f'unsupported ECIES ephemeral point type {point_type}')
                    v = bytes([point_type]) + message[offset + 2:offset + 34]
                    c = message[offset + 34:offset + 50]
                    t = message[offset + 50:offset + 66]
                    out['recipients'].append({'cert_id': cert_id, 'v': v, 'c': c, 't': t})
                    offset += 66
                if offset != list_end:
                    raise ValueError('recipient_info list length mismatch')
            else:
                raise ValueError(f'unsupported header field type {ftype}')
        if offset != header_end:
            raise ValueError('header field list length mismatch')

        out['payload_start'] = offset
        out['payload_type'] = message[offset]; offset += 1
        payload_len, offset = v2enc.decode_length(message, offset)
        out['payload'] = message[offset:offset + payload_len]; offset += payload_len
        if len(out['payload']) != payload_len:
            raise ValueError('truncated payload')
        trailer_len, trailer_start = v2enc.decode_length(message, offset)
        if trailer_start + trailer_len != len(message):
            raise ValueError('trailer length does not match the message size')
        out['trailer'] = message[trailer_start:]
        out['trailer_start'] = trailer_start
        return out
    except IndexError:
        raise ValueError('truncated SecuredMessage') from None


def _v2_verify(message: bytes, signer_pub_key, signer_cert_encoded: Optional[bytes],
               external_payload_hash: Optional[bytes] = None) -> dict:
    fail = lambda msg: {'valid': False, 'format': 'v2', 'error': msg}
    try:
        msg = v2_parse(message)
    except ValueError as e:
        return fail(f'malformed SecuredMessage: {e}')

    if msg['payload_type'] not in (_V2_PAYLOAD_SIGNED, _V2_PAYLOAD_SIGNED_EXTERNAL,
                                   _V2_PAYLOAD_SIGNED_AND_ENCRYPTED):
        return fail(f"unsigned payload type {msg['payload_type']}")
    trailer = msg['trailer']
    if (len(trailer) != _V2_SIGNATURE_TRAILER_SIZE or trailer[0] != _V2_TRAILER_SIGNATURE
            or trailer[1] != _V2_ECDSA_NISTP256_WITH_SHA256 or trailer[2] != _V2_ECC_X_COORDINATE_ONLY):
        return fail('unsupported or malformed signature trailer')

    if msg['signer_digest'] is not None:
        if signer_cert_encoded is None:
            return fail('message is signed with a certificate digest; the signer certificate is required')
        if v2enc.hash_certificate_v1(signer_cert_encoded) != msg['signer_digest']:
            return fail('signer digest does not match the AT certificate')
        signer_cert = signer_cert_encoded
        signer_info = {'type': 'digest', 'hash': msg['signer_digest'].hex()}
    elif msg['signer_cert'] is not None:
        signer_cert = msg['signer_cert']
        if signer_cert_encoded is not None and signer_cert != signer_cert_encoded:
            return fail('embedded signer certificate differs from --at-cert')
        signer_info = {'type': 'certificate', 'cert_len': len(signer_cert)}
    else:
        return fail('missing signer_info header field')

    if signer_pub_key is None:
        cert, _ = v2enc.decode_certificate_v1(signer_cert)
        vk = cert.tbs.verify_key_indicator
        signer_pub_key = load_public_key_from_compressed(vk.point.curve, vk.point.compressed)

    signing_input = message[:msg['trailer_start'] + 1]
    payload = msg['payload']
    if msg['payload_type'] == _V2_PAYLOAD_SIGNED_EXTERNAL:
        # clause 5.2: no payload data is transmitted; the external data is part of the
        # signature "at the position where a non-external payload would be"
        if msg['payload']:
            return fail('signed_external payload must not carry data (TS 103 097 V1.2.1 clause 5.2)')
        if external_payload_hash is None:
            return fail('signed_external message: the external payload hash is required for verification')
        start = msg['payload_start']
        # wire: ... | type 0x03 | length 0x00 | trailer length | trailer type | ...
        signing_input = (message[:start] + bytes([_V2_PAYLOAD_SIGNED_EXTERNAL])
                         + v2enc.encode_length(len(external_payload_hash)) + external_payload_hash
                         + message[start + 2:msg['trailer_start'] + 1])
        payload = external_payload_hash
    r, s = trailer[3:35], trailer[35:67]
    return {
        'valid': ecdsa_verify(signer_pub_key, signing_input, r, s, PublicKeyAlgorithm.ECDSA_NIST_P256),
        'format': 'v2',
        'psid': msg['psid'],
        'generation_time_us': msg['generation_time_us'],
        'generation_location': msg['generation_location'],
        'signer': signer_info,
        'payload': payload,
    }


# ── Public API ───────────────────────────────────────────────────────────────

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
    Create a signed message: EtsiTs103097Data-Signed (v3 certificate) or a
    v2 SecuredMessage (v2 certificate).

    Args:
        payload: The plaintext data to sign.
        psid: ITS-AID for this message type.
        signer_priv_key: ECDSA private key of the signer (AT or EC).
        signer_cert_encoded: Encoded signer certificate (selects the format).
        algorithm: must be ECDSA NIST P-256.
        use_digest: If True, signer = certificate digest; else the full certificate.
        generation_time_us: Time64 microseconds since 2004-01-01. Defaults to now.
        generation_location: Optional (lat, lon, elev): 1/10 micro-degree, decimeters.
        expiry_time_us: Optional expiry Time64.
    """
    _require_p256(algorithm)
    gen_time = generation_time_us or now_its_time64()

    if cert_format(signer_cert_encoded) == 'v2':
        if int(psid) not in _V2_PROFILE_PSIDS:
            # clause 7.3 generic profile: certificate signer, generation_location present
            if generation_location is None:
                raise ValueError("v2 generic signed messages need generation_location "
                                 "(TS 103 097 V1.2.1 clause 7.3)")
            use_digest = False
        prefix = _v2_signing_prefix(signer_cert_encoded, use_digest, psid, gen_time,
                                    generation_location, expiry_time_us, _V2_PAYLOAD_SIGNED, payload)
        return _v2_sign(prefix, signer_priv_key)

    tbs = {
        'payload': {'data': {'protocolVersion': 3, 'content': ('unsecuredData', payload)}},
        'headerInfo': _v3_header_info(psid, gen_time, generation_location, expiry_time_us),
    }
    return _v3_sign(tbs, signer_priv_key, signer_cert_encoded, use_digest)


def sign_data_external_payload(payload_hash: bytes,
                                psid: int,
                                signer_priv_key,
                                signer_cert_encoded: bytes,
                                algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
                                use_digest: bool = True,
                                generation_time_us: Optional[int] = None,
                                generation_location: Optional[tuple] = None) -> bytes:
    """
    Create EtsiTs103097Data-SignedExternalPayload (v3: extDataHash with the
    SHA-256 of the external payload) or a v2 Signed_External SecuredMessage.
    Per FR-SN-07.

    v2 (TS 103 097 V1.2.1): no payload data is transmitted (clause 5.2); the 32-byte
    hash given here is the external data, included in the signature at the payload
    position. Verification needs it (verify_signed_data(external_payload_hash=...)).
    The generic profile applies (clause 7.3): certificate signer, generation_location
    required, CAM/DENM ITS-AIDs rejected. vanetza's v2 verifier accepts only payload
    type signed and reports these messages as Unsigned_Message.
    """
    _require_p256(algorithm)
    if len(payload_hash) != 32:
        raise ValueError("external payload hash must be a 32-byte SHA-256 digest")
    gen_time = generation_time_us or now_its_time64()

    if cert_format(signer_cert_encoded) == 'v2':
        _v2_generic_profile(psid, generation_location, 'signed_external payload')
        fields = _v2_header_fields(signer_cert_encoded, False, psid, gen_time,
                                   generation_location, None)
        signing_prefix = _v2_message_prefix(fields, _V2_PAYLOAD_SIGNED_EXTERNAL, payload_hash)
        wire_prefix = _v2_message_prefix(fields, _V2_PAYLOAD_SIGNED_EXTERNAL, b'')
        signed = _v2_sign(signing_prefix, signer_priv_key)
        return wire_prefix + signed[len(signing_prefix):]

    tbs = {
        'payload': {'extDataHash': ('sha256HashedData', payload_hash)},
        'headerInfo': _v3_header_info(psid, gen_time, None, None),
    }
    return _v3_sign(tbs, signer_priv_key, signer_cert_encoded, use_digest)


# ── CAM signing (profile 7.1.1) ──────────────────────────────────────────────

def sign_cam(cam_payload: bytes,
             at_priv_key,
             at_cert_encoded: bytes,
             algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
             use_digest: bool = True,
             include_full_cert_now: bool = False) -> bytes:
    """
    Sign a CAM (TS 103 097 v1.3.1 clause 7.1.1 / v1.2.1 clause 7.1).

    signer: digest by default; the full certificate is included once per second
            or on request (use_digest=False or include_full_cert_now=True).
    generationTime: always present. generationLocation: absent.
    """
    return sign_data(
        payload=cam_payload,
        psid=int(ItsAid.CAM),
        signer_priv_key=at_priv_key,
        signer_cert_encoded=at_cert_encoded,
        algorithm=algorithm,
        use_digest=use_digest and not include_full_cert_now,
    )


# ── DENM signing (profile 7.1.2) ─────────────────────────────────────────────

def sign_denm(denm_payload: bytes,
              at_priv_key,
              at_cert_encoded: bytes,
              generation_location: tuple,
              algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256) -> bytes:
    """
    Sign a DENM (TS 103 097 v1.3.1 clause 7.1.2 / v1.2.1 clause 7.1).

    signer: certificate (full AT always). generationLocation: always present.
    """
    return sign_data(
        payload=denm_payload,
        psid=int(ItsAid.DENM),
        signer_priv_key=at_priv_key,
        signer_cert_encoded=at_cert_encoded,
        algorithm=algorithm,
        use_digest=False,
        generation_location=generation_location,
    )


# ── Verification ─────────────────────────────────────────────────────────────

def verify_signed_data(signed_data_bytes: bytes,
                       signer_pub_key=None,
                       algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
                       signer_cert_encoded: Optional[bytes] = None,
                       external_payload_hash: Optional[bytes] = None) -> dict:
    """
    Verify a signed message (v3 EtsiTs103097Data or v2 SecuredMessage).

    external_payload_hash: for external-payload messages, the same 32-byte value
    that was passed to sign_data_external_payload(). Required for v2 signed_external
    (nothing is transmitted); for v3 optional and, if given, it must equal extDataHash.

    signer_cert_encoded is required for digest-signed messages, because the
    v3 signing input and the digest check both need the full certificate. When
    signer_pub_key is None it is taken from the signer certificate.

    Returns dict with 'valid' bool, 'format' ('v2'/'v3') and the parsed fields
    (psid, generation_time_us, generation_location, signer, payload) or 'error'.
    Only the message signature is checked here, not the certificate chain.
    """
    try:
        _require_p256(algorithm)
        fmt = message_format(signed_data_bytes)
    except ValueError as e:
        return {'valid': False, 'error': str(e)}
    if fmt == 'v2':
        return _v2_verify(signed_data_bytes, signer_pub_key, signer_cert_encoded, external_payload_hash)
    result = _v3_verify(signed_data_bytes, signer_pub_key, signer_cert_encoded)
    if external_payload_hash is not None and result.get('valid') and result.get('payload') != external_payload_hash:
        return {'valid': False, 'format': 'v3', 'error': 'external payload hash does not match extDataHash'}
    return result
