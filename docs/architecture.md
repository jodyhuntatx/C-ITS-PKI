# C-ITS PKI - System Architecture

## Overview

This repository implements a complete ETSI C-ITS Public Key Infrastructure in Python, supporting two certificate encoding formats:

- **Vanetza-compatible binary format** (default) — ETSI TS 103 097 V1.2.1 (2015), compatible with the vanetza V2X simulator's `security/v2` C++ layer
- **COER format** — ETSI TS 103 097 V2.2.1 (2021), IEEE Std 1609.2-2022/2025

Both formats share the same PKI hierarchy, key material, and CLI interface. The encoding format is chosen at PKI initialisation time and recorded in `pki_meta.json`; all subsequent commands (enrol, issue-at, butterfly-at, info, verify-cert) auto-detect the format from that file.

The implementation covers the full certificate lifecycle: Root CA initialisation through Authorization Ticket (AT) issuance (both standard and Butterfly Key Expansion batch), V2X message signing, encryption, and chain verification.

---

## Standards Alignment

| Standard | Scope in This Implementation |
|---|---|
| ETSI TS 103 097 V1.2.1 | Default certificate encoding; vanetza-compatible binary format; profiles 7.1–7.6 |
| ETSI TS 103 097 V2.2.1 | Alternative COER encoding; certificate profiles 9.1–9.6; message security headers |
| IEEE Std 1609.2-2022/2025 | COER encoding, ECDSA signing, ECIES encryption, AES-128-CCM |
| IEEE 1609.2a | Butterfly Key Expansion (BKE) for AT batch provisioning |
| ETSI TS 102 941 | Trust and privacy management; BKE protocol reference |
| ETSI TS 102 965 | ITS-AID registry (CAM=36, DENM=37, CTL=617, CRL=622, CERT_REQUEST=623) |
| ITU-T X.696 | Canonical Octet Encoding Rules (COER) — V2.2.1 format only |

---

## PKI Hierarchy

```
                    +-----------+
                    |  Root CA  |  self-signed, trust anchor
                    | (profile  |  appPerms: CRL + CTL
                    |  7.1/9.1) |  certIssuePerms: all
                    +-----+-----+
               +----------+-----------+
               v                      v
        +-----------+          +-----------+
        |    EA     |          |    AA     |
        | Enrolment |          |Authoriz'n |
        | Authority |          | Authority |
        | (profile  |          | (profile  |
        |  7.2/9.2) |          |  7.3/9.3) |
        +-----+-----+          +-----+-----+
               |                      |
               v                      v
        +-----------+          +-----------+
        |    EC     |          | AT/BKE AT |
        | Enrolment |          |Authoriz'n |
        | Credential|          |  Ticket   |
        | (profile  |          | (profile  |
        |  7.5/9.5) |          |  7.6/9.6) |
        +-----------+          +-----------+

        +-----------+
        |    TLM    |  self-signed (separate trust root)
        | Trust List|  appPerms: CTL only
        |  Manager  |
        | (profile  |
        |  7.4/9.4) |
        +-----------+
```

The EA and AA are independent subordinate CAs. The EA knows the vehicle's real identity (via the EC) but never issues ATs. The AA issues ATs but never learns the vehicle's real identity — it receives only a caterpillar public key. No single entity holds both pieces of information simultaneously.

---

## Module Structure

```
C-ITS-PKI/
├── src/
│   ├── types.py          Data structure definitions (EtsiVersion, Certificate, ...)
│   ├── coer.py           COER encoding primitives
│   ├── encoding.py       COER certificate encoder/decoder (V2.2.1)
│   ├── v1_encoding.py    Vanetza binary encoder/decoder (V1.2.1)
│   ├── crypto.py         Cryptographic operations + BKE
│   ├── certificates.py   Certificate issuance (all profiles, both formats, BKE batch)
│   ├── pki.py            PKI hierarchy manager
│   ├── signing.py        V2X message signing and verification
│   ├── encryption.py     ECIES + AES-128-CCM
│   └── verification.py   Certificate chain and profile verification
├── cli.py                Command-line interface
└── tests/                Shell-based test suite (test_01 - test_09)
```

---

## Module Descriptions

### `src/types.py`

Defines all ASN.1-derived Python dataclasses and enumerations:

- **`EtsiVersion`** — `V1_2_1 = 1` (vanetza binary, default), `V2_2_1 = 2` (COER). Controls the encoding format selected throughout the issuance pipeline.
- **`ItsAid`** — ITS-AID values: `CAM=36`, `DENM=37`, `CTL=617`, `CRL=622`, `CERT_REQUEST=623`, `MDM=637`
- **`PublicKeyAlgorithm`** — `ECDSA_NIST_P256`, `ECDSA_NIST_P384`, `ECIES_NIST_P256`, `ECIES_NIST_P384`
- **`CertIdChoice`** — `LINKAGE_DATA`, `NAME`, `BINARY_ID`, `NONE` (pseudonymous ATs use `NONE`)
- **`IssuerChoice`** — `SHA256_AND_DIGEST`, `SHA384_AND_DIGEST`, `SELF`
- **`DurationChoice`** — `MICROSECONDS` through `YEARS`
- **`Certificate`**, **`ToBeSignedCertificate`**, **`EcdsaSignature`**, **`EccPoint`**, **`PsidSsp`**, **`PsidGroupPermissions`**, **`ValidityPeriod`**, **`GeographicRegion`**
- ITS time conversion: `unix_to_its_time32()`, `its_time32_to_unix()`, `now_its_time64()` (epoch 2004-01-01T00:00:00Z)

### `src/coer.py`

Low-level COER (ITU-T X.696) encoding and decoding primitives:

- Integer encoders: `encode_uint8()`, `encode_uint16()`, `encode_uint32()`, `encode_uint64()`
- Variable-length: `encode_length()`, `encode_octet_string()`
- CHOICE encoding: `encode_choice()`, `encode_enumerated()`
- Used exclusively by `encoding.py` and `signing.py`

### `src/encoding.py`

Certificate-level COER serialisation and deserialisation for the **V2.2.1 format**:

- **`encode_certificate(cert, version)`** — full `EtsiTs103097Certificate` to COER bytes
- **`encode_tbs_certificate(tbs, version)`** — `ToBeSignedCertificate` to COER bytes. The `version` parameter selects a 1-byte presence bitmap (V1.2.1) or a 2-byte presence bitmap (V2.2.1). Note: the 1-byte bitmap path in this module is for the IEEE 1609.2-2016 field layout; the full vanetza wire format is handled by `v1_encoding.py`.
- **`decode_certificate(data, version)`** — COER bytes to `(Certificate, bytes_consumed)`
- Handles all CHOICE alternatives for `CertificateId`, `IssuerIdentifier`, `GeographicRegion`, `ValidityPeriod`, and `PublicVerificationKey`/`PublicEncryptionKey`

### `src/v1_encoding.py`

Complete vanetza-compatible binary serialiser and deserialiser for the **V1.2.1 format**. Implements the wire format used by `vanetza/security/v2/certificate.cpp` and related modules.

**Key constants (matching vanetza enums):**
- `V1SubjectType` — `ROOT_CA=4`, `ENROLLMENT_AUTHORITY=3`, `AUTHORIZATION_AUTHORITY=2`, `ENROLLMENT_CREDENTIAL=0`, `AUTHORIZATION_TICKET=1`
- `V1SignerInfoType` — `SELF=0`, `CERTIFICATE_DIGEST_WITH_SHA256=1`
- `V1EccPointType` — `X_COORDINATE_ONLY=0`, `COMPRESSED_LSB_Y_0=2`, `COMPRESSED_LSB_Y_1=3`
- `V1PublicKeyAlgorithm` — `ECDSA_NISTP256_WITH_SHA256=0`, `ECIES_NISTP256=1`
- `V1SubjectAttributeType` — `VERIFICATION_KEY=0`, `ENCRYPTION_KEY=1`, `ASSURANCE_LEVEL=2`, `ITS_AID_LIST=32`, `ITS_AID_SSP_LIST=33`
- `V1ValidityRestrictionType` — `TIME_END=0`, `TIME_START_AND_END=1`, `TIME_START_AND_DURATION=2`, `REGION=3`

**Length coding (`encode_length` / `decode_length`):**
Vanetza uses a custom variable-length encoding (not COER). Leading 1-bits in the first byte signal additional byte count:
- `0xxxxxxx` — 1 byte, values 0–127
- `10xxxxxx xxxxxxxx` — 2 bytes, values 0–16383
- `110xxxxx xxxxxxxx xxxxxxxx` — 3 bytes, values 0–2097151

**IntX:** Same encoding as `encode_length`, used for ITS-AID values in `ITS_AID_List` and `ITS_AID_SSP_List` attributes.

**Duration encoding:** 2-byte word, bits 15–13 = units (0=Sec, 1=Min, 2=Hours, 3=60hBlocks, 4=Years), bits 12–0 = value.

**Certificate wire format:**
```
[0x02]                             version (always 2)
[SignerInfo]                       type(1) + optional 8-byte HashedId8 digest
[SubjectInfo]                      subject_type(1) + vanetza_len(name) + name
[vanetza_len(attrs_size)]          total byte size of attribute list
  [0x00][algo=0x00][EccType][x:32] Verification_Key
  [0x01][algo=0x01][sym=0x00][EccType][x:32]  Encryption_Key (optional)
  [0x20][vanetza_len(aids)][IntX aid1]...  ITS_AID_List
[vanetza_len(vr_size)]             total byte size of validity restriction list
  [0x02][start:4][dur:2]           Time_Start_And_Duration
  [0x03][0x04][dict:1][id:2][IntX(0)]  Region IdentifiedRegion (optional)
[0x00][0x00][r:32][s:32]           Signature (algo + X_COORD_ONLY + r + s)
```

**Signing input** (`compute_signing_input_v1`) — everything except the trailing Signature field, matching vanetza's `convert_for_signing()`.

**Key functions:**
- `build_and_sign_v1(tbs, issuer, sign_priv_key, algorithm, subject_type, psids)` — builds and signs a complete vanetza certificate; populates `cert.encoded` and `cert.tbs_encoded`
- `decode_certificate_v1(data, offset)` — full decoder; returns `(Certificate, new_offset)`
- `hash_certificate_v1(cert_encoded)` — `SHA-256(cert)[−8:]`; matches vanetza's `calculate_hash()`

### `src/crypto.py`

All cryptographic primitives plus Butterfly Key Expansion:

**Key generation:**
- `generate_keypair(algorithm)` — P-256 or P-384 key pair
- `serialize_private_key(priv)` / `deserialize_private_key(pem)` — PEM (PKCS#8) round-trip

**Hashing:**
- `sha256(data)`, `sha384(data)`
- `hash_certificate(cert_encoded, algorithm)` — HashedId8 (last 8 bytes of SHA-256 or SHA-384); used for the COER/V2.2.1 format
- `hash_data(data, algorithm)`

**ECDSA:**
- `ecdsa_sign(private_key, data, algorithm)` — returns `(r_bytes, s_bytes)`; `r` is the x-coordinate of the ephemeral point, directly usable as the vanetza `X_Coordinate_Only` EccPoint
- `ecdsa_verify(public_key, data, r_bytes, s_bytes, algorithm)` — returns `bool`

**KDF2 and ECIES (IEEE 1609.2 §5.3.5):**
- `kdf2_sha256(shared_secret, param)` — 48 bytes (ke ‖ km)
- `ecies_encrypt(recipient_pub_key, plaintext_key)` — returns `{'v', 'c', 't'}`
- `ecies_decrypt(recipient_priv_key, v, c, t)` — returns plaintext key

**AES-128-CCM (IEEE 1609.2 §5.3.8):**
- `aes_ccm_encrypt(key, nonce, plaintext, aad)` — ciphertext ‖ tag
- `aes_ccm_decrypt(key, nonce, ciphertext_with_tag, aad)` — plaintext

**Butterfly Key Expansion (IEEE 1609.2a §6.4.3.7):**
- `bke_expand_private_key(caterpillar_priv, expansion_value)` — vehicle side: `sᵢ = (f + H(Cf‖eᵢ)) mod n`
- `bke_expand_public_key(caterpillar_pub, expansion_value)` — AA side: `Sᵢ = Cf + H(Cf‖eᵢ)·G` via `tinyec` EC point addition

### `src/certificates.py`

Certificate issuance for all profiles in both encoding formats:

| Function | V1.2.1 Profile | V2.2.1 Profile | Subject Type |
|---|---|---|---|
| `issue_root_ca_certificate()` | 7.1 | 9.1 | `ROOT_CA` |
| `issue_ea_certificate()` | 7.2 | 9.2 | `ENROLLMENT_AUTHORITY` |
| `issue_aa_certificate()` | 7.3 | 9.3 | `AUTHORIZATION_AUTHORITY` |
| `issue_tlm_certificate()` | 7.4 | 9.4 | `ROOT_CA` |
| `issue_enrolment_credential()` | 7.5 | 9.5 | `ENROLLMENT_CREDENTIAL` |
| `issue_authorization_ticket()` | 7.6 | 9.6 | `AUTHORIZATION_TICKET` |
| `issue_butterfly_authorization_tickets()` | 7.6 (BKE) | 9.6 (BKE) | `AUTHORIZATION_TICKET` |

All issuance functions default to `version=EtsiVersion.V1_2_1`.

The internal `_build_and_sign()` helper dispatches based on `version`:
- `V1_2_1` → `build_and_sign_v1()` in `v1_encoding.py`
- `V2_2_1` → encodes TBS with 2-byte bitmap, signs, then calls `encode_certificate()` from `encoding.py`

The `_hash_cert()` helper selects the correct hash function per format:
- `V1_2_1` → `hash_certificate_v1()` (always SHA-256, last 8 bytes)
- `V2_2_1` → `hash_certificate()` (SHA-256 or SHA-384 per algorithm)

### `src/pki.py`

`CITSPKI` — the top-level PKI manager class. Defaults to `version=EtsiVersion.V1_2_1`.

- **`initialise()`** — creates Root CA → TLM → EA → AA in one call; returns encoded bytes for each
- **`enrol_its_station(name)`** — generates a fresh EC key pair, issues an EC signed by the EA
- **`issue_authorization_ticket(app_psids, validity_hours)`** — generates a fresh AT key pair, issues an AT signed by the AA
- **`issue_butterfly_authorization_tickets(caterpillar_sign_priv, expansion_values, ...)`** — AA side issues N AT certificates; vehicle side recovers N AT private keys via `bke_expand_private_key()`; returns list of dicts with `at`, `certificate`, `sign_priv_key`, `sign_pub_key`, `expansion_value`, `priv_key_pem`
- **`save(output_dir)`** — persists all CA certificates and private keys to disk; writes `pki_meta.json` with `etsi_version` field (1 or 2)
- **`get_cert_chain(entity_name)`** — returns the certificate chain (leaf → Root CA) for EA or AA

### `src/signing.py`

Produces and verifies `EtsiTs103097Data-Signed` structures (V2.2.1 COER format):

**Core:**
- `sign_data(payload, psid, signer_priv_key, signer_cert_encoded, ...)` — generic signed message builder
- `verify_signed_data(signed_data_bytes, signer_pub_key, algorithm)` — returns dict with `valid`, `psid`, `generation_time_us`, `generation_location`, `signer`, `payload`

**Message profiles:**
- `sign_cam(cam_payload, at_priv_key, at_cert_encoded, ...)` — signer=digest by default
- `sign_denm(denm_payload, at_priv_key, at_cert_encoded, generation_location, ...)` — signer=full certificate, location always present

### `src/encryption.py`

`EtsiTs103097Data-Encrypted` per IEEE 1609.2 §5.3.8:

- **`encrypt_data(plaintext, recipient_cert_encoded, recipient_enc_pub_key, algorithm)`** — ECIES key encapsulation + AES-128-CCM content encryption
- **`decrypt_data(encrypted_data_bytes, recipient_enc_priv_key, my_cert_encoded, algorithm)`** — ECIES key recovery + AES-128-CCM decryption

### `src/verification.py`

Certificate chain and profile validation per IEEE 1609.2 clause 5.1:

- **`verify_certificate_signature(cert, issuer_cert)`** — ECDSA verification; self-signed check for Root CA and TLM
- **`verify_certificate_validity_period(cert, at_unix_time)`** — checks `[start, start+duration)` interval
- **`verify_issuer_digest(cert, issuer_cert, algorithm)`** — HashedId8 comparison
- **`verify_permissions_constraints(cert)`** — at least one of `appPermissions` or `certIssuePermissions` must be present
- **`verify_craca_and_crl_series(cert)`** — `cracaId=000000H`, `crlSeries=0` (V2.2.1 only; not present in vanetza format)
- **`verify_at_profile(cert)`** — AT-specific: `id=none`, `certIssuePermissions` absent, `appPermissions` present
- **`verify_region_constraint(cert, allow_eu27)`** — EU-27 region ID 65535 accepted
- **`verify_certificate_chain(leaf_cert, intermediate_certs, root_cert, algorithm)`** — full chain validation; returns `{'valid', 'errors', 'details'}`
- **`compute_hashed_id8(cert_encoded, algorithm)`** — HashedId8 for revocation checks
- **`check_revocation_by_hash(cert_encoded, revoked_hashes, algorithm)`** — hash-based revocation lookup

---

## CLI Command Summary

| Command | Key flags | Purpose |
|---|---|---|
| `init` | `--output`, `--algo`, `--region`, `--etsi-version` | Initialise full PKI hierarchy |
| `enrol` | `--output`, `--name`, `--validity` | Issue Enrolment Credential |
| `issue-at` | `--output`, `--psid`, `--validity` | Issue Authorization Ticket |
| `butterfly-at` | `--output`, `--count`, `--psid`, `--validity` | Issue BKE batch of ATs |
| `sign-cam` | `--at-key`, `--at-cert`, `--payload`, `--full-cert` | Sign a CAM |
| `sign-denm` | `--at-key`, `--at-cert`, `--payload`, `--lat`, `--lon` | Sign a DENM |
| `verify-sig` | `--signed`, `--at-cert`, `--aa`, `--root` | Verify a signed message |
| `encrypt` | `--enc-cert`, `--enc-key`, `--payload` | Encrypt a message |
| `decrypt` | `--enc-cert`, `--enc-key`, `--input` | Decrypt a message |
| `verify-cert` | `--cert`, `--issuer`, `--etsi-version` | Verify a certificate |
| `info` | `--cert`, `--etsi-version` | Display certificate details |

For `info` and `verify-cert`, `--etsi-version` is optional. The format is auto-detected by searching the certificate's directory tree for `pki_meta.json`; if not found, `v2` (vanetza) is assumed.

---

## Butterfly Key Expansion - Data Flow

BKE is a privacy-preserving protocol for AT batch provisioning (IEEE 1609.2a §6.4.3.7). The vehicle and AA never share private keys; the AA cannot link the issued ATs to each other or to the vehicle's real identity.

```
Vehicle                                   AA
------------------------------------------------------------------
1. Generate caterpillar key pair (f, Cf)
2. Generate N expansion values {ei}
3. Send (Cf, {ei}) in AT batch request
                                          4. For each ei:
                                               Si = Cf + H(Cf||ei)*G
                                               Issue AT cert for Si
                                          5. Return {ATi}
6. For each ATi:
     si = (f + H(Cf||ei)) mod n    <- recover AT private key
     Verify: si*G == Si            <- sanity check
7. Sign V2X messages with ATi / si
```

**Key privacy properties:**
- The AA never sees any AT private key
- The AA cannot link the N certificates to each other (without the caterpillar key)
- The AA cannot link a batch to the vehicle's Enrolment Credential
- A new caterpillar key should be generated for each batch request

**Stored artefacts per BKE batch (minimum required for operation):**
- Caterpillar private key `f` — allows re-derivation of any AT private key
- Expansion values `{eᵢ}` — needed alongside `f` to re-derive `sᵢ`; also links expansion to certificate
- AT certificates `{ATᵢ}` — presented when signing V2X messages

---

## Certificate Encoding

### Vanetza binary format (V1.2.1, default)

The vanetza wire format is a compact binary serialisation defined in ETSI TS 103 097 V1.2.1, section 6.1, and implemented in the vanetza simulator's `vanetza/security/v2/` C++ module. It does **not** use COER; instead it uses a custom variable-length coding scheme and a subject-centric structure with no IEEE 1609.2-2022 constructs.

Key properties:
- Certificate version byte = `0x02`
- `HashedId8` = SHA-256 of full encoded certificate, last 8 bytes
- EC public keys stored as compressed points with a 1-byte type prefix (EccPointType)
- PSID/ITS-AIDs encoded as IntX (same algorithm as vanetza length coding)
- Duration as 2-byte word: units in bits 15–13, value in bits 12–0
- Signing input = all bytes except the trailing Signature field; matches vanetza's `convert_for_signing()`
- ECDSA P-256 only (vanetza `security/v2` limitation)

### COER format (V2.2.1)

Canonical Octet Encoding Rules (ITU-T X.696) as `EtsiTs103097Certificate`:
- Certificate version byte = `0x03`
- `HashedId8` = last 8 bytes of SHA-256 (P-256) or SHA-384 (P-384) of full COER-encoded certificate
- EC public keys stored as compressed points (33 bytes for P-256, 49 bytes for P-384)
- `cracaId` always `000000H` (3 bytes), `crlSeries` always `0`
- PSID variable-length encoding: 1 byte for `< 0x80`, 2 bytes for `< 0x4000`, 3 or 4 bytes otherwise
- `Time32` = seconds since 2004-01-01T00:00:00Z; `Time64` = microseconds since same epoch

---

## Message Signing - Structure

```
EtsiTs103097Data                    (Ieee1609Dot2Data wrapper, version=3)
+-- signedData  [CHOICE 1]
    +-- hashId                      (sha256=0 or sha384=1)
    +-- tbsData  (ToBeSignedData)   <- what is actually signed
    |   +-- payload
    |   |   +-- data  [CHOICE 0]
    |   |       +-- EtsiTs103097Data-Unsecured
    |   |           +-- unsecuredData: <raw CAM/DENM bytes>
    |   +-- headerInfo
    |       +-- psid                (ITS-AID, variable-length)
    |       +-- generationTime      (Time64, always present)
    |       +-- generationLocation  (ThreeDLocation, present for DENM)
    +-- signer  (SignerIdentifier)
    |   +-- digest  [CHOICE 0]      HashedId8 of AT cert (CAM default)
    +-- signature  (EcdsaP256Signature or EcdsaP384Signature)
        +-- r                       (32 or 48 bytes)
        +-- s                       (32 or 48 bytes)
```

---

## Encryption - Structure

```
EtsiTs103097Data-Encrypted
+-- encryptedData
    +-- recipients  [SEQUENCE OF RecipientInfo]
    |   +-- certRecipInfo  [CHOICE 2]
    |       +-- recipientId         HashedId8 of recipient certificate
    |       +-- encKey  (PKRecipientInfo)
    |           +-- eciesNistP256   ECIES-wrapped AES-128 content key
    |               +-- v           ephemeral public key (compressed)
    |               +-- c           encrypted content key (XOR with ke)
    |               +-- t           HMAC-SHA256 authentication tag (16 bytes)
    +-- ciphertext  (SymmetricCiphertext)
        +-- aes128ccm
            +-- nonce               12 random bytes
            +-- ccmCiphertext       AES-128-CCM(content key, nonce, plaintext)
```

ECIES key encapsulation follows IEEE 1609.2 §5.3.5. KDF2 with SHA-256 derives a 48-byte output split into `ke` (encryption, 16 bytes) and `km` (MAC, 32 bytes).

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `cryptography` | latest | ECDSA, ECIES, AES-128-CCM, key serialisation |
| `tinyec` | >= 0.4.0 | EC point addition for BKE public key derivation |

`tinyec` is used exclusively in `bke_expand_public_key()` for the point addition `Cf + h·G`. The `cryptography` library does not expose raw EC point addition, making `tinyec` necessary for the AA-side BKE computation.

---

## Relationship to ETSI CCMS and CAMP SCMS

This implementation targets the **European CCMS** (C-ITS Credential Management System) profile based on ETSI TS 102 940 / 102 941. It is architecturally similar to the North American **CAMP SCMS** but differs in:

| Aspect | This repo (ETSI) | CAMP SCMS |
|---|---|---|
| Pseudonym cert name | Authorization Ticket (AT) | Pseudonym Certificate (PC) |
| Identity cert name | Enrolment Credential (EC) | Enrollment Certificate (EC) |
| Default cert format | Vanetza binary (V1.2.1) | IEEE1609Dot2 ExplicitCertificate |
| Message wrapper | EtsiTs103097Data-Signed | Ieee1609Dot2Data |
| Primary PSID | CAM=36, DENM=37 | BSM=32 |
| Standard reference | ETSI TS 103 097 V1.2.1 / V2.2.1 | IEEE 1609.2-2016 / 1609.2.1 |

## Vanetza Compatibility

Certificates generated in the default V1.2.1 mode have been verified to load and display correctly in vanetza's `certify` tool. The encoding matches vanetza's `vanetza/security/v2/certificate.cpp` serialisation exactly, including:

- The custom length-coding scheme (`vanetza/security/v2/length_coding.hpp`)
- The IntX encoding for ITS-AIDs (`vanetza/security/v2/int_x.hpp`)
- The 2-byte Duration word format (`vanetza/security/v2/validity_restriction.hpp`)
- The IdentifiedRegion structure with `RegionDictionary`, signed `region_identifier`, and IntX `local_region` (`vanetza/security/v2/region.hpp`)
- The signing input format from `convert_for_signing()` in `vanetza/security/v2/certificate.cpp`
- The `HashedId8` calculation from `calculate_hash()` in the same file
