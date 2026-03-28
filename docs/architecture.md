# C-ITS PKI — System Architecture

## Overview

This repository implements a complete ETSI C-ITS Public Key Infrastructure in Python, conforming to ETSI TS 103 097 V2.2.1 and IEEE Std 1609.2-2025. It covers the full certificate lifecycle from Root CA initialisation through Authorization Ticket (AT) issuance (both standard and Butterfly Key Expansion batch), V2X message signing, encryption, and chain verification.

---

## Standards Alignment

| Standard | Scope in This Implementation |
|---|---|
| ETSI TS 103 097 V2.2.1 | Certificate profiles 9.1–9.6, message security headers |
| IEEE Std 1609.2-2025 | COER encoding, ECDSA signing, ECIES encryption, AES-128-CCM |
| IEEE 1609.2a | Butterfly Key Expansion (BKE) for AT batch provisioning |
| ETSI TS 102 941 | Trust and privacy management; BKE protocol reference |
| ETSI TS 102 965 | ITS-AID registry (CAM=36, DENM=37, CTL=617, CRL=622, CERT_REQUEST=623) |
| ITU-T X.696 | Canonical Octet Encoding Rules (COER) |

---

## PKI Hierarchy

```
                    ┌─────────────┐
                    │   Root CA   │  self-signed, trust anchor
                    │  (profile   │  appPerms: CRL + CTL
                    │    9.1)     │  certIssuePerms: all
                    └──────┬──────┘
               ┌───────────┴───────────┐
               ▼                       ▼
        ┌─────────────┐         ┌─────────────┐
        │     EA      │         │     AA      │
        │ Enrolment   │         │Authoriz'n   │
        │ Authority   │         │ Authority   │
        │ (profile    │         │ (profile    │
        │    9.2)     │         │    9.3)     │
        └──────┬──────┘         └──────┬──────┘
               │                       │
               ▼                       ▼
        ┌─────────────┐         ┌─────────────┐
        │     EC      │         │ AT / BKE AT │
        │ Enrolment   │         │Authoriz'n   │
        │ Credential  │         │  Ticket     │
        │ (profile    │         │ (profile    │
        │    9.5)     │         │    9.6)     │
        └─────────────┘         └─────────────┘

        ┌─────────────┐
        │     TLM     │  self-signed (separate trust root)
        │ Trust List  │  appPerms: CTL only
        │  Manager    │
        │ (profile    │
        │    9.4)     │
        └─────────────┘
```

The EA and AA are independent subordinate CAs. The EA knows the vehicle's real identity (via the EC) but never issues ATs. The AA issues ATs but never learns the vehicle's real identity — it receives only a caterpillar public key from the EA's introduction channel. No single entity holds both pieces of information simultaneously.

---

## Module Structure

```
C-ITS-PKI/
├── src/
│   ├── types.py          Data structure definitions
│   ├── coer.py           COER encoding primitives
│   ├── encoding.py       Certificate encoder/decoder
│   ├── crypto.py         Cryptographic operations + BKE
│   ├── certificates.py   Certificate issuance (all profiles + BKE batch)
│   ├── pki.py            PKI hierarchy manager
│   ├── signing.py        V2X message signing and verification
│   ├── encryption.py     ECIES + AES-128-CCM
│   └── verification.py   Certificate chain and profile verification
├── cli.py                Command-line interface
└── tests/                Shell-based test suite (test_01 – test_09)
```

---

## Module Descriptions

### `src/types.py`

Defines all ASN.1-derived Python dataclasses and enumerations:

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

Certificate-level COER serialisation and deserialisation:

- **`encode_certificate(cert)`** — full `EtsiTs103097Certificate` → COER bytes
- **`encode_tbs_certificate(tbs)`** — `ToBeSignedCertificate` → COER bytes (used as signing input)
- **`decode_certificate(data)`** — COER bytes → `(Certificate, bytes_consumed)`
- **`encode_signature(sig)`** / **`decode_signature(data, offset)`** — ECDSA signature round-trip
- Handles all CHOICE alternatives for `CertificateId`, `IssuerIdentifier`, `GeographicRegion`, `ValidityPeriod`, and `PublicVerificationKey`/`PublicEncryptionKey`

### `src/crypto.py`

All cryptographic primitives plus Butterfly Key Expansion:

**Key generation:**
- `generate_keypair(algorithm)` — P-256 or P-384 key pair
- `serialize_private_key(priv)` / `deserialize_private_key(pem)` — PEM (PKCS#8) round-trip

**Hashing:**
- `sha256(data)`, `sha384(data)`
- `hash_certificate(cert_encoded, algorithm)` — HashedId8 (last 8 bytes of hash)
- `hash_data(data, algorithm)`

**ECDSA:**
- `ecdsa_sign(private_key, data, algorithm)` → `(r_bytes, s_bytes)`
- `ecdsa_verify(public_key, data, r_bytes, s_bytes, algorithm)` → `bool`

**KDF2 and ECIES (IEEE 1609.2 §5.3.5):**
- `kdf2_sha256(shared_secret, param)` → 48 bytes (ke ‖ km)
- `ecies_encrypt(recipient_pub_key, plaintext_key)` → `{'v', 'c', 't'}`
- `ecies_decrypt(recipient_priv_key, v, c, t)` → plaintext key

**AES-128-CCM (IEEE 1609.2 §5.3.8):**
- `aes_ccm_encrypt(key, nonce, plaintext, aad)` → ciphertext ‖ tag
- `aes_ccm_decrypt(key, nonce, ciphertext_with_tag, aad)` → plaintext

**Butterfly Key Expansion (IEEE 1609.2a §6.4.3.7):**
- `bke_expand_private_key(caterpillar_priv, expansion_value)` — vehicle side: derives AT private key `sᵢ = (f + H(Cf‖eᵢ)) mod n`
- `bke_expand_public_key(caterpillar_pub, expansion_value)` — AA side: derives AT public key `Sᵢ = Cf + H(Cf‖eᵢ)·G` using EC point addition via `tinyec` (curve name `'secp256r1'` / `'secp384r1'`)

**Curve constants:**
- `_P256_ORDER`, `_P384_ORDER` — group orders for key derivation arithmetic
- `_curve_order(curve)` — helper returning the correct order for a given curve instance

### `src/certificates.py`

Certificate issuance for all ETSI TS 103 097 V2.2.1 profiles:

| Function | Profile | Issuer | Notes |
|---|---|---|---|
| `issue_root_ca_certificate()` | 9.1 | self | id=name, certIssuePerms=all, appPerms=CRL+CTL |
| `issue_ea_certificate()` | 9.2 | Root CA | id=name, encKey present, certIssuePerms=all |
| `issue_aa_certificate()` | 9.3 | Root CA | id=name, encKey present, certIssuePerms=all |
| `issue_tlm_certificate()` | 9.4 | self | id=name, appPerms=CTL only |
| `issue_enrolment_credential()` | 9.5 | EA | id=name, appPerms=CERT_REQUEST |
| `issue_authorization_ticket()` | 9.6 | AA | id=none (pseudonymous), appPerms=CAM+DENM |
| `issue_butterfly_authorization_tickets()` | 9.6 (BKE) | AA | Batch; derives each pubkey via `bke_expand_public_key()` |

All functions encode via `_build_and_sign()` which: encodes the TBS, signs it with ECDSA, assembles the full `Certificate`, and caches both `tbs_encoded` and `encoded`.

### `src/pki.py`

`CITSPKI` — the top-level PKI manager class:

- **`initialise()`** — creates Root CA → TLM → EA → AA in one call; returns COER-encoded bytes for each
- **`enrol_its_station(name)`** — generates a fresh EC key pair, issues an EC signed by the EA
- **`issue_authorization_ticket(app_psids, validity_hours)`** — generates a fresh AT key pair, issues an AT signed by the AA
- **`issue_butterfly_authorization_tickets(caterpillar_sign_priv, expansion_values, ...)`** — AA side issues N AT certificates via `_issue_bke_ats()`; vehicle side recovers N AT private keys via `bke_expand_private_key()`; returns a list of dicts with `at`, `certificate`, `sign_priv_key`, `sign_pub_key`, `expansion_value`, `priv_key_pem`
- **`save(output_dir)`** — persists all CA certificates and private keys to disk
- **`get_cert_chain(entity_name)`** — returns the certificate chain (leaf → Root CA) for EA or AA

### `src/signing.py`

Produces and verifies `EtsiTs103097Data-Signed` structures:

**Core:**
- `sign_data(payload, psid, signer_priv_key, signer_cert_encoded, ...)` — generic signed message builder; handles `HeaderInfo` encoding (PSID, `generationTime`, optional `generationLocation`, optional `expiryTime`), `SignerIdentifier` (digest or full certificate), and ECDSA signature
- `sign_data_external_payload(payload_hash, ...)` — for `EtsiTs103097Data-SignedExternalPayload` (FR-SN-07)
- `verify_signed_data(signed_data_bytes, signer_pub_key, algorithm)` → dict with `valid`, `psid`, `generation_time_us`, `generation_location`, `signer`, `payload`

**Message profiles:**
- `sign_cam(cam_payload, at_priv_key, at_cert_encoded, ...)` — profile 10.1: signer=digest by default; `include_full_cert_now=True` for the once-per-second full certificate rule
- `sign_denm(denm_payload, at_priv_key, at_cert_encoded, generation_location, ...)` — profile 10.2: signer=full certificate, location always present

**Header encoding:**
- `encode_header_info(psid, generation_time_us, generation_location, ...)` — 2-byte presence bitmap + fields
- Variable-length PSID encoding: `_encode_psid(psid)` (1–4 bytes), `_decode_psid(data, offset)`

### `src/encryption.py`

`EtsiTs103097Data-Encrypted` per IEEE 1609.2 §5.3.8:

- **`encrypt_data(plaintext, recipient_cert_encoded, recipient_enc_pub_key, algorithm)`** — generates a random AES-128 content key; encrypts content with AES-128-CCM; wraps the content key with ECIES for the recipient's encryption public key
- **`decrypt_data(encrypted_data_bytes, recipient_enc_priv_key, my_cert_encoded, algorithm)`** — recovers the AES-128 content key via ECIES decryption; decrypts the content

### `src/verification.py`

Certificate chain and profile validation per IEEE 1609.2 clause 5.1:

- **`verify_certificate_signature(cert, issuer_cert)`** — ECDSA signature verification; self-signed check for Root CA and TLM
- **`verify_certificate_validity_period(cert, at_unix_time)`** — checks `[start, start+duration)` interval
- **`verify_issuer_digest(cert, issuer_cert, algorithm)`** — HashedId8 comparison (FR-VF-04)
- **`verify_permissions_constraints(cert)`** — at least one of `appPermissions` or `certIssuePermissions` must be present (FR-CI-09)
- **`verify_craca_and_crl_series(cert)`** — `cracaId=000000H`, `crlSeries=0` (FR-CI-10)
- **`verify_at_profile(cert)`** — AT-specific: `id=none`, `certIssuePermissions` absent, `appPermissions` present
- **`verify_region_constraint(cert, allow_eu27)`** — EU-27 region ID 65535 accepted (FR-VF-06)
- **`verify_certificate_chain(leaf_cert, intermediate_certs, root_cert, algorithm)`** — full chain: root self-sig → intermediates → leaf; returns `{'valid', 'errors', 'details'}`
- **`compute_hashed_id8(cert_encoded, algorithm)`** — HashedId8 for revocation checks
- **`check_revocation_by_hash(cert_encoded, revoked_hashes, algorithm)`** — hash-based revocation lookup (FR-VF-04)

---

## CLI Command Summary

| Command | Key flags | Purpose |
|---|---|---|
| `init` | `--output`, `--algo`, `--region` | Initialise full PKI hierarchy |
| `enrol` | `--output`, `--name`, `--validity` | Issue Enrolment Credential |
| `issue-at` | `--output`, `--psid`, `--validity` | Issue Authorization Ticket |
| `butterfly-at` | `--output`, `--count`, `--psid`, `--validity` | Issue BKE batch of ATs |
| `sign-cam` | `--at-key`, `--at-cert`, `--payload`, `--full-cert` | Sign a CAM |
| `sign-denm` | `--at-key`, `--at-cert`, `--payload`, `--lat`, `--lon` | Sign a DENM |
| `verify-sig` | `--signed`, `--at-cert`, `--aa`, `--root` | Verify a signed message |
| `encrypt` | `--enc-cert`, `--enc-key`, `--payload` | Encrypt a message |
| `decrypt` | `--enc-cert`, `--enc-key`, `--input` | Decrypt a message |
| `verify-cert` | `--cert`, `--issuer`, `--root` | Verify a certificate |
| `info` | `--cert` | Display certificate details |

`verify-cert` automatically detects pseudonymous certificates (`id=none`) and runs AT profile validation in addition to the standard checks.

---

## Butterfly Key Expansion — Data Flow

BKE is a privacy-preserving protocol for AT batch provisioning (IEEE 1609.2a §6.4.3.7). The vehicle and AA never share private keys; the AA cannot link the issued ATs to each other or to the vehicle's real identity.

```
Vehicle                                   AA
────────────────────────────────────────────────────────────────
1. Generate caterpillar key pair (f, Cf)
2. Generate N expansion values {eᵢ}
3. Send (Cf, {eᵢ}) in AT batch request
                                          4. For each eᵢ:
                                               Sᵢ = Cf + H(Cf‖eᵢ)·G
                                               Issue AT cert for Sᵢ
                                          5. Return {ATᵢ}
6. For each ATᵢ:
     sᵢ = (f + H(Cf‖eᵢ)) mod n    ← recover AT private key
     Verify: sᵢ·G == Sᵢ           ← sanity check
7. Sign V2X messages with ATᵢ / sᵢ
```

**Key privacy properties:**
- The AA never sees any AT private key
- The AA cannot link the N certificates to each other (without the caterpillar key)
- The AA cannot link a batch to the vehicle's Enrolment Credential
- A new caterpillar key should be generated for each batch request to prevent the AA from linking batches across provisioning epochs

**Stored artefacts per BKE batch (minimum required for operation):**
- Caterpillar private key `f` — allows re-derivation of any AT private key
- Expansion values `{eᵢ}` — needed alongside `f` to re-derive `sᵢ`; also links expansion to certificate
- AT certificates `{ATᵢ}` — presented when signing V2X messages

---

## Certificate Encoding (COER)

All certificates are encoded in Canonical Octet Encoding Rules (COER, ITU-T X.696) as `EtsiTs103097Certificate`. The encoding is compatible with Vanetza's `load_certificate_from_file()` in its v3 security layer.

Key encoding conventions:
- EC public keys stored as compressed points (33 bytes for P-256, 49 bytes for P-384)
- `HashedId8` = last 8 bytes of SHA-256 or SHA-384 of the full COER-encoded certificate
- `cracaId` always `000000H` (3 bytes), `crlSeries` always `0` (FR-CI-10)
- PSID variable-length encoding: 1 byte for `< 0x80`, 2 bytes for `< 0x4000`, 3 or 4 bytes otherwise
- `Time32` = seconds since 2004-01-01T00:00:00Z; `Time64` = microseconds since same epoch

---

## Message Signing — Structure

```
EtsiTs103097Data                    (Ieee1609Dot2Data wrapper, version=3)
└── signedData  [CHOICE 1]
    ├── hashId                      (sha256=0 or sha384=1)
    ├── tbsData  (ToBeSignedData)   ← what is actually signed
    │   ├── payload
    │   │   └── data  [CHOICE 0]
    │   │       └── EtsiTs103097Data-Unsecured
    │   │           └── unsecuredData: <raw CAM/DENM bytes>
    │   └── headerInfo
    │       ├── psid                (ITS-AID, variable-length)
    │       ├── generationTime      (Time64, always present)
    │       ├── generationLocation  (ThreeDLocation, present for DENM)
    │       └── ...                 (expiryTime, encryptionKey — optional)
    ├── signer  (SignerIdentifier)
    │   ├── digest  [CHOICE 0]      HashedId8 of AT cert (CAM default)
    │   └── certificate  [CHOICE 1] Full AT cert (DENM; CAM once/second)
    └── signature  (EcdsaP256Signature or EcdsaP384Signature)
        ├── r                       (32 or 48 bytes)
        └── s                       (32 or 48 bytes)
```

---

## Encryption — Structure

```
EtsiTs103097Data-Encrypted
└── encryptedData
    ├── recipients  [SEQUENCE OF RecipientInfo]
    │   └── certRecipInfo  [CHOICE 2]
    │       ├── recipientId         HashedId8 of recipient certificate
    │       └── encKey  (PKRecipientInfo)
    │           └── eciesNistP256   ECIES-wrapped AES-128 content key
    │               ├── v           ephemeral public key (compressed)
    │               ├── c           encrypted content key (XOR with ke)
    │               └── t           HMAC-SHA256 authentication tag (16 bytes)
    └── ciphertext  (SymmetricCiphertext)
        └── aes128ccm
            ├── nonce               12 random bytes
            └── ccmCiphertext       AES-128-CCM(content key, nonce, plaintext)
```

ECIES key encapsulation follows IEEE 1609.2 §5.3.5. KDF2 with SHA-256 derives a 48-byte output split into `ke` (encryption, 16 bytes) and `km` (MAC, 32 bytes). The content key is XOR'd with `ke`; the authentication tag is `HMAC-SHA256(c, km)` truncated to 16 bytes.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `cryptography` | latest | ECDSA, ECIES, AES-128-CCM, key serialisation |
| `tinyec` | ≥ 0.4.0 | EC point addition for BKE public key derivation (`secp256r1`, `secp384r1`) |

`tinyec` is used exclusively in `bke_expand_public_key()` for the point addition `Cf + h·G`. The `cryptography` library does not expose raw EC point addition, making `tinyec` necessary for the AA-side BKE computation.

---

## Relationship to ETSI CCMS and CAMP SCMS

This implementation targets the **European CCMS** (C-ITS Credential Management System) profile based on ETSI TS 102 940 / 102 941. It is architecturally similar to the North American **CAMP SCMS** but differs in:

| Aspect | This repo (ETSI) | CAMP SCMS |
|---|---|---|
| Pseudonym cert name | Authorization Ticket (AT) | Pseudonym Certificate (PC) |
| Identity cert name | Enrolment Credential (EC) | Enrollment Certificate (EC) |
| Certificate format | EtsiTs103097Certificate | IEEE1609Dot2 ExplicitCertificate |
| Message wrapper | EtsiTs103097Data-Signed | Ieee1609Dot2Data |
| Primary PSID | CAM=36, DENM=37 | BSM=32 |
| Standard reference | ETSI TS 103 097 V2.2.1 | IEEE 1609.2-2016 / 1609.2.1 |
