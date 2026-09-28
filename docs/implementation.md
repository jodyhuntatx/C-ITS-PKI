# Part II — Implementation Details

How the utility implements the certificate formats, security profiles and cryptographic
mechanisms, with the standard clause behind each element. Operational use is covered in
[Part I](operations.md), evidence of conformance in [Part III](compliance.md), and gaps
and decisions in [design decisions](design-decisions.md). References [Rn] are in the
[appendix](references.md).

- [1. Architecture](#1-architecture)
- [2. Source layout](#2-source-layout)
- [3. Common elements](#3-common-elements)
- [4. v3 encoding (COER)](#4-v3-encoding-coer)
- [5. v2 encoding (TS 103 097 V1.2.1)](#5-v2-encoding-ts-103-097-v121)
- [6. Signed messages](#6-signed-messages)
- [7. Encrypted messages](#7-encrypted-messages)
- [8. Butterfly Key Mechanism](#8-butterfly-key-mechanism)
- [9. Verification](#9-verification)
- [10. Certificate profiles as issued](#10-certificate-profiles-as-issued)

---

## 1. Architecture

The utility is an offline PKI. It generates all key material, acts as every
authority, and writes certificates and messages to files. It implements the C-ITS
trust model of ETSI TS 102 940 [R6] and TS 102 941 [R5]:

```
                 Root CA (self-signed, trust anchor)          TLM (self-signed, CTL signer)
                 /                            \
   EA (Enrolment Authority)          AA (Authorization Authority)
            |                                   |
   EC (Enrolment Credential)        AT (Authorization Ticket), also issued in
   long-term identity               butterfly batches (IEEE 1609.2.1)
```

The EA knows the station's identity (EC) but does not issue ATs. The AA issues ATs but
never sees the EC. The butterfly mechanism (section 8) additionally prevents the EA
from recognising the ATs the AA issues for its requests [R21 §1].

Every artefact exists in two formats (see [operations §2](operations.md#2-choosing-a-format-v2-or-v3)),
chosen per PKI. The code paths split at the encoding layer: `certificates.py` and
`pki.py` build format-neutral dataclasses, `v1_encoding.py` serialises v2, and
`encoding/asn1_codec.py` serialises v3.

## 2. Source layout

| Path | Role |
|---|---|
| `cli.py` | command-line interface ([operations §4](operations.md#4-cli-reference)) |
| `src/types.py` | dataclasses (`Certificate`, `ToBeSignedCertificate`, …), enums (`ItsAid`, `EtsiVersion`, …), ITS time helpers |
| `src/pki.py` | `CITSPKI`: hierarchy creation, enrolment, AT issuance, butterfly orchestration, `save()` |
| `src/certificates.py` | certificate profiles (section 10), format dispatch, v3 certificate signing |
| `src/encoding/asn1_codec.py` | v3: dataclass ↔ ASN.1 value mapping, COER via asn1tools [R27] |
| `src/encoding/certificate.py` | v3: certificate encode/decode API with strict canonical check |
| `src/asn1/*.asn` | ASN.1 modules vendored from Vanetza [R24] (see `src/asn1/README.md`) |
| `src/v1_encoding.py` | v2: certificate serialiser/parser, HashedId8 |
| `src/signing.py` | signed messages, v2 and v3; v2 `SecuredMessage` parser |
| `src/encryption.py` | encrypted and signed-and-encrypted messages, v2 and v3 |
| `src/crypto.py` | ECDSA, ECIES, KDF2, AES-CCM, butterfly key functions, key serialisation |
| `src/verification.py` | certificate signature, validity, profile, chain and revocation-by-hash checks |
| `src/coer.py`, `src/encoding/keys.py`, `src/encoding/permissions.py` | **legacy**: the pre-2026-09 hand-written encoder. Not used for any output; kept only because old unit tests in `test_08` import them. Their CHOICE and PSID encodings are **not** COER-conformant ([DD-18](design-decisions.md#dd-18)). |

## 3. Common elements

### 3.1 Algorithms

| Function | Algorithm | Standard | Implementation |
|---|---|---|---|
| Signature | ECDSA over NIST P-256 with SHA-256 | [R1 cl. 4.2], [R4 cl. 4.2.2], [R16] | `crypto.ecdsa_sign/verify` (OpenSSL via [R28]); signatures carry `r` as an x-only point |
| Hash | SHA-256 | [R1 cl. 4.2] | `hashlib` |
| Key agreement | ECDH (x-coordinate) | [R4 cl. 5.9] (ECSVDP-DHC), [R1 Annex B] | `cryptography` ECDH |
| Key wrap | ECIES: KDF2-SHA256, XOR, HMAC-SHA256/128 | [R1 Annex B], [R4 cl. 5.9], [R13], [R14] | `crypto.ecies_encrypt/decrypt` (section 7.2) |
| Data encryption | AES-128-CCM, 12-byte nonce, 16-byte tag | [R1 cl. 4.2, Annex B], [R15] | `crypto.aes_ccm_*` |
| Butterfly expansion | AES-128 expansion function | [R11] via [R22], [R21 §3.3] | section 8 |

NIST P-384 keys can be generated (`generate_keypair`), but neither certificate format
can carry them ([DD-02](design-decisions.md#dd-02)).

### 3.2 Time

- **Time32**: seconds, and **Time64**: microseconds, both since 2004-01-01 00:00:00 UTC
  (`types.unix_to_its_time32/64`).
- The standards count TAI seconds [R4 cl. 4.2.14–4.2.15]. The tool, like Vanetza, uses
  UTC-based values and so omits the 5 leap seconds inserted since 2004
  ([DD-17](design-decisions.md#dd-17)).

### 3.3 Keys and identifiers

- Private keys are stored as unencrypted PKCS#8 DER. Public keys are carried as
  compressed points (33 bytes for P-256).
- **HashedId8** (certificate digest):
  - v3: the last 8 bytes of SHA-256 over the canonical COER certificate
  - v2: the last 8 bytes of SHA-256 over the certificate
    (`v1_encoding.hash_certificate_v1`; matches Vanetza `calculate_hash`)
- ITS-AIDs [R7]: CAM 36, DENM 37, GN-MGMT 141, CTL 617, CRL 622, secured certificate
  request 623, MDM 637 (`types.ItsAid`).

## 4. v3 encoding (COER)

### 4.1 Schema and codec

- **Schema:** the ASN.1 modules Vanetza compiles for its v3 layer [R24] are vendored in
  `src/asn1/`:

  | Module | Identifier | SHA-256 of vendored file |
  |---|---|---|
  | `IEEE1609dot2` | `{iso(1) … dot2(2) base(1) schema(1) major-version-2(2)}` | `4df4be96…d3e43ece` |
  | `IEEE1609dot2BaseTypes` | `{… base(1) base-types(2) major-version-2(2)}` | `295a4322…a58a490dd` |
  | `EtsiTs103097Module` | `{itu-t(0) … ts(103097) v1(0)}` (TS 103 097 V1.3.1 [R3]) | `6fc5b220…17afc696` |

- **Codec:** `asn1_codec.compiled()` compiles them once with asn1tools' OER codec [R27].
  The top-level types are `EtsiTs103097Certificate`, `ToBeSignedCertificate` and
  `EtsiTs103097Data`.
- **Why these modules:** see [DD-01](design-decisions.md#dd-01) for why these rather
  than the TS 103 097 V2.2.1 / IEEE 1609.2-2025 modules named in the PRD.

### 4.2 Canonical encoding (COER)

TS 103 097 requires COER per ITU-T X.696 [R1 cl. 4.1], [R12]. asn1tools produces OER,
and the codec enforces the canonical rules that asn1tools leaves to the caller:

- **DEFAULT components are omitted** when they equal the default. This applies to
  `PsidGroupPermissions.minChainLength` (1), `chainLengthRange` (0) and `eeType` (`'00'H`).
  See [DD-04](design-decisions.md#dd-04).
- **Public key points are always compressed** (`compressed-y-0/1`). This is the
  canonical form used for certificate hashing and signing.
- **Decoding is strict.** `encoding.certificate._decode_canonical` re-encodes every
  decoded value and rejects the input unless the bytes are identical. The asn1tools OER
  decoder alone is lenient and accepts some non-canonical or malformed input
  ([DD-03](design-decisions.md#dd-03)). The same check is applied to signed and
  encrypted messages.

### 4.3 Certificate signature

- **Signature input:** a certificate's ECDSA signature is computed over
  `Hash( Hash(tbsCertificate) ‖ Hash(signer) )`. `tbsCertificate` is the canonical COER
  of `toBeSigned`, and `signer` is the canonical COER of the issuer certificate, or the
  empty string for a self-signed certificate.
- **Sources:** the "Data Input / Signer Identifier Input" rule of IEEE 1609.2 clause
  5.3.1 [R9], referenced by [R1 cl. 6] and described in [R5 cl. 6.2.3.5.2]. Vanetza
  implements the same rule (`security/v3/hash.cpp`, "IEEE 1609.2 clause 5.3.1.2.2").
- **Code:** `crypto.ieee1609_signing_input` builds `Hash(tbs) ‖ Hash(signer)`, and ECDSA
  applies the outer hash.
- **Other fields:** the issuer is `self` with `sha256`, or `sha256AndDigest` of the
  issuer certificate [R1 cl. 7.2.x]. `r` is encoded as `x-only`.

## 5. v2 encoding (TS 103 097 V1.2.1)

### 5.1 Certificate

The v2 certificate follows TS 103 097 V1.2.1 clause 6.1 [R4], as serialised by Vanetza's
`security/v2` module [R24]. The encoder is `v1_encoding.build_and_sign_v1`:

```
0x02                                   version (cl. 6.1)
SignerInfo                             0x00 self | 0x01 + HashedId8 (cl. 4.2.10/4.2.11)
SubjectInfo                            subject_type + length + name (ASCII; empty for AT) (cl. 6.2/6.3)
length ‖ SubjectAttribute…             ascending type order (cl. 6.4/6.5):
    0x00 verification_key              0x00 (ECDSA P-256) + EccPoint (0x02/0x03 + x)
    0x01 encryption_key                0x01 (ECIES P-256) + 0x00 (AES-128-CCM) + EccPoint   (EA, AA)
    0x02 assurance_level               SubjectAssurance byte (level << 5 | confidence), default 0x00
    0x20 its_aid_list | 0x21 its_aid_ssp_list   IntX AIDs [+ length-prefixed SSP]  (CAs: 0x20; EC, AT: 0x21)
length ‖ ValidityRestriction…          (cl. 6.7/6.8)
    0x01 time_start_and_end            Time32 start + Time32 end
    0x03 region (optional)             identified region, one country ID
Signature                              0x00 (ECDSA P-256) + EccPoint x-only (0x00 + r) + s
```

- **Lengths and IntX:** use the variable-length coding of [R4 cl. 4.1–4.2.1]
  (`v1_encoding.encode_length`).
- **Signature input:** all fields before the signature, including the vector lengths
  [R4 cl. 7.4.1] (`compute_signing_input_v1`).
- **End time:** start + duration, using Vanetza's unit multipliers (years = 31,556,925 s).
- **Assurance:** every certificate carries `assurance_level` (attribute `0x02`), default `0x00` [R4 cl. 7.4.1].

### 5.2 ITS-AID lists and SSPs

- **CA lists:** a v2 certificate's AIDs must be a subset of its signer's [R4 cl. 7.4.1].
  CA certificates therefore list the AIDs of everything they issue
  ([DD-06](design-decisions.md#dd-06)):
  - AA: 36, 37, 141, 623
  - EA: 623
  - Root: 622, 617, 36, 37, 141, 623
- **ATs:** always carry `its_aid_ssp_list` [R4 cl. 7.4.2]. The default SSPs are
  `01 00 00` (CAM) and `01 00 00 00` (DENM), "no special permissions" [R17], [R18],
  matching Vanetza `certify` ([DD-07](design-decisions.md#dd-07)).

## 6. Signed messages

`signing.sign_data` selects the format from the signer certificate (`cert_format`: version
byte `0x02` means v2) ([DD-11](design-decisions.md#dd-11)).

### 6.1 v3: EtsiTs103097Data-Signed

```
EtsiTs103097Data { protocolVersion 3,
  content signedData {                                   [R1 cl. 5.1, 5.2]
    hashId sha256,
    tbsData {
      payload { data: Ieee1609Dot2Data { 3, unsecuredData <payload> } }
                | { extDataHash: sha256HashedData <32 bytes> }       (external payload)
      headerInfo { psid, generationTime,
                   [generationLocation {latitude, longitude, elevation}], [expiryTime] } },
    signer   digest <HashedId8>  |  certificate [ <AT> ],
    signature ecdsaNistP256Signature { rSig x-only, sSig } } }
```

- **Signature input:** `Hash(Hash(COER(tbsData)) ‖ Hash(COER(signer certificate)))`,
  computed over the full signer certificate even when only its digest is sent [R1 cl.
  5.2] → [R9 cl. 5.3.1].
- **Header fields:** `p2pcdLearningRequest` and `missingCrlIdentifier` are never
  produced [R1 cl. 5.2]. `inlineP2pcdRequest` and `requestedCertificate` depend on
  receive-side state that an offline tool does not have
  ([DD-13](design-decisions.md#dd-13)).
- **CAM** [R1 cl. 7.1.1]: psid 36, `generationTime` only. The signer is a digest by
  default, or the certificate with `--full-cert`.
- **DENM** [R1 cl. 7.1.2]: psid 37, `generationTime` + `generationLocation`, signer = certificate.
- **Elevation:** `ElevInt` encodes −4096…61439 decimetres, with negative values as
  16-bit two's complement.

### 6.2 v2: SecuredMessage

```
0x02                                  protocol_version                       [R4 cl. 5.1]
length ‖ HeaderField…                 signer_info first, then ascending type  [R4 cl. 7.1]
    0x80 signer_info                  0x01 digest | 0x02 certificate
    0x00 generation_time              Time64
    0x02 expiration                   Time32 (optional)
    0x03 generation_location          int32 lat, int32 lon, 2-byte elevation (DENM)
    0x05 its_aid                      IntX
    0x81 encryption_parameters        (encrypted messages, section 7)
    0x82 recipient_info               (encrypted messages, section 7)
payload_type ‖ length ‖ data          0x01 signed | 0x02 encrypted | 0x03 signed_external | 0x04 signed_and_encrypted
length(67) ‖ TrailerField             0x01 signature: 0x00 ECDSA P-256, 0x00 x-only, r, s
```

- **Signature input:** protocol version, the header vector with its length, the whole
  payload field, and the trailer-vector length plus the signature trailer type
  [R4 cl. 7.1, Table 6] (`signing._v2_sign`).
- **Profiles:** CAM and DENM header sets follow [R4 cl. 7.1/7.2].
- **Generic profile** [R4 cl. 7.3]: for ITS-AIDs other than 36/37 the signer is always the
  certificate and `generation_location` is required. v2 external-payload and
  signed-and-encrypted messages are refused for CAM/DENM, which shall be `signed` and not
  encrypted [R4 cl. 7.1, 7.2] ([DD-20](design-decisions.md#dd-20)).
- **`signed_external`** [R4 cl. 5.2]: the payload field is sent with zero-length data. The
  external data is included in the signing input at the payload position, and
  `verify_signed_data(..., external_payload_hash=...)` needs it
  ([DD-19](design-decisions.md#dd-19)).

### 6.3 Verification (`verify_signed_data`)

1. Detect the format from the protocol byte.
2. v3: decode and require canonical COER. v2: parse with `signing.v2_parse`.
3. Resolve the signer:
   - embedded certificate: must equal `--at-cert` if one is supplied;
   - digest: must equal the HashedId8 of `--at-cert`, which is then required.
4. Recompute the signature input and verify the ECDSA signature.

This checks the message signature only. `verify-sig --aa --root` adds the chain checks
(section 9).

## 7. Encrypted messages

### 7.1 v3: EtsiTs103097Data-Encrypted

```
EtsiTs103097Data { 3, content encryptedData {                               [R1 cl. 5.3]
  recipients [ certRecipInfo { recipientId <HashedId8 of recipient cert>,
                               encKey eciesNistP256 { v compressed point, c 16 bytes, t 16 bytes } } ],
  ciphertext aes128ccm { nonce <12 random bytes>, ccmCiphertext <AES-128-CCM(k, nonce, plaintext)> } } }
```

- **Unicast:** exactly one recipient [R1 cl. 5.1].
- **Signed-and-encrypted** [R1 cl. 7.1.5]: an `EtsiTs103097Data-Encrypted` whose
  plaintext is an `EtsiTs103097Data-Signed`. `decrypt_and_verify` decrypts, then
  verifies the inner message.
- **Recipient types:** `pskRecipInfo` and `signedDataRecipInfo` are not implemented
  ([KD-7](compliance.md#6-known-deviations)).

### 7.2 ECIES

Per [R1 Annex B] and [R4 cl. 5.9], implemented by `crypto.ecies_encrypt` / `ecies_decrypt`:

1. Generate a fresh ephemeral key `v`, `V = v·G`.
2. `S = x(v·K_r)`.
3. `ke ‖ km = SHA256(S ‖ 00000001 ‖ P1) ‖ SHA256(S ‖ 00000002 ‖ P1)`, truncated to 48 bytes.
4. `c = k ⊕ ke`, `t = HMAC-SHA256(km, c)[0..16)`.

`P1` is not defined in TS 103 097 V2.2.1 Annex B. It is resolved as follows
([DD-09](design-decisions.md#dd-09)):

| Format / recipient | `P1` | Source |
|---|---|---|
| v3 `certRecipInfo` | SHA-256 of the COER-encoded recipient certificate | IEEE 1609.2 [R9]/[R10] as quoted by [R23] (`RecipientInfo.java`) |
| v2 | empty string ("P1 and P2 shall be empty strings") | [R4 cl. 5.9] |

The implementation reproduces both SCMS ECIES reference vectors exactly [R22]
(`test_06`).

### 7.3 v2: encrypted SecuredMessage

- **Headers:** `encryption_parameters` (`0x81`: `0x00` AES-128-CCM + 12-byte nonce) and
  `recipient_info` (`0x82`: length + HashedId8 + `0x01` ECIES P-256 + `V` (type + x) +
  `c` + `t`) [R4 cl. 4.2.7, 5.8, 5.9].
- **Payload:** `encrypted` (2). The trailer is empty.
- **Signed-and-encrypted:** a single message with payload `signed_and_encrypted` (4),
  a `signer_info` header, and a signature trailer covering the ciphertext.
  `decrypt_and_verify` verifies before decrypting.

## 8. Butterfly Key Mechanism

The Butterfly Key Mechanism (BKM) of IEEE 1609.2.1 [R11], as profiled by ETSI
TS 102 941 [R5 cl. 6.2.3.5]. The formal description follows [R21 §3.3, Figs. 2–4] and
the reference implementation [R22].

### 8.1 Expansion function

```
x_cert = 0^32 ‖ i ‖ j ‖ 0^32        (certificate / verification keys)
x_enc  = 1^32 ‖ i ‖ j ‖ 0^32        (response encryption keys, original option)
f_k^int(x) = (AES_k(x+1) ⊕ (x+1)) ‖ (AES_k(x+2) ⊕ (x+2)) ‖ (AES_k(x+3) ⊕ (x+3))      384 bits
f_k(x)     = f_k^int(x) mod n
```

- **Inputs:** `k` is a 16-byte expansion key [R5 cl. 6.2.3.5.2]. `i` is the i-period
  and `j` the certificate index (32 bits each). Additions are mod 2^128.
- **Code:** `crypto.bke_expansion_input`, `bke_f_k_int`, `bke_f_k`.
- **Validation:** checked against the SCMS reference vectors for both certificate and
  encryption expansion [R22] (`test_08`).

### 8.2 Roles and keys

| Step | Party | Computation | Function |
|---|---|---|---|
| Caterpillar | EE | `(a, A)`, `k`; original also `(h, H)`, `ek` | `generate_keypair`, `random_bytes(16)` |
| Cocoon keys | EA/RA | `pk_cc = A + f_k(x_cert)·G`; response key `H + f_ek(x_enc)·G` (original) or `pk_cc` (unified) | `bke_cocoon_public_key` |
| Butterfly keys | AA/ACA | random `r ∈ [1, n-1]`; certify `pk_bf = pk_cc + r·G` | `bke_random_offset`, `bke_butterfly_public_key`, `certificates.issue_butterfly_authorization_tickets` |
| Reconstruction | EE | `sk_cc = a + f_k(x_cert)`, `sk_bf = sk_cc + r mod n`; check `sk_bf·G = pk_bf` | `bke_cocoon_private_key`, `bke_butterfly_private_key` |

- **Why the offset `r`:** it stops the EA, which can compute every cocoon key, from
  recognising the certified keys [R21 §1, Fig. 3]. The published standard uses
  `h_i = r_i` [R21 Fig. 3], and this implementation follows that
  ([DD-12](design-decisions.md#dd-12)).
- **Modes:** *original* uses a separate encryption caterpillar and expansion key, and
  the AA's response is encrypted to the encryption cocoon key. *Unified* [R20] reuses
  the signing cocoon key for the response. TS 102 941 allows both
  [R5 cl. 6.2.3.5.2, 6.2.3.5.4].
- **Orchestration:** `CITSPKI.issue_butterfly_authorization_tickets` runs all three
  roles and aborts if the end entity could not decrypt the response or if a
  reconstructed key does not match its certificate.
- **Scope:** the protocol messages (`EeRaCertRequest`, `ButterflyAuthorizationRequest`,
  encrypted `AcaEeCertResponse`) are not produced
  ([KD-8](compliance.md#6-known-deviations)).

## 9. Verification

`verification.py` implements the checks behind `verify-cert` and `verify-sig --root`:

| Check | Function | Basis |
|---|---|---|
| Certificate signature (v3: IEEE 1609.2 input; v2: signing input) | `verify_certificate_signature` | [R1 cl. 6], [R4 cl. 7.4.1] |
| Validity `[start, start + duration)` | `verify_certificate_validity_period` | [R1 cl. 6] |
| Issuer digest = HashedId8(issuer) | `verify_issuer_digest` | [R1 cl. 7.2.x] |
| cracaId = 000000H, crlSeries = 0 | `verify_craca_and_crl_series` | [R1 cl. 6] |
| appPermissions or certIssuePermissions present | `verify_permissions_constraints` | [R1 cl. 6] |
| AT profile: id none, no certIssuePermissions, appPermissions | `verify_at_profile` | [R1 cl. 7.2.1] |
| Region; 65535 = EU-27 | `verify_region_constraint` | [R1 cl. 6] |
| Chain root → CA → leaf | `verify_certificate_chain` | [R1 cl. 4.1] → [R9 cl. 5.1] |
| Revocation by HashedId8 | `check_revocation_by_hash` | [R1 cl. 4.1] (Hash ID-based) |

Durations in years are converted with 365.25 days, while Vanetza uses 31,556,952 s
([KD-5](compliance.md#6-known-deviations)).

## 10. Certificate profiles as issued

v3 values (`certificates.py`), with the profile clause of [R1] and the v2 equivalent from
[R4 cl. 7.4]:

| Certificate | [R1] clause | issuer | id | appPermissions (v3) | certIssuePermissions (v3) | encryptionKey | v2 subject_type / AID attribute |
|---|---|---|---|---|---|---|---|
| Root CA | 7.2.3 | self (sha256) | name | CRL 622, CTL 617 | all, minChainLength 2, eeType {app, enrol} | — | root_ca / its_aid_list (6 AIDs) |
| TLM | 7.2.5 | self (sha256) | name | CTL 617 | — | — | root_ca / its_aid_list (617) |
| EA | 7.2.4 | sha256AndDigest(Root) | name | 623 | all, minChainLength 1, eeType {enrol} | ECIES P-256 | enrollment_authority / its_aid_list (623) |
| AA | 7.2.4 | sha256AndDigest(Root) | name | 623 | all, minChainLength 1, eeType {app} | ECIES P-256 | authorization_authority / its_aid_list (36, 37, 141, 623) |
| EC | 7.2.2 | sha256AndDigest(EA) | name | 623 | — | — | enrollment_credential / its_aid_ssp_list (623, empty SSP) |
| AT | 7.2.1 | sha256AndDigest(AA) | none | 36, 37 (no SSP) | — | — | authorization_ticket / its_aid_ssp_list |
| Butterfly AT | 7.2.1 | sha256AndDigest(AA) | none | 36, 37 | — | — | authorization_ticket / its_aid_ssp_list |

- **Common v3 fields:** `cracaId` 000000H, `crlSeries` 0, `type` explicit.
- **Absent v3 fields:** `certRequestPermissions`, `canRequestRollover`, `assuranceLevel`.
- **Region:** only when `--region` is given.
- **Validity:** Root and TLM 10 years, EA and AA 5 years, EC 1 year, AT 168 hours (defaults).
- **Issuing permissions:** the choice of `subjectPermissions all`, `minChainLength` and
  `eeType` is explained in [DD-05](design-decisions.md#dd-05).
