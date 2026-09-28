# Part III — Standards Compliance and Evidence

This part maps each normative requirement the utility addresses to its implementation,
and to evidence that can be reproduced. It also lists the known deviations. Design
decisions for gaps and ambiguities in the specifications are in
[design-decisions.md](design-decisions.md). References [Rn] are in the
[appendix](references.md).

- [1. Evidence methods](#1-evidence-methods)
- [2. Summary](#2-summary)
- [3. ETSI TS 103 097 — v3 format](#3-etsi-ts-103-097--v3-format)
- [4. ETSI TS 103 097 V1.2.1 — v2 format](#4-etsi-ts-103-097-v121--v2-format)
- [5. IEEE 1609.2.1 Butterfly Key Mechanism](#5-ieee-160921-butterfly-key-mechanism)
- [6. Known deviations](#6-known-deviations)
- [7. PRD requirements traceability](#7-prd-requirements-traceability)

**Status key:** ✅ conforms, with evidence · ⚠️ partial (scope noted) · ❌ not implemented ·
⛔ deviation (known nonconformance, section 6) · N/A not applicable to an offline issuing tool.

---

## 1. Evidence methods

| ID | Method | What it demonstrates | How to reproduce | Result (2026-09-25) |
|---|---|---|---|---|
| **E1** | Tool test suites `tests/v2`, `tests/v3` | Profiles, encodings, crypto, negative cases | `bash tests/v2/run_all.sh`, `bash tests/v3/run_all.sh` | v2: 84/84 tests, 9/9 suites. v3: 85/85 tests, 9/9 suites |
| **E2** | Published reference vectors [R22] | Butterfly expansion function (certificate and encryption), ECIES (C, T), bit-exact | `test_08` "Expansion function matches the SCMS reference test vectors"; `test_06` "ECIES matches the SCMS reference test vectors" | all vectors match |
| **E3** | ASN.1 schema conformance | v3 certificates and messages are canonical COER of the schema Vanetza compiles [R24] | `test_08`/`test_05`/`test_06` conformance tests (decode, then byte-identical re-encode) | all pass; legacy non-COER input rejected |
| **E4** | Independent crypto recomputation | Signature inputs recomputed with `cryptography` rather than the tool's own code (IEEE 1609.2 certificate and message inputs; v2 `convert_for_signing`); ECIES `P1` per format | `test_08` "Signatures use the IEEE 1609.2 input…", `test_05` conformance tests, `test_06` P1 tests | pass |
| **E5** | Vanetza-NAP message checker `vnap-msgcheck` [R30] | Vanetza's own parser and `StraightVerifyService` (v3 with full-chain AT→AA→root) accept tool output | [operations §8](operations.md#8-using-the-output-with-vanetza-nap) | see table E5 below |
| **E6** | Vanetza-NAP live simulation [R30] | RSU and OBU exchange CAMs signed with tool certificates over the simulated link; OBU uses a butterfly AT | `run-r2-sim.sh c-its-pki` + `check-r2-cams.sh` | v3: 30/30 `Success` both ways (original-mode butterfly AT). v2: 20/20 `Success` both ways (unified-mode butterfly AT) |
| **E7** | End-to-end workflow script | All CLI workflows for both formats, including full-chain `verify-sig` and decrypt-then-verify | `bash gen-verify.sh` | exit 0; 20 × VALID, 0 × INVALID |
| **E8** | Vanetza `certify show-certificate` | v2 certificates parse in Vanetza's v2 decoder | `certify show-certificate <file>` in the Vanetza image | parses Root, AA, AT, butterfly AT |
| **E9** | Latency measurement | NFR-PER budgets | benchmark in section 7.3 | far below budget |
| **E10** | Stock Vanetza-NAP (`vnap:r2-stock`, without the vnap-secure assurance patch) live simulation | v2 certificates meet Vanetza's unmodified TS 103 097 V1.2.1 checks (KD-1) | `CERTS_DIR=… PKI_SECURITY=certs-v2 ./run-r2-sim.sh c-its-pki vnap:r2-stock` | OBU: 15/15 `Success` for RSU CAMs (before KD-1 was fixed: all rejected). The RSU direction shows the stock image's clock bug (`Invalid_Timestamp`), unrelated to certificates |

**E5: Vanetza verification of tool output** (`vnap-msgcheck`, Vanetza-NAP release2 + vnap-secure patches):

| Message | v3 | v2 |
|---|---|---|
| CAM, signer digest | `Success` (full chain) | `Success` |
| CAM, signer certificate | `Success` (full chain) | `Success` |
| DENM (certificate, generation location) | `Success` (full chain) | `Success` |
| External payload | `Success` | parsed (`decode-v2`: payload type 3, empty data); Vanetza's v2 verifier only verifies payload type `signed` |
| Generic message, ITS-AID 623 (certificate signer, generation location) | — | `Success` (AT authorised for 623); an AT without 623 is rejected as `Insufficient_ITS_AID`, as expected |
| Payload byte flipped | `False_Signature` ✓ | `False_Signature` ✓ |
| Chain to an untrusted root | `Invalid_Certificate` (Unknown_Signer) ✓ | Vanetza v2 does not check AA→root (upstream limitation) |
| Encrypted / signed-and-encrypted (`decode-*`) | parsed: `certRecipInfo/eciesNistP256`, `aes128ccm` | parsed, every byte consumed; headers 0,129,130 / 128,0,5,129,130 |
| Inner CAM after decryption | `Success` (full chain) | `Success` |
| Output of the pre-2026-09 encoder | rejected by the parser | — |

## 2. Summary

| Area | Status |
|---|---|
| v3 certificate format and all certificate profiles except the Misbehaviour Authority [R1 cl. 6, 7.2] | ✅ (explicit certificates, P-256) |
| v3 signed, external-payload, encrypted and signed-and-encrypted data [R1 cl. 5, 7.1] | ✅ (`certRecipInfo` only) |
| v2 certificate and message formats [R4] | ✅ (deviations KD-1 to KD-4 resolved 2026-09-25) |
| ECIES / AES-CCM [R1 Annex B], [R4 cl. 5.9] | ✅ (reference vectors) |
| Butterfly key derivation [R11] via [R5 cl. 6.2.3.5] | ✅ (reference vectors); protocol messages ❌ |
| Implicit certificates, P-384, psk/signedData recipients, MA certificate, PICS | ❌ (see section 6 and design decisions) |

## 3. ETSI TS 103 097 — v3 format

Clauses of TS 103 097 V2.2.1 [R1]. The implementation uses the V1.3.1 ASN.1 module
[R3] ([DD-01](design-decisions.md#dd-01)); the clauses below have the same content in
both editions for the features implemented.

| Clause | Requirement | Status | Implementation | Evidence |
|---|---|---|---|---|
| 4.1 | COER per X.696 [R12], canonical encodings | ✅ | asn1tools + DEFAULT omission + compressed points + strict re-encode ([impl §4.2](implementation.md#42-canonical-encoding-coer)) | E3, E5, E6 |
| 4.1 | Certificate validity per 1609.2 cl. 5.1, Hash ID revocation for EA/AA | ⚠️ | `verify_certificate_chain`, `check_revocation_by_hash`; no CRL processing; year length KD-5 | E1 `test_09` |
| 4.1 | PICS exceptions: parse UnCountryId / CountryAndRegions / … | ⚠️ | identified regions decode; only `countryOnly` values are kept. Non-identified regions are not parsed (KD-6) | E1 `test_07`, `test_09` |
| 4.2 | ECDSA, SHA-256/384, ECIES, AES-128 | ⚠️ | P-256/SHA-256 only ([DD-02](design-decisions.md#dd-02)) | E1–E6 |
| 4.3 | Extensions, HeaderInfo `contributedExtensions` | ❌ | not in the 1609.2-2016 schema used ([DD-01](design-decisions.md#dd-01)) | — |
| 5.1 | `EtsiTs103097Data` variants: Unsecured (inner), Signed, SignedExternalPayload, Encrypted(-Unicast), SignedAndEncrypted(-Unicast) | ✅ | `signing.py`, `encryption.py` | E1 `test_05`/`test_06`, E5 |
| 5.2 | `hashId`; `tbsData.payload` data or `extDataHash` | ✅ | sha256; both payload forms | E1, E5 |
| 5.2 | headerInfo: psid, generationTime always present | ✅ | `_v3_header_info` | E1 `test_05` (header set asserted) |
| 5.2 | `p2pcdLearningRequest`, `missingCrlIdentifier` absent | ✅ | never generated | E1 `test_05` |
| 5.2 | `inlineP2pcdRequest`, `requestedCertificate`, `pduFunctionalType` per profile | N/A | receive-state dependent ([DD-13](design-decisions.md#dd-13)) | — |
| 5.2 | signer digest, or exactly one certificate | ✅ | `_v3_sign` | E1, E5 |
| 5.2 | ECDSA signature per 1609.2 cl. 6.3.38/6.3.39/5.3.1 | ✅ | `Hash(Hash(tbsData) ‖ Hash(signer))` | E4, E5 |
| 5.3 | recipients: pskRecipInfo / certRecipInfo / signedDataRecipInfo | ⚠️ | `certRecipInfo` only (KD-7) | E1 `test_06`, E5 decode |
| 5.3 | ECIES per 1609.2 cl. 5.3.5; ciphertext AES-128-CCM | ✅ | `P1` = SHA-256(recipient cert) ([DD-09](design-decisions.md#dd-09)) | E2, E4, E5 |
| 6 | `EtsiTs103097Certificate`, explicit or implicit | ⚠️ | explicit only (KD-7) | E3, E5, E6 |
| 6 | id: name or none; cracaId 000000H; crlSeries 0 | ✅ | all profiles | E1 `test_02` (AC-11), `test_04` |
| 6 | validity `[start, start+duration)` | ✅ | `ValidityPeriod`; verifier year length KD-5 | E1 `test_09` |
| 6 | region; 65535 = EU-27 | ✅ | `identifiedRegion/countryOnly` | E1 `test_07`, `test_09` (AC-10) |
| 6 | ≥ 1 of appPermissions / certIssuePermissions; certRequestPermissions and canRequestRollover absent | ✅ | all profiles | E1 `test_02`–`test_04`, E3 |
| 6 | verifyKeyIndicator = verificationKey (explicit) | ✅ | compressed P-256 point | E3 |
| 6 | flags / appExtensions / certIssueExtensions / certRequestExtensions | ✅ (absent, permitted) | not in 2016 schema | E3 |
| 6 | certificate signature per 1609.2 cl. 5.3.1 | ✅ | [impl §4.3](implementation.md#43-certificate-signature) | E4, E5 (full chain), E6 |
| 7.1.1 | CAM: digest default, certificate option, psid 36, generationTime only | ✅ | `sign_cam` | E1 `test_05`, E5, E6 |
| 7.1.1 | CAM: once-per-second certificate inclusion, P2PCD reactions | N/A | runtime ITS-S behaviour ([DD-13](design-decisions.md#dd-13)) | — |
| 7.1.2 | DENM: signer certificate, generationLocation, psid 37 | ✅ | `sign_denm` | E1 `test_05` (AC-07), E5 |
| 7.1.3 | Generic signed / external payload | ✅ | `sign_data`, `sign_data_external_payload` | E1, E5 |
| 7.1.4 / 7.1.5 | Encrypted / signed-and-encrypted | ✅ | `encrypt_data`, `sign_and_encrypt` | E1 `test_06`, E5 |
| 7.2.1 | AT: issuer digest, appPermissions, id none, no certIssuePermissions | ✅ | `issue_authorization_ticket`, butterfly | E1 `test_04` (AC-05), E3, E5, E6 |
| 7.2.2 | EC: explicit, issuer digest, appPermissions (request signing), id name, no certIssuePermissions | ✅ | `issue_enrolment_credential` | E1 `test_04` (AC-04) |
| 7.2.3 | Root CA: explicit, self, certIssuePermissions, appPermissions CRL + CTL, id name | ✅ | `issue_root_ca_certificate` | E1 `test_02` (AC-01) |
| 7.2.4 | EA/AA: explicit, issuer digest, encryptionKey, certIssuePermissions, appPermissions | ✅ | `issue_ea/aa_certificate` | E1 `test_03` (AC-02/03) |
| 7.2.5 | TLM: explicit, self, appPermissions CTL, id name, no encryptionKey / certIssuePermissions | ✅ | `issue_tlm_certificate` | E1 `test_04` |
| 7.2.6 | Misbehaviour Authority certificate | ❌ | not implemented (KD-7) | — |
| Annex B | ECIES KDF2, XOR, HMAC tag (16 bytes), AES-CCM nonce 12 / key 16 | ✅ | `crypto.ecies_*`, `aes_ccm_*` | E2 |

## 4. ETSI TS 103 097 V1.2.1 — v2 format

| Clause [R4] | Requirement | Status | Evidence |
|---|---|---|---|
| 4.2 | Basic elements: IntX, EccPoint, Time32/64, Duration, identified region | ✅ (times UTC-based, [DD-17](design-decisions.md#dd-17)) | E1 `test_08`, E8, E6 |
| 5.1–5.4 | SecuredMessage, payload types signed/encrypted/signed_and_encrypted, header fields | ✅ | E1 `test_05`/`test_06`, E5 |
| 5.2 | `signed_external`: no payload data transmitted; external data signed at the payload position | ✅ (KD-3 resolved, [DD-19](design-decisions.md#dd-19)) | E1 `test_05` (independent signing-input check), E5 decode |
| 5.6 / 7.1 Table 6 | Signature over version, header vector with length, payload, trailer length and type | ✅ | E4 (`test_05` v2 conformance), E5, E6 |
| 5.8 / 5.9 | RecipientInfo, EciesEncryptedKey; `P1`, `P2` empty; KDF2-SHA256; MAC1 tBits 128 | ✅ | E1 `test_06` (layout, empty `P1`), E2 (KDF/MAC), E5 decode |
| 6.1 | Certificate structure, version 2 | ✅ | E8, E6 |
| 7.1 | CAM: signer_info first, digest or certificate, generation_time, its_aid, ascending order | ✅ | E5, E6 |
| 7.2 | DENM: signer certificate, generation_time, generation_location, its_aid | ✅ | E5 |
| 7.3 | Generic: signer certificate and generation_location required | ✅ (KD-4 resolved, [DD-20](design-decisions.md#dd-20)) | E1 `test_05`/`test_06`, E5 (generic 623 `Success`) |
| 7.1 / 7.2 | CAMs/DENMs: payload type signed, not encrypted | ✅ (v2 encryption / external payload rejected for 36/37) | E1 `test_05` |
| 7.4.1 | verification_key; assurance_level (default 0) | ✅ (KD-1 resolved) | E1 `test_04`, E10 (stock Vanetza) |
| 7.4.1 | time_start_and_end; validity within signer's; region inheritance; AID subset of signer | ✅ | E6 (Vanetza consistency check), E1 |
| 7.4.1 | signature over version, signer_info, subject_info, attributes, restrictions | ✅ | E6, E1 `test_03`/`test_04` |
| 7.4.2 | AT: digest signer, subject_type 1, empty name, its_aid_ssp_list, time_start_and_end | ✅ | E6, E8 |
| 7.4.3 | EC: its_aid_ssp_list | ✅ (KD-2 resolved) | E1 `test_04` |
| 7.4.4 | CA: root self / others digest, subject types, its_aid_list | ✅ | E6, E8 |

## 5. IEEE 1609.2.1 Butterfly Key Mechanism

The standard itself was not available to the project [R11]. Conformance is shown against
the published reference vectors [R22], the formal protocol description [R21] and ETSI's
profile [R5].

| Element | Source | Status | Evidence |
|---|---|---|---|
| Expansion function `f_k`, 384-bit AES construction mod n | [R22] `bfkeyexp.py`, [R21 §3.3] | ✅ | E2: all intermediate values match (x, f_k^int, f_k, keys) |
| Inputs `x_cert = 0³²‖i‖j‖0³²`, `x_enc = 1³²‖i‖j‖0³²` | [R22] | ✅ | E2 |
| 16-byte expansion keys; original and unified options | [R5 cl. 6.2.3.5.2, 6.2.3.5.4] | ✅ | E1 `test_08` (both modes) |
| Cocoon keys `A + f_k(x)·G` / `a + f_k(x)` | [R21 Fig. 2] | ✅ | E2, E1 |
| AA random offset per certificate, `pk_bf = pk_cc + r·G` | [R21 Fig. 3] (standard: `h_i = r_i`) | ✅ | E1 `test_08` (fresh offsets, certified ≠ cocoon) |
| EE reconstruction `sk_bf = sk_cc + r`, check against certificate | [R21 Fig. 4] | ✅ | E1, E6 (OBU signs with reconstructed key) |
| Response encryption key: cocoon encryption key (original) / signing cocoon key (unified) | [R5 cl. 6.2.3.5.4], [R20] | ⚠️ keys derived and checked; no response ciphertext | E1 |
| Protocol messages (EeRaCertRequest, ButterflyAuthorizationRequest, AcaEeCertResponse) | [R5 cl. 6.2.3.5.2–6.2.3.5.7] | ❌ KD-8 | — |
| i-period definition | [R11] | ⚠️ [DD-12](design-decisions.md#dd-12) | — |

## 6. Known deviations

Nonconformances, with their remedy. None of the open ones affects the v3
CAM/DENM/certificate path used in the Vanetza-NAP simulation.

### 6.1 Open

| ID | Deviation | Affected | Standard | Impact | Remedy |
|---|---|---|---|---|---|
| **KD-5** | verifier converts `years` with 365.25 days | `verification.py` (tool-side checks only) | 1609.2 duration semantics; Vanetza uses 31,556,952 s | tool may accept a certificate up to ~11 min × years after Vanetza considers it expired | use 31,556,952 s per year |
| **KD-6** | only `identifiedRegion/countryOnly` regions are processed; other region forms fail to decode in the tool | v3 decoding of third-party certificates | [R1 cl. 4.1] (parse), cl. 6 | the tool cannot inspect certificates with circular/rectangular/polygonal regions | map the remaining alternatives into `GeographicRegion` |
| **KD-7** | not implemented: implicit certificates (issuing and validating), `pskRecipInfo` / `signedDataRecipInfo`, Misbehaviour Authority certificate | v3 | [R1 cl. 5.3, 6, 7.2.6] | features unavailable; explicit certificates are always valid choices for senders | future work |
| **KD-8** | butterfly protocol messages and TS 102 941 request/response messages are not produced | BKM, EC/AT request protocols | [R5 cl. 6.2] | the tool demonstrates key derivation, not the on-the-wire protocol | future work; see [DD-13](design-decisions.md#dd-13) |

### 6.2 Resolved

Fixed on 2026-09-25 in the tool's v2 encoder; no Vanetza changes were needed.

| ID | Former deviation | Standard | Fix | Evidence |
|---|---|---|---|---|
| **KD-1** | v2 certificates omitted `assurance_level` | [R4 cl. 7.4.1] | every v2 certificate carries `assurance_level` (attribute type 2), default `0x00` or `tbs.assurance_level`; the decoder now reports it | `test_04` "KD-1"; E10: stock Vanetza (no assurance patch) accepts the certificates |
| **KD-2** | v2 EC used `its_aid_list` | [R4 cl. 7.4.3] | ECs use `its_aid_ssp_list` like ATs; CA certificates keep `its_aid_list` | `test_04` "KD-2" |
| **KD-3** | v2 `signed_external` carried the hash as payload data | [R4 cl. 5.2] | zero-length payload on the wire; the external data (the 32-byte hash given by the caller) is signed at the payload position; verification takes it as `external_payload_hash` ([DD-19](design-decisions.md#dd-19)) | `test_05` "KD-3" (independent signing-input check); E5 decode |
| **KD-4** | v2 generic messages did not enforce the clause 7.3 profile | [R4 cl. 7.1–7.3] | for ITS-AIDs other than 36/37 the signer is always the certificate and `generation_location` is required; v2 external-payload and signed-and-encrypted messages are refused for CAM/DENM ([DD-20](design-decisions.md#dd-20)) | `test_05` "KD-4", `test_06`; E5 generic 623 `Success` |

## 7. PRD requirements traceability

Requirements of the project PRD [R26]. PRD profile numbers "9.x" correspond to
[R1] clauses 7.2.x (9.1→7.2.3, 9.2/9.3→7.2.4, 9.4→7.2.5, 9.5→7.2.2, 9.6→7.2.1,
9.7→7.2.6). The v3 test file headers use the PRD numbering.

### 7.1 Functional requirements

| ID | Requirement (abridged) | Status | Evidence / note |
|---|---|---|---|
| FR-KG-01 | ECDSA P-256 key pairs | ✅ | `test_01` |
| FR-KG-02 | ECDSA P-384 key pairs | ⚠️ | keys generated (`test_01`); not usable in certificates ([DD-02](design-decisions.md#dd-02)) |
| FR-KG-03 | CSPRNG | ✅ | OpenSSL via [R28], `os.urandom`; `test_01` distinctness |
| FR-KG-04 | compressed public keys (33/49 bytes) | ✅ | `test_01`; certificates use compressed points |
| FR-KG-05 | separate signing and encryption keys | ✅ | EA/AA `*_sign.key` / `*_enc.key`; `test_01` |
| FR-CI-01…06 | Root, EA, AA, TLM, EC, AT per profile | ✅ | section 3 rows 7.2.1–7.2.5; AC-01…05 |
| FR-CI-07 | EtsiTs103097Certificate in COER | ✅ (v3) | E3, E5 |
| FR-CI-08 | configurable validity `[start, start+duration)` | ✅ | CLI `--validity`; `test_09` |
| FR-CI-09 | app or certIssue permissions present | ✅ | `verify_permissions_constraints`; `test_02`–`04` |
| FR-CI-10 | cracaId 000000H, crlSeries 0 | ✅ | `test_02` (AC-11) |
| FR-CI-11 | explicit and implicit certificates | ⚠️ | explicit only (KD-7) |
| FR-SN-01 | EtsiTs103097Data-Signed | ✅ | E3, E5 |
| FR-SN-02 | ECDSA per 1609.2 cl. 5.3.1 | ✅ | E4, E5 |
| FR-SN-03 | hashId matches curve | ✅ | sha256 with P-256 (the only supported curve) |
| FR-SN-04 | signer digest or certificate | ✅ | `test_05`, E5 |
| FR-SN-05 | generationTime always present | ✅ | `test_05` |
| FR-SN-06 | p2pcdLearningRequest, missingCrlIdentifier absent | ✅ | `test_05` header-set assertion |
| FR-SN-07 | external payload signing | ✅ | `test_05`, E5 |
| FR-EN-01 | EncryptedData with ECIES | ✅ | `test_06`, E2, E5 |
| FR-EN-02 | AES-128-CCM, 16-byte key, 12-byte nonce | ✅ | `test_06` |
| FR-EN-03 | psk, cert and signedData recipient types | ⚠️ | `certRecipInfo` only (KD-7) |
| FR-EN-04 | unicast (one recipient) | ✅ | `test_06` conformance |
| FR-EN-05 | fresh ephemeral key per encryption | ✅ | `test_06` "Ephemeral key V is unique" |
| FR-EN-06 | ECIES decryption per Annex B.3 | ✅ | `ecies_decrypt` (tag check before unwrap); E2 |
| FR-VF-01 | certificate signature verification | ✅ | `test_03`/`test_04`/`test_09` |
| FR-VF-02 | validity per 1609.2 cl. 5.1 | ⚠️ | signature, time, issuer and profile checks; KD-5 |
| FR-VF-03 | SignedData verification with message hash reconstruction | ✅ | `verify_signed_data`; E4 |
| FR-VF-04 | Hash-ID revocation for EA/AA | ⚠️ | `check_revocation_by_hash` helper (`test_09`); no CRL format |
| FR-VF-05 | parse explicit and implicit certificates | ⚠️ | the decoder maps `reconstructionValue`; no reconstruction (KD-7) |
| FR-VF-06 | region check, 65535 = EU-27 | ✅ | `test_07`/`test_09` (AC-10) |
| FR-PM-01 | ITS-AIDs as PSID [R7] | ✅ | E3 |
| FR-PM-02 | certIssuePermissions as PsidGroupPermissions | ✅ | [DD-05](design-decisions.md#dd-05) |
| FR-PM-03…06 | AT app only; EC request signing; Root CRL/CTL + issue; EA/AA issue + response signing | ✅ | [impl §10](implementation.md#10-certificate-profiles-as-issued) |

### 7.2 Non-functional requirements

| ID | Requirement (abridged) | Status | Evidence / note |
|---|---|---|---|
| NFR-SEC-01 | private keys never in plaintext outside an HSM | ❌ | files are unencrypted PKCS#8 DER ([DD-16](design-decisions.md#dd-16)) |
| NFR-SEC-02 | CSPRNG per SP 800-90A | ⚠️ | OS/OpenSSL CSPRNG; SP 800-90A compliance of the platform not assessed |
| NFR-SEC-03 | timing side-channel resistance | ⚠️ | ECDSA/ECDH/AES in OpenSSL; tag comparison with `hmac.compare_digest`; butterfly scalar and point arithmetic in Python/tinyec is **not** constant-time ([DD-15](design-decisions.md#dd-15)) |
| NFR-SEC-04 | unique CCM nonce per encryption | ✅ | fresh random 96-bit nonce and fresh key per message; `test_06` |
| NFR-SEC-05 | AT keys independent of EC keys | ✅ | `test_04` |
| NFR-SEC-06 | AT id none | ✅ | `test_04`, `verify_at_profile` |
| NFR-INT-01 | COER for all ASN.1 structures | ✅ | E3, E5 |
| NFR-INT-02 | PICS [R8] conformance | ❌ | no PICS proforma completed (AC-13) |
| NFR-INT-03 | parse region variants | ⚠️ | KD-6 |
| NFR-INT-04 | ETSI module OID per V2.2.1 Annex A.1 | ⛔ | V1.3.1 module `{… ts(103097) v1(0)}` used ([DD-01](design-decisions.md#dd-01)) |
| NFR-INT-05 | backward compatible with V1.3.1/V1.4.1 explicit certificates | ✅ | the implementation *is* the V1.3.1 schema [R3]; V1.4.1 [R2 cl. 5.3, 6] keeps the same explicit certificate structure |
| NFR-PER-01…04 | latency / concurrency | ✅ PER-01/02/04; ⚠️ PER-03 | see 7.3; the library is not a service, so concurrency is not measured |
| NFR-REL-01…03 | availability, key backup, atomic issuance | N/A | operational properties of a deployed PKI service, not of this tool |

### 7.3 Measured performance (E9)

aarch64 VM, Python 3.13, median of 50–200 runs, 2026-09-25:

| Operation | Budget | v2 | v3 |
|---|---|---|---|
| AT issuance (NFR-PER-01) | 500 ms | 0.06 ms | 0.10 ms |
| CAM signing, P-256 (NFR-PER-02) | 10 ms | 0.03 ms | 0.06 ms |
| Chain verification AT→AA→Root (NFR-PER-04) | 50 ms | 0.27 ms | 0.27 ms |

### 7.4 Acceptance criteria

| AC | Criterion (abridged) | Status | Evidence |
|---|---|---|---|
| AC-01 | Root CA decodes and meets profile | ✅ | `test_02` "AC-01", E3 |
| AC-02 / AC-03 | EA / AA verify against Root | ✅ | `test_03` |
| AC-04 | EC verifies against EA | ✅ | `test_04` |
| AC-05 | AT verifies against AA; id none | ✅ | `test_04`, E5, E6 |
| AC-06 | CAM verifies per CAM profile | ✅ | `test_05`, E5, E6 |
| AC-07 | DENM has generationLocation and signer certificate | ✅ | `test_05`, E5 |
| AC-08 | AES-CCM + ECIES round trip | ✅ | `test_06`, E2 |
| AC-09 | implicit certificate reconstruction | ❌ | KD-7 |
| AC-10 | region 65535 = EU-27 | ✅ | `test_07`, `test_09` |
| AC-11 | cracaId/crlSeries values | ✅ | `test_02` |
| AC-12 | decodes with a conformant 1609.2 COER decoder (cross-implementation) | ✅ | E5 (Vanetza's asn1c decoder), E6, E3 (asn1tools) |
| AC-13 | PICS claims substantiated | ❌ | NFR-INT-02 |
