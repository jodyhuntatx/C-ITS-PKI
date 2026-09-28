# Design Decisions and Specification Gaps

Each entry records a place where the specifications are silent, ambiguous, unavailable to
the project, or in tension with the target platform, and the decision taken. Every entry
has four parts: **Context** (the gap, with citations), **Decision**, **Justification** and
**Consequences**. Nonconformances that are defects rather than decisions are listed
separately as [known deviations](compliance.md#6-known-deviations). References [Rn] are in
the [appendix](references.md).

| ID | Topic |
|---|---|
| [DD-01](#dd-01) | ASN.1 edition for the v3 format |
| [DD-02](#dd-02) | NIST P-256 only |
| [DD-03](#dd-03) | Codec: asn1tools with a strict canonical check |
| [DD-04](#dd-04) | COER canonical rules applied by the tool |
| [DD-05](#dd-05) | Content of certIssuePermissions |
| [DD-06](#dd-06) | v2 CA ITS-AID lists |
| [DD-07](#dd-07) | v2 AT service-specific permissions |
| [DD-08](#dd-08) | v3 appPermissions content |
| [DD-09](#dd-09) | ECIES parameter P1 |
| [DD-10](#dd-10) | Signed-and-encrypted construction |
| [DD-11](#dd-11) | Message format follows the certificate |
| [DD-12](#dd-12) | Butterfly Key Mechanism parameters |
| [DD-13](#dd-13) | Scope of an offline tool |
| [DD-14](#dd-14) | Verification of digest-signed messages |
| [DD-15](#dd-15) | Non-constant-time butterfly arithmetic |
| [DD-16](#dd-16) | Unencrypted key files |
| [DD-17](#dd-17) | Time base (UTC vs TAI) |
| [DD-18](#dd-18) | Legacy encoder modules |
| [DD-19](#dd-19) | v2 external payload on the wire |
| [DD-20](#dd-20) | Enforcing the v2 generic and CAM/DENM message profiles |

---

<a id="dd-01"></a>
## DD-01 — ASN.1 edition for the v3 format

**Context.** The PRD requires ETSI TS 103 097 V2.2.1 with the ASN.1 modules of its
Annex A: `EtsiTs103097Module` major-version-3/minor-2 and `Ieee1609Dot2`
major-version-2/minor-7 from IEEE 1609.2-2025 [R26 §5.2, §13.1], [R1 Annex A]. Those
modules are not in the repository. The target consumer, Vanetza-NAP [R24], compiles
TS 103 097 **V1.3.1** [R3] with the IEEE 1609.2-**2016** modules [R9].

**Decision.** v3 structures are encoded with the three modules vendored from Vanetza
(`src/asn1/`, identifiers and hashes in
[implementation §4.1](implementation.md#41-schema-and-codec)). The internal enum value
`EtsiVersion.V2_2_1` (`pki_meta.json` `etsi_version: 2`) is kept as the identifier of
"v3" so that existing PKI directories stay readable. Profile conformance is checked
against the V2.2.1 text [R1], whose certificate and message profiles are unchanged for
the features implemented.

**Justification.**
- **Interoperability:** the utility exists to provision Vanetza-NAP. Encoding against the
  exact schema its asn1c decoder uses makes acceptance a matter of construction (E5/E6 in
  [compliance](compliance.md#1-evidence-methods)).
- **Forward compatibility:** the ASN.1 types are extensible, and later editions add
  fields after the extension markers [R1 cl. 4.3.1]. A structure without those
  extensions is therefore a valid value of the later types.

**Consequences.**
- NFR-INT-04 (module OID) is not met.
- V2.2.1-only features are unavailable: `flags`, `appExtensions`, HeaderInfo
  `contributedExtensions`, `pduFunctionalType`, NIST P-384.
- The CLI and docs name the format "v3 (TS 103 097 V1.3.1)" to avoid implying V2.2.1
  module conformance.

<a id="dd-02"></a>
## DD-02 — NIST P-256 only

**Context.**
- TS 103 097 permits SHA-256 and SHA-384 [R1 cl. 4.2], and the PRD asks for P-384
  (FR-KG-02).
- The 1609.2-2016 schema [R9] offers only `ecdsaNistP256` and `ecdsaBrainpoolP256r1`,
  plus `ecdsaBrainpoolP384r1` as an extension. It has **no NIST P-384** verification
  key, signature or encryption key.
- TS 103 097 V1.2.1 defines only `ecdsa_nistp256_with_sha256` and `ecies_nistp256`
  [R4 cl. 4.2.2].

**Decision.** `init --algo p384` is rejected for both formats. The v3 codec raises a
clear error for any non-P-256 key. P-384 key generation remains available as a
primitive.

**Justification.** The alternative is certificates that no decoder for these schemas can
read.

**Consequences.** FR-KG-02 is partial; FR-SN-03 holds trivially (sha256 with P-256).

<a id="dd-03"></a>
## DD-03 — Codec: asn1tools with a strict canonical check

**Context.**
- TS 103 097 mandates COER [R1 cl. 4.1], [R12].
- The previous hand-written encoder mis-encoded CHOICE tags, preambles and SEQUENCE OF
  counts. Its output was rejected by Vanetza (E5).
- The asn1tools OER decoder is lenient: it "decoded" such legacy messages into
  meaningless values rather than failing.

**Decision.**
- Encode and decode with asn1tools [R27] against the vendored schema.
- Every decode re-encodes the value and requires byte identity. This applies to
  certificates, signed messages and encrypted messages.

**Justification.**
- A schema-driven codec removes a whole class of hand-coding errors.
- Because COER is canonical, "re-encodes identically" is equivalent to "was canonical
  COER". The check turns the lenient decoder into a strict validator.

**Consequences.** Non-canonical input (e.g. uncompressed points, explicitly encoded
DEFAULT values) is rejected even where a lenient receiver might accept it.

<a id="dd-04"></a>
## DD-04 — COER canonical rules applied by the tool

**Context.** X.696's canonical variant requires DEFAULT-valued components to be absent
[R12]. 1609.2 defines a canonical form for certificates with compressed points [R1 cl.
4.1]. asn1tools does not enforce either rule when encoding.

**Decision.**
- The codec omits `minChainLength = 1`, `chainLengthRange = 0` and `eeType = '00'H`
  when they have those values.
- All public keys are emitted as `compressed-y-0/1`.

**Justification.** Certificate hashes and signatures are computed over the canonical
encoding. Any other encoding breaks the HashedId8 and the signature input.

**Consequences.** Covered by E3 (byte-identical re-encode) and E5 (Vanetza decode).

<a id="dd-05"></a>
## DD-05 — Content of certIssuePermissions

**Context.** TS 103 097 requires Root CA, EA and AA certificates to carry
`certIssuePermissions` "to indicate issuing permissions" [R1 cl. 7.2.3, 7.2.4], but does
not fix the values. The previous code emitted an invalid `eeType` (`0x60`).

**Decision.**

| Issuer | subjectPermissions | minChainLength | eeType |
|---|---|---|---|
| Root CA | `all` | 2 (Root → EA/AA → EC/AT) | {app, enrol} (`0xC0`) |
| EA | `all` | 1 (default, omitted) | {enrol} (`0x40`) |
| AA | `all` | 1 (default, omitted) | {app} (`0x80`) |

`eeType` is `BIT STRING {app(0), enrol(1)} (SIZE(8))`, so bit 0 is the most significant
bit.

**Justification.**
- The chain lengths reflect the actual hierarchy.
- `eeType` separates enrolment (EA) from application (AA) end entities, which matches the
  roles in [R6].
- `all` avoids re-listing PSIDs in a test PKI.

**Consequences.** Permissions are broader than a production CPOC policy would allow.
Vanetza does not evaluate them. Restricting `subjectPermissions` to explicit PSID ranges
is a policy change, not a format change.

<a id="dd-06"></a>
## DD-06 — v2 CA ITS-AID lists

**Context.** In v2, a certificate's ITS-AIDs must be a subset of its signer's
[R4 cl. 7.4.1], and CA certificates carry an `its_aid_list` [R4 cl. 7.4.4]. The
standard does not say which AIDs a CA should list. The previous output gave the Root
only CRL/CTL and the AA only 623, so every AT chain was rejected by Vanetza.

**Decision.**
- AA: {36, 37, 141, 623}. EA: {623}. Root: {622, 617, 36, 37, 141, 623}.
- A v2 AT requesting other AIDs is refused with an explanatory error.

**Justification.**
- Each CA lists what it may issue (CAM, DENM, GeoNetworking management for beacons,
  certificate requests), plus its own service AIDs.
- Refusing early is preferable to issuing an AT that every conformant receiver rejects.

**Consequences.** Other AIDs require editing `V2_AA_AIDS`/`V2_ROOT_AIDS` in
`certificates.py`.

<a id="dd-07"></a>
## DD-07 — v2 AT service-specific permissions

**Context.**
- v2 ATs shall carry `its_aid_ssp_list` [R4 cl. 7.4.2], but SSP contents are defined by
  the application standards [R17], [R18].
- The previous plain `its_aid_list` made Vanetza reject every message
  (`Insufficient_ITS_AID`).

**Decision.**
- Always emit `its_aid_ssp_list` for ATs.
- Default SSPs are `01 00 00` (CAM) and `01 00 00 00` (DENM), i.e. SSP version 1 with no
  special permissions; other AIDs get an empty SSP. Caller-supplied SSPs take precedence.

**Justification.** These are the values Vanetza's `certify` tool uses for the same
purpose [R24 `tools/certify/commands/generate-ticket.cpp`]. They grant no special
vehicle roles, which is the safe default.

**Consequences.** ATs for special roles (emergency, roadworks, …) need explicit SSPs via
the Python API.

<a id="dd-08"></a>
## DD-08 — v3 appPermissions content

**Context.** In 1609.2, `PsidSsp.ssp` is OPTIONAL [R9]. TS 103 097 only requires
appPermissions to express signing permissions [R1 cl. 7.2.1–7.2.4].

**Decision.**
- v3 ATs list PSIDs 36/37 without SSP.
- EA, AA and EC use PSID 623 (secured certificate request [R7]) for request and
  response signing, matching the ITS-AID used by TS 102 941 [R5 cl. 6.2.3.5.2].

**Justification.** A conformant minimal encoding. Vanetza's v3 verifier accepts it (E5,
E6), and SSP policy is outside the certificate format.

**Consequences.** A receiver that enforces SSP-based roles treats these ATs as having
default (no special) permissions.

<a id="dd-09"></a>
## DD-09 — ECIES parameter P1

**Context.**
- TS 103 097 V2.2.1 Annex B specifies `KDF2(S) = SHA256(S ‖ counter ‖ P1)` but does not
  define `P1` [R1 Annex B]. Clause 5.3 defers to 1609.2 clause 5.3.5 [R1 cl. 5.3], which
  the project does not hold [R9].
- The previous code used an empty `P1` for v3.

**Decision.**
- v3 `certRecipInfo`: `P1 = SHA-256(COER(recipient certificate))`.
- v2: `P1` empty.

**Justification.**
- For certificate recipients, 1609.2 (as amended [R10]) defines `P1` as the hash of the
  recipient certificate. It uses the hash of the empty string only for `rekRecipInfo`.
  This is quoted verbatim in the independent implementation [R23]
  (`RecipientInfo.java`).
- TS 103 097 V1.2.1 states explicitly that "the parameters P1 and P2 shall be empty
  strings" [R4 cl. 5.9].
- The ECIES core (KDF2, XOR, HMAC tag) is verified against [R22].

**Consequences.** v3 ciphertexts made by the previous version cannot be decrypted (their
`P1` differs); this is intended. Using the v3 `P1` for v2, or the reverse, fails
authentication (tested in `test_06`).

<a id="dd-10"></a>
## DD-10 — Signed-and-encrypted construction

**Context.** v3 defines signed-and-encrypted as encryption of an
`EtsiTs103097Data-Signed` [R1 cl. 7.1.5]. v2 has a single payload type
`signed_and_encrypted` [R4 cl. 5.3], with a signature over the header and payload
fields (the ciphertext).

**Decision.**
- **v3:** sign, then encrypt the signed structure. Receivers decrypt, then verify.
- **v2:** one `SecuredMessage` with encryption headers, the ciphertext payload and a
  signature trailer. Receivers verify first, then decrypt.

**Justification.** Each format's own structure; in v2 the signature covers the
ciphertext, so verifying first avoids decrypting unauthenticated data.

**Consequences.** `decrypt_and_verify` behaves differently per format but returns the
same result dictionary.

<a id="dd-11"></a>
## DD-11 — Message format follows the certificate

**Context.** Previously every message used a v3-style envelope, even when signed with a
v2 AT. That combination is not defined by any standard.

**Decision.**
- The signer certificate (signing) or recipient certificate (encryption) selects the
  message format: version byte `0x02` means v2.
- `sign_and_encrypt` rejects a mix of v2 and v3 certificates.

**Justification.** A message format only makes sense with certificates of the same
standard.

**Consequences.** `sign-*` and `encrypt` need no `--etsi-version`.

<a id="dd-12"></a>
## DD-12 — Butterfly Key Mechanism parameters

**Context.** IEEE 1609.2.1 [R11] is not available to the project. TS 102 941 defers to it
for the expansion and fixes only the 16-byte expansion keys and the original/unified
options [R5 cl. 6.2.3.5.2]. Open points:

- (a) how the ACA derives the offset;
- (b) the definition of the i-period;
- (c) the range of `j`;
- (d) which option to default to;
- (e) what to store.

**Decision.**
- **(a)** A fresh uniform `r ∈ [1, n-1]` per certificate, used directly: `pk_bf = pk_cc + r·G`.
- **(b)** Default `i` = whole weeks since 2004-01-01 (`--i-value` overrides).
- **(c)** `j = 0 … count-1`.
- **(d)** Default `original`.
- **(e)** Write the caterpillar and expansion keys, the per-certificate offset `r`, and
  the reconstructed AT private key.

**Justification.**
- **(a)** The published protocol uses `h_i = r_i`, and the hash variant is only a proposed
  change [R21 Fig. 3].
- **(b)** A weekly period matches the one-week AT validity default. The expansion
  function accepts any 32-bit `i`, so the value only has to be agreed between EE and EA.
  This tool plays both.
- **(c)** Any 32-bit `j` is valid input to the verified expansion function [R22].
- **(d)** The original option is the base mechanism of [R11] and [R19]; unified [R20] is
  offered as an option.
- **(e)** Vanetza-NAP loads a private key file, so the reconstructed key is needed. The
  offset lets the key be re-derived and audited.

**Consequences.** Interoperability with a real EA/ACA also requires the protocol
messages (KD-8) and agreement on the i-period definition of [R11]. Stored reconstructed
keys are a convenience that a production ITS-S would not keep at rest.

<a id="dd-13"></a>
## DD-13 — Scope of an offline tool

**Context.** Several requirements describe runtime behaviour of an ITS-S or on-line PKI
protocols:

- CAM certificate inclusion once per second, and P2PCD `inlineP2pcdRequest` /
  `requestedCertificate` [R1 cl. 7.1.1];
- v2 `request_unrecognized_certificate` [R4 cl. 7.1];
- TS 102 941 request and response messages [R5 cl. 6.2].

**Decision.**
- The tool produces individual messages and offers both signer choices.
- It does not maintain peer state or generate receive-triggered header fields.
- Protocol messages are out of scope (KD-8).

**Justification.** These behaviours depend on what a station has received. They belong
to the ITS-S stack (Vanetza implements them), not to a certificate utility.

**Consequences.** Recorded as N/A or ❌ in [compliance](compliance.md).

<a id="dd-14"></a>
## DD-14 — Verification of digest-signed messages

**Context.** For v3 the message signature covers `Hash(signer certificate)` even when the
signer is sent as a digest [R1 cl. 5.2] → [R9 cl. 5.3.1]. A digest cannot be verified from a
public key alone.

**Decision.** `verify_signed_data(..., signer_cert_encoded=...)` requires the certificate
for digest-signed messages and checks that the digest matches it. `verify-sig` always
passes `--at-cert`.

**Justification.** This mirrors a real receiver, which resolves digests from its
certificate cache.

**Consequences.** It is an API change from earlier versions. Callers that passed only a
public key get an explicit error instead of an unverifiable result.

<a id="dd-15"></a>
## DD-15 — Non-constant-time butterfly arithmetic

**Context.** NFR-SEC-03 requires resistance to timing side channels [R26]. The `cryptography`
library does not expose EC point addition.

**Decision.** Butterfly point additions use tinyec [R29], and scalar additions use Python
integers. All ECDSA, ECDH and AES operations use OpenSSL [R28].

**Justification.**
- The point additions operate on public keys and on `f_k` values the EA can compute
  anyway.
- The private scalar additions run once per certificate, offline, on the issuing host.

**Consequences.** Not suitable for issuing on hardware exposed to timing observation.
A constant-time implementation would be needed for a production EE.

<a id="dd-16"></a>
## DD-16 — Unencrypted key files

**Context.** NFR-SEC-01 forbids plaintext private keys outside an HSM [R26]. Vanetza-NAP
loads PKCS#8 DER key files.

**Decision.** Keys are written as unencrypted PKCS#8 DER.

**Justification.** This is a test and simulation PKI whose output must be loadable by
Vanetza-NAP.

**Consequences.** NFR-SEC-01 is not met. Do not use generated keys outside test
environments.

<a id="dd-17"></a>
## DD-17 — Time base (UTC vs TAI)

**Context.** Time32 and Time64 count TAI (micro)seconds since 2004-01-01 00:00:00 UTC
[R4 cl. 4.2.14–4.2.15]. Five leap seconds have been inserted since 2004.

**Decision.** Times are computed from the UTC system clock minus the 2004 epoch, without
a leap-second offset.

**Justification.** Vanetza computes its clock the same way (`Clock::at`, epoch 2004-01-01
without a TAI offset) [R24]. Matching it keeps generation-time and validity checks
consistent in the simulation.

**Consequences.** Generated time values are 5 s lower than the strict TAI count. This is
negligible for certificate validity. For CAM freshness windows (2 s), it matters only
against receivers that apply TAI correctly; this could be changed by adding the TAI−UTC
offset.

<a id="dd-18"></a>
## DD-18 — Legacy encoder modules

**Context.** `src/coer.py`, `src/encoding/keys.py` and `src/encoding/permissions.py` are
the original hand-written encoder. Their CHOICE (raw index) and PSID encodings are not
COER [R12].

**Decision.** They are no longer used to produce any output. They are kept only because
legacy unit tests in `test_08` still exercise them.

**Justification.** Removing them is a separate clean-up that does not change behaviour.

**Consequences.** Do not use them for new code. They should be removed together with
their tests.

<a id="dd-19"></a>
## DD-19 — v2 external payload on the wire

**Context.** TS 103 097 V1.2.1 defines `Payload` with `case signed_external: ;`, i.e. no
data field, and says the external data "shall be included when calculating the signature,
at the position where a non-external payload would be" [R4 cl. 5.2]. It does not say
whether a length field is still transmitted. Vanetza's serializer and parser always
write and read a length for every payload type [R24 `v2/payload.cpp`].

**Decision.**
- On the wire, a `signed_external` payload is the type byte followed by a zero-length data
  vector (`03 00`).
- The signing input replaces it with `03 ‖ length ‖ external data`, exactly as a signed
  payload would appear.
- The "external data" is the 32-byte value the caller passes to
  `sign_data_external_payload` (a SHA-256 hash, which keeps the API identical to v3's
  `extDataHash`).
- `verify_signed_data` requires the same value as `external_payload_hash` and rejects a
  `signed_external` message that carries data.

**Justification.**
- A zero-length vector transmits no payload data, which satisfies clause 5.2.
- It is also what Vanetza itself produces and parses for an empty payload. Omitting the
  length byte would make Vanetza's parser read the trailer as the payload length.

**Consequences.**
- Receivers must obtain the external data out of band; this is inherent to the payload
  type.
- Vanetza's v2 verifier does not verify `signed_external` at all (it returns
  `Unsigned_Message`), so only its parser is exercised (E5).

<a id="dd-20"></a>
## DD-20 — Enforcing the v2 generic and CAM/DENM message profiles

**Context.** TS 103 097 V1.2.1 requires generic signed messages (ITS-AIDs other than CAM/DENM)
to use a `certificate` signer and a `generation_location` header [R4 cl. 7.3]. It requires
CAM and DENM payloads to be of type `signed` and states that they "shall not be encrypted"
[R4 cl. 7.1, 7.2]. The API previously allowed any combination.

**Decision.**
- For v2 ITS-AIDs other than 36/37:
  - `sign_data`, `sign_data_external_payload` and `sign_and_encrypt` always use the
    certificate as signer (overriding `use_digest`);
  - they raise `ValueError` if `generation_location` is missing.
- For ITS-AIDs 36/37, v2 external-payload and signed-and-encrypted messages are refused.
- CAM/DENM signing (`sign_cam`, `sign_denm`) is unchanged.
- The v3 path is unaffected, because TS 103 097 V2.2.1's generic profile does not impose
  these constraints [R1 cl. 7.1.3–7.1.5].

**Justification.**
- The signer choice has only one valid value, so forcing it cannot produce a
  nonconformant message.
- A missing location cannot be invented, so it is an error.
- Refusing CAM/DENM encryption follows the "shall not" of the profile.

**Consequences.** `sign_and_encrypt` and `sign_data_external_payload` gained a
`generation_location` parameter. v2 callers must pass it, and must use a generic ITS-AID
(for example 623) for encrypted or external-payload messages.

