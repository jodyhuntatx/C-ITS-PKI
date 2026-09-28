# Vanetza v2 Certificate Permission Structure (informative)

How Vanetza's `security/v2` module [R24] represents and checks certificate permissions
for ETSI TS 103 097 V1.2.1 [R4]. This is background for
[DD-06](design-decisions.md#dd-06), [DD-07](design-decisions.md#dd-07) and
[KD-1/KD-2](compliance.md#62-resolved) (now resolved). Source references are to
`vanetza-nap/vanetza/security/` (release2) and name functions rather than line numbers.

## 1. Certificate chain

```
Root CA (signer_info = self, held in the TrustStore)
  └── Authorization Authority (signer_info = certificate_digest_with_sha256)
        └── Authorization Ticket (signer_info = certificate_digest_with_sha256)
```

- **TS 103 097 V1.2.1:** requires `self` for root CAs and
  `certificate_digest_with_sha256` for other CAs [R4 cl. 7.4.4] and for ATs and ECs
  [R4 cl. 7.4.2, 7.4.3].
- **Vanetza** (`v2/default_certificate_validator.cpp`, `check_certificate`):
  - ATs are verified only against AAs found in the certificate cache;
  - AAs are verified only against root certificates in the trust store.
- **Caveat:** AAs supplied to socktap with `--certificate-chain` go straight into the
  cache. Vanetza therefore does not check them against the trust store, and a
  wrong-root configuration is not detected at runtime for v2. The vnap-secure startup
  diagnostic `[V2-CHAIN]` reports it.

## 2. Subject attributes

The attribute types [R4 cl. 6.4, 6.5], mirrored in `v2/subject_attribute.hpp`:

| Type | Value | Content |
|---|---|---|
| `verification_key` | 0 | ECDSA public key |
| `encryption_key` | 1 | ECIES public key (EA/AA) |
| `assurance_level` | 2 | `SubjectAssurance`: bits 7–5 level, bits 1–0 confidence [R4 cl. 6.6] |
| `reconstruction_value` | 3 | ECC point (implicit certificates) |
| `its_aid_list` | 32 | ITS-AIDs without SSP: CA certificates [R4 cl. 7.4.4] |
| `its_aid_ssp_list` | 33 | ITS-AIDs with service-specific permissions: ATs and ECs [R4 cl. 7.4.2, 7.4.3] |

`its_aid_list` entries are interpreted as all possible SSPs of that AID [R4 cl. 7.4.1].

## 3. SSPs

Each `ItsAidSsp` pairs an ITS-AID with an opaque SSP byte string [R4 cl. 6.9]. SSP
contents are defined by the application standards. For CAMs [R17], Vanetza's
`security/cam_ssp.hpp` decodes the first byte as role flags:

- CEN DSRC tolling zone 0x80
- public transport 0x40
- special transport 0x20
- dangerous goods 0x10
- roadwork 0x08
- rescue 0x04
- emergency 0x02
- safety car 0x01

The next byte carries further flags (closed lanes, right of way, …).

The C-ITS-PKI tool writes SSP version 1 with no special permissions by default
([DD-07](design-decisions.md#dd-07)).

**Message permissions** (`straight_verify_service.cpp`, `assign_permissions`): Vanetza
takes the permissions for a received message **only from `its_aid_ssp_list`**. If the
signer's AT has no `its_aid_ssp_list` entry for the message's AID, the message is
rejected as `Invalid_Certificate` (`Insufficient_ITS_AID`).

## 4. Consistency with the signer

`check_consistency` (`v2/default_certificate_validator.cpp`) applies the checks of
[R4 cl. 7.4.1] between a certificate and its signer:

| Check | Function | Rule |
|---|---|---|
| Time | `check_time_consistency` | validity within the signer's |
| Permissions | `check_permission_consistency` | the certificate's AIDs ⊆ the signer's AIDs |
| Assurance | `check_subject_assurance_consistency` | level ≤ the signer's level |
| Region | `check_region_consistency` | region covered by the signer's |

**Assurance level.**
- TS 103 097 V1.2.1 requires `assurance_level` in every certificate, default 0
  [R4 cl. 7.4.1].
- Stock Vanetza rejects certificates without it (`Missing_Subject_Assurance`), and the
  consistency check fails when either certificate lacks it.
- The vnap-secure patch #4 makes the attribute optional. Since
  [KD-1](compliance.md#62-resolved) was fixed, C-ITS-PKI v2 certificates carry
  `assurance_level` 0 and no longer need the patch (verified with stock Vanetza, E10).
