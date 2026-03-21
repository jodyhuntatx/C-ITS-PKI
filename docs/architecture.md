# C-ITS PKI System Architecture

## 1. Overview

The C-ITS PKI implementation follows the three-tier trust hierarchy mandated by ETSI TS 103 097 V2.2.1 and IEEE Std 1609.2-2025. All certificates are encoded in the `EtsiTs103097Certificate` format using COER (Canonical Octet Encoding Rules per ITU-T X.696).

---

## 2. PKI Hierarchy

```
                    ┌──────────────────┐
                    │  Trust List Mgr  │ ← self-signed (Profile 9.4)
                    │  (TLM Cert)      │   appPerms: CTL ITS-AID
                    └──────────────────┘

                    ┌──────────────────┐
                    │    Root CA       │ ← self-signed (Profile 9.1)
                    │ (trust anchor)   │   certIssuePerms: all
                    └────────┬─────────┘   appPerms: CRL + CTL

               ┌────────────┴───────────┐
               ▼                        ▼
  ┌────────────────────┐   ┌────────────────────┐
  │  Enrolment         │   │  Authorization     │
  │  Authority (EA)    │   │  Authority (AA)    │
  │  Profile 9.2       │   │  Profile 9.3       │
  │  + encryptionKey   │   │  + encryptionKey   │
  └─────────┬──────────┘   └──────────┬─────────┘
            │                          │
            ▼                          ▼
  ┌────────────────────┐   ┌────────────────────┐
  │  Enrolment         │   │  Authorization     │
  │  Credential (EC)   │   │  Ticket (AT)       │
  │  Profile 9.5       │   │  Profile 9.6       │
  │  id = name         │   │  id = none (anon)  │
  │  appPerms: SCR     │   │  appPerms: CAM+DENM│
  └────────────────────┘   └────────────────────┘
           ITS-Station               ITS-Station
```

---

## 3. Module Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                           cli.py                                   │
│              Command-line interface (all PKI operations)           │
└────────────────────────────┬───────────────────────────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
┌────────────────┐  ┌────────────────┐  ┌────────────────┐
│    pki.py      │  │   signing.py   │  │ encryption.py  │
│ PKI Hierarchy  │  │ EtsiTs103097   │  │ ECIES +        │
│ Manager        │  │ Data-Signed    │  │ AES-128-CCM    │
└───────┬────────┘  └───────┬────────┘  └───────┬────────┘
        │                   │                    │
        ▼                   ▼                    ▼
┌────────────────────────────────────────────────────────┐
│                    certificates.py                     │
│         Certificate Issuance (Profiles 9.1–9.6)       │
└────────────────────┬───────────────────────────────────┘
                     │
         ┌───────────┼──────────────┐
         ▼           ▼              ▼
┌──────────────┐ ┌──────────┐ ┌──────────────────┐
│  encoding.py │ │ coer.py  │ │  verification.py │
│ Cert COER    │ │ COER     │ │ Certificate Chain│
│ Encode/Decode│ │Primitives│ │ Verification     │
└──────────────┘ └──────────┘ └──────────────────┘
         │                              │
         ▼                              ▼
┌──────────────────────────────────────────────────┐
│                   types.py                       │
│    ASN.1 data structure dataclasses and enums    │
└──────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────┐
│                   crypto.py                      │
│  ECDSA P-256/P-384 · AES-128-CCM · ECIES · KDF2 │
│  (uses Python `cryptography` library)            │
└──────────────────────────────────────────────────┘
```

---

## 4. Data Structure Mapping

### 4.1 EtsiTs103097Certificate (COER encoding)

```
Byte layout:
┌─────────┬──────────┬────────────────────┬─────────────────────────┬───────────┐
│ version │   type   │      issuer        │       toBeSigned        │ signature │
│  0x03   │  0x00=ex │  CHOICE (1+8 or   │  id + cracaId +         │ OPTIONAL  │
│  1 byte │  1 byte  │  1+1 for self)     │  crlSeries + validity + │ (bitmap+  │
│         │          │                    │  bitmap + opt fields +  │  r + s)   │
│         │          │                    │  verifyKeyIndicator     │           │
└─────────┴──────────┴────────────────────┴─────────────────────────┴───────────┘
```

### 4.2 IssuerIdentifier CHOICE encoding

| Value | Tag byte | Content |
|---|---|---|
| sha256AndDigest | `0x00` | 8-byte HashedId8 |
| self | `0x01` | 1-byte HashAlgorithm (0=sha256, 1=sha384) |
| sha384AndDigest | `0x02` | 8-byte HashedId8 |

### 4.3 ToBeSignedCertificate optional fields (2-byte bitmap)

```
Bit 15 (MSB): region
Bit 14:       assuranceLevel
Bit 13:       appPermissions
Bit 12:       certIssuePermissions
Bit 11:       certRequestPermissions (always 0)
Bit 10:       canRequestRollover (always 0)
Bit  9:       encryptionKey
Bits 8–0:     reserved (0)
```

### 4.4 PSID Variable-Length Encoding

| Range | Bytes | Format |
|---|---|---|
| 0–0x7F | 1 | `bbbbbbbb` |
| 0x80–0x3FFF | 2 | `10bbbbbb bbbbbbbb` |
| 0x4000–0x1FFFFF | 3 | `110bbbbb bbbbbbbb bbbbbbbb` |
| 0x200000–0xFFFFFFF | 4 | `1110bbbb bbbbbbbb bbbbbbbb bbbbbbbb` |

---

## 5. Cryptographic Design

### 5.1 ECDSA Signing (IEEE 1609.2 §5.3.1)

```
TBS = COER(ToBeSignedCertificate)  or  COER(ToBeSignedData)
     ↓
hash = SHA-256(TBS)   [or SHA-384 for P-384]
     ↓
(r, s) = ECDSA_sign(private_key, TBS)
     ↓
Signature { EccP256CurvePoint(r.x), s }
```

Note: IEEE 1609.2 stores `r` as the x-coordinate only (x-only form), not the full point.

### 5.2 ECIES Key Encapsulation (IEEE 1609.2 §5.3.5)

```
Sender:
  r ←$ [1, q-1]         (random ephemeral private key)
  V = r·G                (ephemeral public key, 33 bytes compressed)
  S = Px where (Px,Py) = r·Kr   (ECDH shared secret x-coordinate)
  (ke ‖ km) = KDF2(S)   (16 bytes ke + 32 bytes km)
  c = A ⊕ ke             (XOR encrypt AES-128 key A)
  t = HMAC-SHA256(c, km)[:16]  (16-byte authentication tag)
  → transmit: V, c, t

Receiver:
  S = Px where (Px,Py) = kr·V   (ECDH with own private key kr)
  (ke ‖ km) = KDF2(S)
  verify: t == HMAC-SHA256(c, km)[:16]
  A = c ⊕ ke             (recover AES-128 key)
```

### 5.3 KDF2 (IEEE 1609.2)

```
KDF2(S, P1=''):
  H1 = SHA-256(S ‖ 0x00000001 ‖ P1)
  H2 = SHA-256(S ‖ 0x00000002 ‖ P1)
  return (H1 ‖ H2)[:48]   → ke (16 bytes) ‖ km (32 bytes)
```

### 5.4 AES-128-CCM Encryption (IEEE 1609.2 §5.3.8)

```
key A: 16 bytes (random per operation)
nonce n: 12 bytes (random per operation — NFR-SEC-04)
tag length: 16 bytes
ciphertext = AES-128-CCM(A, n, plaintext)  → ciphertext ‖ 16-byte auth tag
```

---

## 6. Certificate Validity Periods

| Entity | Default Validity | Duration Encoding |
|---|---|---|
| Root CA | 10 years | `DurationChoice.YEARS, 10` |
| TLM | 10 years | `DurationChoice.YEARS, 10` |
| EA | 5 years | `DurationChoice.YEARS, 5` |
| AA | 5 years | `DurationChoice.YEARS, 5` |
| EC | 1 year | `DurationChoice.YEARS, 1` |
| AT | 168 hours (1 week) | `DurationChoice.HOURS, 168` |

Time base: **2004-01-01T00:00:00Z** (IEEE 1609.2 Time32 epoch).
Unix timestamp of epoch: `1072915200`.

---

## 7. Message Security Profiles

### 7.1 CAM (Profile 10.1)

```
EtsiTs103097Data-Signed {
  hashId: sha256
  tbsData {
    payload { data: EtsiTs103097Data-Unsecured { cam_payload } }
    headerInfo {
      psid: 36 (CAM ITS-AID)
      generationTime: <Time64>      ← ALWAYS present
    }
  }
  signer: digest(AT_cert)           ← default; full cert 1x/second
  signature: ECDSA-P256
}
```

### 7.2 DENM (Profile 10.2)

```
EtsiTs103097Data-Signed {
  hashId: sha256
  tbsData {
    payload { data: EtsiTs103097Data-Unsecured { denm_payload } }
    headerInfo {
      psid: 37 (DENM ITS-AID)
      generationTime: <Time64>      ← ALWAYS present
      generationLocation: <lat,lon,elev>  ← ALWAYS present
    }
  }
  signer: certificate(AT_cert)      ← ALWAYS full certificate
  signature: ECDSA-P256
}
```

### 7.3 Encrypted Message (Profile 10.4)

```
EtsiTs103097Data-Encrypted {
  recipients: [
    certRecipInfo {
      recipientId: HashedId8(recipient_cert)
      encKey: eciesNistP256EncryptedKey { V, c, t }
    }
  ]
  ciphertext: aes128ccm { nonce, AES-CCM(plaintext) }
}
```

---

## 8. Acceptance Criteria Implementation Status

| AC ID | Criterion | Status |
|---|---|---|
| AC-01 | Root CA passes COER decode + profile 9.1 | ✅ `test_02_root_ca.sh` |
| AC-02 | EA verifiable against Root CA | ✅ `test_03_ea_aa_certs.sh` |
| AC-03 | AA verifiable against Root CA | ✅ `test_03_ea_aa_certs.sh` |
| AC-04 | EC verifiable against EA | ✅ `test_04_tlm_ec_at.sh` |
| AC-05 | AT verifiable against AA; id=none | ✅ `test_04_tlm_ec_at.sh` |
| AC-06 | CAM signed with AT passes verification | ✅ `test_05_signing.sh` |
| AC-07 | DENM includes generationLocation + signer=cert | ✅ `test_05_signing.sh` |
| AC-08 | AES-CCM encrypted message decrypts with ECIES | ✅ `test_06_encryption.sh` |
| AC-09 | Implicit cert reconstruction | ⚠️ Parsing supported; reconstruction partial |
| AC-10 | Region 65535 accepted as EU-27 | ✅ `test_07_pki_init.sh` |
| AC-11 | cracaId=000000H, crlSeries=0 | ✅ `test_02_root_ca.sh` |
| AC-12 | Structures decode without error | ✅ `test_08_coer_encoding.sh` |
| AC-13 | PICS conformance review | ⚠️ Manual review required |

---

## 9. Functional Requirements Coverage

| FR ID | Requirement | Module |
|---|---|---|
| FR-KG-01..05 | Key pair generation | `crypto.py` |
| FR-CI-01..11 | Certificate issuance | `certificates.py`, `encoding.py` |
| FR-SN-01..07 | Signing operations | `signing.py` |
| FR-EN-01..06 | Encryption operations | `encryption.py`, `crypto.py` |
| FR-VF-01..06 | Certificate verification | `verification.py` |
| FR-PM-01..06 | Permissions management | `certificates.py`, `types.py` |

---

## 10. Dependencies

| Package | Version | Purpose |
|---|---|---|
| `cryptography` | ≥ 42.0.0 | ECDSA, AES-CCM, ECDH, key serialization |

No external ASN.1 compiler or IEEE 1609.2 library is required. COER encoding is implemented natively in `coer.py` and `encoding.py`.
