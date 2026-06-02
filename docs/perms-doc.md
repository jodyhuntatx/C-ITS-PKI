# Certificate Permission Structure — vanetza-nap/vanetza/security

Certificates implement the **ETSI TS 103 097 v1.2.1** standard for V2X (Vehicle-to-Everything) security. Permissions flow through a 3-layer hierarchy.

## 1. The Three-Tier Certificate Chain

```
Root CA (self-signed, in TrustStore)
  └── Authorization Authority (AA)
        └── Authorization Ticket (AT)  ← what a vehicle actually uses
```

- **Root CAs** sign Authorization Authorities and live in the `TrustStore`.
- **Authorization Authorities** sign Authorization Tickets.
- **Authorization Tickets (ATs)** are the end-entity certs carried in signed V2X messages.

Validation is enforced in `default_certificate_validator.cpp:220-254` — ATs can only be verified by AAs, and AAs only by root CAs.

---

## 2. Subject Attributes — Where Permissions Live

Defined in `subject_attribute.hpp:44-52`, a certificate's `subject_attributes` list holds one or more of:

| Type | Enum value | Content |
|---|---|---|
| `Verification_Key` | 0 | ECDSA public key for signature verification |
| `Encryption_Key` | 1 | Public key for encryption |
| `Assurance_Level` | 2 | `SubjectAssurance` — trust level |
| `Reconstruction_Value` | 3 | ECC point (for implicit certs) |
| **`ITS_AID_List`** | **32** | List of allowed ITS Application IDs (no SSP) |
| **`ITS_AID_SSP_List`** | **33** | List of ITS AIDs + Service Specific Permissions |

The key permission-carrying attributes are `ITS_AID_List` (used by AAs) and `ITS_AID_SSP_List` (used by ATs).

---

## 3. ITS-AID and Service Specific Permissions (SSP)

Each `ItsAidSsp` (`subject_attribute.hpp:38-42`) pairs:
- **`its_aid`** — a numeric application ID (e.g., 36 for CAM, 37 for DENM)
- **`service_specific_permissions`** — a raw `ByteBuffer` of permission bits

For CAM specifically (`cam_ssp.hpp`), the SSP is a 2-byte bitmask of role flags:

```
First byte:   CEN_DSRC_Tolling_Zone (0x80), Public_Transport (0x40),
              Special_Transport (0x20), Dangerous_Goods (0x10),
              Roadwork (0x08), Rescue (0x04), Emergency (0x02), Safety_Car (0x01)

Second byte:  Closed_Lanes (0x8000), Request_For_Right_Of_Way (0x4000),
              Request_For_Free_Crossing_At_Traffic_Light (0x2000),
              No_Passing (0x1000), No_Passing_For_Trucks (0x0800), Speed_Limit (0x0400)
```

Permissions are added to a certificate via `certificate.cpp:226-251` (`Certificate::add_permission`), which appends to either the `ITS_AID_List` or `ITS_AID_SSP_List` attribute.

---

## 4. Permission Inheritance (the Key Constraint)

When validating, `check_permission_consistency()` (`default_certificate_validator.cpp:97-107`) enforces that **a certificate's AIDs must be a subset of its signer's AIDs**:

```cpp
return std::includes(signer_aids.begin(), signer_aids.end(),
                     certificate_aids.begin(), certificate_aids.end());
```

So an AA can only grant an AT permission for services the AA itself was authorized for. This is the downward delegation constraint — permissions can only narrow, never expand, down the chain.

---

## 5. Assurance Level (Trust Level)

`SubjectAssurance` (`subject_attribute.hpp:17-35`) is a single byte split into:
- **`assurance`** — 3 bits (bits 7–5): trust level 0–7
- **`confidence`** — 2 bits (bits 1–0): confidence in that level

The validator (`default_certificate_validator.cpp:109-129`) enforces that an AT's assurance level cannot exceed its signing AA's level. If either cert omits the field, the check passes (it's optional per TS 103 096-2).
