# Privacy and Deployment Notes (informative)

Background analysis collected during development. This page is **informative**: it
explains what the implemented mechanisms do and do not protect, and lists deployment
questions the standards leave open. Normative behaviour is in
[implementation](implementation.md) and [compliance](compliance.md). References [Rn] are
in the [appendix](references.md).

---

## 1. What the Butterfly Key Mechanism and split authorities provide

### 1.1 Split EA / AA

The C-ITS trust model separates the Enrolment Authority, which knows the station
identity through its EC, from the Authorization Authority, which issues ATs [R6], [R5].

- The AA never sees the EC, so it cannot link ATs to the station's identity.
- The EA does not learn which ATs were issued, and never sees V2X messages signed with
  them.

### 1.2 Butterfly Key Mechanism (IEEE 1609.2.1)

The mechanism is described in [R11], [R21 §1, §3.3] and
[implementation §8](implementation.md#8-butterfly-key-mechanism).

| Party | Sees | Cannot |
|---|---|---|
| EA / RA | caterpillar public key(s) and expansion key(s), so it can compute every **cocoon** key | recognise the certified **butterfly** keys, because the AA adds a secret random offset `r` to each |
| AA / ACA | shuffled cocoon keys from many requests | link a cocoon key to a vehicle or to other cocoon keys from the same request |
| Observer | ATs with independent-looking public keys | link ATs of a batch cryptographically |

### 1.3 What they do not protect against

| Threat | Mitigated by BKM / split CAs? | Comment |
|---|---|---|
| EA and AA collusion | ❌ | together, the EA (cocoon keys) and the AA (offsets `r`) can link every AT to the request, and so to the EC. The separation is organisational, not cryptographic. |
| Reuse of a caterpillar key and expansion key across requests | ❌ | the same `(A, k, i, j)` yields the same cocoon keys, so the EA can link the requests. The tool generates fresh caterpillar and expansion keys on every `butterfly-at` run [R5 cl. 6.2.3.5.2]. |
| Radio or network identifiers (MAC, IP) unchanged across AT changes | ❌ | AT changes must be coordinated with identifier changes in the ITS-S stack. The vnap-secure notes point out that pseudonym rotation alone does not change the GeoNetworking or MAC address. |
| Correlation through message content (position, timing) | ❌ | application-layer issue |
| When to change ATs | ❌ | the standards do not fix a change strategy (section 2) |
| Misbehaviour detection versus unlinkability | — | revocation needs some linkability; this tool implements neither CRLs nor linkage values |

## 2. Deployment parameters left open by the standards

TS 102 941 V2.2.1 defines the butterfly provisioning flow, but does not fix the batch
size, the AT change strategy or the i-period length [R5 cl. 6.2.3.5]. TS 103 097 fixes
no AT lifetime [R1 cl. 7.2.1]. The tool's defaults are choices, not requirements:

| Parameter | Tool default | Basis |
|---|---|---|
| AT validity | 168 h (1 week) | project choice (PRD examples [R26]) |
| Butterfly batch size | 8 (`--count`) | project choice for simulations |
| i-period | weeks since 2004-01-01 | [DD-12](design-decisions.md#dd-12) |
| Caterpillar and expansion keys | fresh per batch | [R5 cl. 6.2.3.5.2] ("for each butterfly authorization request … a new caterpillar key pair") |

> **Unverified guidance.** Earlier project notes cited specific values: batches of
> 20–40 ATs, and change strategies combining time, distance, silence periods and MAC
> rotation, attributed to CAMP/SCMS reports, the PRESERVE project and ETSI TR 103 415.
> These sources were not available to the project and the values have not been
> checked. Treat them as leads for further reading, not as requirements.

## 3. Validating output with external tools

| Tool | Validates | Used in this project |
|---|---|---|
| Vanetza-NAP `vnap-msgcheck` [R30] | v2 and v3 message parsing and verification with Vanetza's security stack, including full-chain v3 | yes (E5) |
| Vanetza-NAP simulation [R30] | end-to-end CAM exchange with tool certificates | yes (E6) |
| Vanetza `certify show-certificate` [R24] | v2 certificate parsing | yes (E8) |
| asn1tools against the vendored schema [R27] | v3 COER conformance | yes (E3) |
| ETSI Plugtests conformance tools, commercial ITS security test suites | TS 103 097 conformance (PICS [R8]) | not evaluated (not publicly available) |
| USDOT/NIST 1609.2 tooling | IEEE 1609.2 structures | not evaluated; ETSI profiles and PSIDs differ from North American ones |
