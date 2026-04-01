***Does BKE and split intermediate CAs ensure privacy and untrackability?***

Not on their own — they are necessary but not sufficient. Here's a precise breakdown of what each mechanism actually protects against, and what gaps remain.

---

### **What BKE provides**


**Unlinkability between ATs in a batch.** The AA sees only the caterpillar public key `Cf` and the expansion values `{eᵢ}`. It cannot link the N issued AT certificates to each other without also knowing `f`, because each derived public key `Sᵢ = Cf + H(Cf‖eᵢ)·G` looks like an independent random key to any outside observer. Crucially, the AA itself cannot correlate the ATs it just issued to future messages signed with them — it never sees the private keys.


**Unlinkability between the EC and the ATs.** The AA only receives the caterpillar key from the EA (via a privacy-preserving protocol), not the EC directly. The vehicle's long-term identity is never exposed to the AA.


**What BKE does not fix on its own:**


* If a vehicle uses the *same caterpillar key* across multiple batch requests to the same AA, the AA can link all those batches together. Caterpillar keys need to be rotated regularly.  
* The AT certificates themselves, once issued, are pseudonymous but not anonymous. Any observer who sees you sign two different messages with two ATs from the same batch cannot link them *cryptographically*, but if the messages carry other identifying information (GPS coordinates, timing, payload structure) they can be correlated at the application layer.  
* BKE says nothing about *when* you switch ATs. If a vehicle uses one AT for a long time before rotating to the next, it is trackable for that entire period regardless of how the AT was issued.

---

### **What split intermediate CAs provide**

The ETSI architecture separates the EA (which knows your identity and issues your EC) from the AA (which issues your ATs). This means:

* The AA never learns your real identity — it only sees a caterpillar key vouched for by the EA.  
* The EA never learns which ATs you were issued or what V2X messages you signed.  
* No single entity holds both pieces of information simultaneously.

**What split CAs do not fix:**

* **Collusion.** If the EA and AA share data, the entire pseudonymity model collapses. The architecture assumes they are operated by different organisations with a legal barrier between them, but this is an organisational control, not a cryptographic one.  
* **The EA still tracks you.** The EA knows your real identity and when you requested credentials. It can observe the pattern of your EC renewals over time.  
* **The Root CA is a single point of trust.** It signed both the EA and AA certificates. A compromised Root CA undermines everything.

---

### **The remaining gaps neither mechanism addresses**

| Threat | BKE | Split CAs | Still vulnerable? |
| ----- | :---: | :---: | ----- |
| AA linking ATs in a batch | ✅ Prevented | — | No |
| AA linking batches over time | ⚠️ Only if caterpillar key rotated | — | Yes, if rotation lapses |
| Radio-layer tracking (constant MAC/IP) | ❌ | ❌ | Yes |
| Application-layer correlation (GPS, timing) | ❌ | ❌ | Yes |
| AT switching strategy (when to rotate) | ❌ | ❌ | Yes |
| EA/AA collusion | — | ⚠️ Org. barrier only | Yes |
| Misbehaviour detection vs. privacy tension | ❌ | ❌ | Yes — inherent tradeoff |

The radio-layer point is particularly important in practice: if your vehicle's Wi-Fi/DSRC MAC address or IP stays constant, an observer can track you regardless of how many different ATs you use. AT rotation needs to be coordinated with MAC address randomisation and happen at moments that don't themselves become a fingerprint (e.g. not always at the same speed or location).

The misbehaviour detection tension is a fundamental one: the system needs enough linkability to revoke a misbehaving vehicle, but full unlinkability would make revocation impossible. ETSI TS 102 941 addresses this with pseudonym linking tokens that only a Misbehaviour Authority can resolve — but that authority then becomes another privacy-sensitive trust point.

So in summary: BKE \+ split CAs give you solid *cryptographic* unlinkability at the PKI layer, but full untrackability requires coordinated AT rotation policy, MAC randomisation, and careful application-layer design on top.

---

***With BKE is there a need for an expansion key and signing key for every certificate?***

No — that's actually one of the key privacy advantages of BKE.

In the current non-BKE `issue_authorization_ticket` flow, each AT gets its own independently generated key pair. With BKE the situation is different for each role:

**Vehicle side:** Only the single caterpillar private key `f` needs to be stored. All N AT private keys are derived on demand from `f` and the stored expansion values — `sᵢ = (f + H(Cf‖eᵢ)) mod n` — so they don't need to be saved at all. The current `cmd_butterfly_at` saves them as a convenience, but in a real ITS-Station implementation you'd re-derive each `sᵢ` from `f` and `eᵢ` at the moment you need to sign a message.

**AA side:** The AA never holds any AT private keys, BKE or otherwise. It derives each AT public key `Sᵢ = Cf + H(Cf‖eᵢ)·G` from the caterpillar public key alone, signs the certificate, and discards the intermediate values. Nothing extra needs to be stored.

So the minimal storage per batch is:

| Item | Who holds it | Why |
| ----- | ----- | ----- |
| Caterpillar private key `f` | Vehicle | Re-derive any AT private key |
| Expansion values `{eᵢ}` | Vehicle | Re-derive specific AT private keys; link cert to key |
| AT certificates `{ATᵢ}` | Vehicle | Present when signing messages |

The `.expansion` files that the current code saves to disk are therefore the important ones — without `eᵢ` you can't re-derive `sᵢ` even if you have `f`. 

The signing key files (e.g. `bke_at_N_sign.key)` are redundant and in a production implementation would not be written to disk at all, since storing derived private keys defeats part of the purpose of BKE (minimising key material at rest).

Expansion key size: 	16 bytes  
Certificate/AuthTicket: 	133 bytes  
	149 bytes/ticket

Or at 1000 tickets/month, \~14K per month

---

**Regarding BKE, have there been any formal or informal best practices been established regarding:**

* **caterpillar key rotation**  
* **how many ATs should be generated per batch**  
* **the change frequency of V2X Authorization Tickets (ATs)**

There are no single definitive standards documents that prescribe exact numbers, but there is meaningful guidance spread across ETSI, IEEE, and academic research. The North American SCMS (now standardised under IEEE 1609.2.1) is currently the most operationally mature deployment and is the closest thing to a reference implementation for these parameters. The European C-ITS system under ETSI has the architecture right but has been slower to converge on specific operational values, partly because member states have wanted flexibility in their own deployments.

Here's what has emerged:

| Parameter | Settled guidance | Source |
| ----- | ----- | ----- |
| AT validity period | \~1 week | ETSI TS 102 941 / codebase default |
| AT change trigger | Time \+ distance \+ silence period \+ MAC rotation | ETSI TR 103 415, PRESERVE project |
| Batch size | 20–40 ATs | CAMP VSC3 / SCMS design docs |
| Caterpillar key lifetime | One key per batch request | IEEE 1609.2.1-2022 implicit model; Whyte et al. |

### **AT Change Frequency**

This is the most settled area. The dominant guidance comes from ETSI TS 102 941 and supporting research:

**ETSI guidance** is deliberately non-prescriptive about exact intervals but the reference implementation and associated technical reports consistently use **pseudonym lifetimes of around 1 week** — which is why the default validity\_hours=168 appears throughout this codebase. The rationale is that shorter lifetimes create more revocation overhead; longer lifetimes create larger tracking windows.

**The more important question is *when* to switch**, not how long the certificate lasts. Research (notably from the PRESERVE and CAMP projects) converged on what is called the **"silence period"** or **"change strategy"**: a vehicle should stop transmitting V2X messages briefly during the AT switch, and ideally coordinate the switch with a change of MAC address, a change of IP address, and a moment when the vehicle is not uniquely identifiable by context (e.g. not the only vehicle at an intersection). Switching ATs without a silence period largely defeats the privacy benefit because an observer can simply correlate the last message from the old AT with the first message from the new one.

ETSI TR 103 415 (Privacy in ITS) elaborates on this, suggesting change events should be:

* Triggered by time *and* distance travelled, not time alone  
* Coordinated with layer-2 identifier changes  
* Performed during moments of high vehicle density where possible

---

### **Batch Size**

Less formally standardised, but several reference points exist:

**ETSI TS 102 941** describes the AT provisioning protocol but does not mandate a batch size. The implicit assumption in the protocol design is that a vehicle requests a batch covering its **next validity period** — typically enough ATs to last until the next scheduled provisioning contact, with some overlap for reliability.

**Practical guidance from CAMP (Crash Avoidance Metrics Partnership)** and the US SCMS (Security Credential Management System) design documents suggests batches of **20–40 ATs** are typical, covering roughly a week of driving if each AT is used for a few hours. The US SCMS butterfly key work (Whyte et al., 2013 and the follow-on CAMP VSC3 reports) specifically modelled batches of this size.

**The tradeoff being managed:**

* Too few ATs per batch → more frequent contact with the AA → the AA sees more provisioning events → more linkability risk  
* Too many ATs per batch → large key material stored on the vehicle → if the vehicle is compromised, more ATs can be abused before revocation takes effect

A secondary consideration is that each AT in a BKE batch shares the same caterpillar key, so a larger batch increases the exposure window if the caterpillar key is ever compromised.

---

### **Caterpillar Key Rotation**

This is the least formally specified area. The key references are:

**Whyte, Weimerskirch, Kumar & Harding (2013)** — the paper that introduced BKE — noted that the caterpillar key must be rotated but did not prescribe a specific interval, treating it as a deployment policy decision.

**IEEE 1609.2.1-2022** (the SCMS management standard, which standardised BKE for North America) specifies the provisioning architecture but leaves caterpillar key lifetime as a system parameter. The implicit model is that a caterpillar key covers one provisioning epoch — i.e. you generate a new caterpillar key each time you request a new batch. This is the most conservative and most privacy-preserving approach, and it is what the current codebase does (a fresh caterpillar key is generated in cmd\_butterfly\_at on every invocation).

**The risk of reuse:** If the same caterpillar key is used across multiple batch requests, the AA can link all those batches — even without colluding with the EA — because the caterpillar public key Cf appears in each request. This effectively collapses the unlinkability that BKE provides across batches. For this reason, generating a new caterpillar key per batch is the correct practice, even though the standards don't always state it explicitly.

---

**What is the best way to validate the credentials issued by the code in this repo?**

The most tractable approach for validating this repo's output against an external tool is to target **ETSI's own test infrastructure**:

**Option A — ETSI ETSI ITS Plugtests conformance tools.** ETSI runs C-V2X Plugtests (the 4th was in Malaga, September 2024\) where PKI certificates from participating implementations are validated for ETSI TS 103 097 conformance. The test tooling used at those events includes certificate parsers and signature verifiers built against the ETSI profile. ETSI publishes the test plans but the tools themselves are provided under NDA to plugtest participants.

**Option B — Marben V2X test tools.** Marben (a French ITS test tool vendor, also mentioned in the OmniAir Plugfest description) produces conformance test tools for ETSI TS 103 097 certificates and signed messages. These are commercial but are the reference tools used in European C-ITS deployment testing.

**Option C — Build a validation bridge using `jpo-security`.** If you want to use the open-source JPO tools, the path is to write a thin converter that takes a signed `EtsiTs103097Data-Signed` output from this repo, rewraps it in the `Ieee1609Dot2Data` envelope that `jpo-security` expects, and maps the certificate fields across. This is tractable for the explicit certificate fields but requires care around the PSID values (CAM PSID 36 vs BSM PSID 32).

**Option D — NIST tool with custom certificate loader.** The `usnistgov/C-V2XInteroperabilityTestingTool` is the most accessible open-source option. It parses 1609.2 messages from pcap captures. If you sign a CAM with this repo's AT and inject it as a DSRC/C-V2X packet capture, the NIST tool can attempt to parse and validate it — though again you will hit the ETSI vs IEEE 1609.2 profile differences in practice.

In short: CAMP's C-V2X Performance Assessment project is the wrong tool for credential validation. The right ecosystem for validating ETSI-profile credentials from this repo is ETSI's own Plugtests toolchain or Marben's conformance tools, neither of which is publicly open source. The closest open-source alternative is the NIST tool or the JPO/Leidos `jpo-security` library, both of which require bridging work due to the ETSI vs North American profile differences.

# **Specialist Task Force 424:**

**Platform for Conformance Testing of Co-operative Awareness Messages (CAM), Decentralized environmental Notification Messages (DENM) and GeoNetworking Protocols**

- [https://portal.etsi.org/STF/STFs/STF-Homepages/STF424](https://portal.etsi.org/STF/STFs/STF-Homepages/STF424)

---

## **How CAM Signature Verification Works in This Repo**

### **Architecture Overview**

The repo is a Python implementation of the ETSI TS 103 097 V2.2.1 / IEEE 1609.2-2025 PKI stack. The relevant source files are:

| File | Role |
| ----- | ----- |
| `cli.py` | Command-line entry point |
| `src/signing.py` | Signs and verifies `EtsiTs103097Data-Signed` structures |
| `src/verification.py` | Verifies certificate chains |
| `src/crypto.py` | ECDSA P-256/P-384 primitives |
| `src/encoding.py` | COER encode/decode for certificates |

---

### **What Gets Signed**

When `sign_cam()` is called in `signing.py`, it builds a `ToBeSignedData` (`tbs_data`) from two concatenated pieces:

tbs\_data \= SignedDataPayload (the CAM bytes wrapped in EtsiTs103097Data-Unsecured)  
         \+ HeaderInfo (PSID=36, generationTime, bitmap)

The ECDSA signature is computed over those raw `tbs_data` bytes using SHA-256. The resulting structure is:

Ieee1609Dot2Data (version=3)  
  └── content: SignedData (choice=1)  
        ├── hashId (0=sha256)  
        ├── tbs\_data  
        ├── signer: digest (HashedId8 \= last 8 bytes of SHA-256(AT cert))  
        │         OR certificate (full AT cert bytes)  
        └── signature: (r, s) as raw 32-byte big-endian integers

**By default, `sign_cam()` uses `use_digest=True` — meaning the signer field carries only the 8-byte HashedId8 fingerprint of the AT cert, not the full cert. The `--full-cert` CLI flag switches to embedding the full cert.**

---

### **How to Verify a Signed CAM File**

#### **Step 1 — Set up the environment**

bash  
cd /Users/josephhunt/COIMBRA/C-ITS-PKI  
uv sync   \# installs dependencies (cryptography library)

#### **Step 2 — Sign a test CAM (if you don't have one already)**

bash  
\# Initialize PKI and issue an AT (only needed once)  
python cli.py init \--output pki-output \--algo p256 \--region 65535  
python cli.py issue-at \--output pki-output \--psid 36,37 \--validity 168

\# Create and sign a CAM payload  
echo \-n "CAM\_PAYLOAD" \> cam.bin

AT\_CERT\=$(ls pki-output/tickets/\*.cert)  
AT\_KEY\=$(ls pki-output/tickets/\*.key)

python cli.py sign-cam \\  
  \--at-key  $AT\_KEY  \\  
  \--at-cert $AT\_CERT \\  
  \--payload cam.bin  \\  
  \--output  cam.signed

#### **Step 3 — Verify the signature with a Python script**

There is no single `verify-cam` CLI command, but `verify_signed_data()` in `signing.py` does the full job. You call it with the AT cert's public key:

python  
from src.signing import verify\_signed\_data  
from src.crypto import deserialize\_private\_key, load\_public\_key\_from\_compressed  
from src.encoding import decode\_certificate  
from src.types import PublicKeyAlgorithm  
from pathlib import Path

\# Load the AT cert to extract its public key  
at\_cert\_bytes \= Path("pki-output/tickets/at\_XXXXXXXX.cert").read\_bytes()  
at\_cert, \_ \= decode\_certificate(at\_cert\_bytes)

vk \= at\_cert.tbs.verify\_key\_indicator  
pub\_key \= load\_public\_key\_from\_compressed(vk.point.curve, vk.point.compressed)

\# Load the signed CAM  
signed\_cam \= Path("cam.signed").read\_bytes()

\# Verify  
result \= verify\_signed\_data(  
    signed\_data\_bytes=signed\_cam,  
    signer\_pub\_key=pub\_key,  
    algorithm=PublicKeyAlgorithm.ECDSA\_NIST\_P256,  
)

print(result)  
\# {'valid': True, 'psid': 36, 'generation\_time\_us': ..., 'signer': {'type': 'digest', ...}, 'payload': b'CAM\_PAYLOAD'}

`verify_signed_data()` returns a dict — the key field is `result['valid']` (bool). It also gives you back the PSID, generation time, signer info, and the decrypted inner payload.

#### **Step 4 — Also verify the AT certificate chain**

The message signature alone isn't sufficient — you also need to confirm the AT cert was legitimately issued. Use `verify_certificate_chain()` from `verification.py`:

python  
from src.verification import verify\_certificate\_chain  
from src.encoding import decode\_certificate  
from src.types import PublicKeyAlgorithm  
from pathlib import Path

def load\_cert(path):  
    b \= Path(path).read\_bytes()  
    cert, \_ \= decode\_certificate(b)  
    cert.encoded \= b   \# required — hash\_certificate uses cert.encoded  
    return cert

root \= load\_cert("pki-output/root\_ca.cert")  
aa   \= load\_cert("pki-output/aa.cert")  
at   \= load\_cert("pki-output/tickets/at\_XXXXXXXX.cert")

chain\_result \= verify\_certificate\_chain(  
    leaf\_cert=at,  
    intermediate\_certs=\[aa\],  
    root\_cert=root,  
    algorithm=PublicKeyAlgorithm.ECDSA\_NIST\_P256,  
)

print(chain\_result\['valid'\])   \# True  
print(chain\_result\['errors'\])  \# \[\]

This validates: Root CA self-signature → Root CA signed the AA → AA signed the AT → all validity periods → issuer digests → cracaId/crlSeries constraints → AT has appPermissions (not certIssuePermissions).

---

### **The Digest vs. Full-Cert Distinction**

This is the main practical gotcha. When a CAM is signed with `use_digest=True` (the default), the `signer` field in the message is only the 8-byte HashedId8 fingerprint of the AT cert. `verify_signed_data()` **does not resolve the cert from the digest** — it takes the public key as a direct argument. So you must supply the correct AT cert's public key out-of-band.

If you signed with `--full-cert`, the AT cert is embedded in the message itself. In that case you could extract it directly from the `cam.signed` bytes before calling the verifier (the embedded cert appears at the signer offset in the binary).

---

### **What `verify_signed_data()` Actually Does Internally**

Looking at `signing.py` lines starting at `def verify_signed_data`:

1. Strips the outer `Ieee1609Dot2Data` wrapper (version byte \+ content choice=1)  
2. Reads `hashId` byte  
3. Marks `tbs_start`, then parses the payload and HeaderInfo to find `tbs_end` — this reconstructs the exact byte range that was signed  
4. Parses the signer field (digest or certificate)  
5. Calls `decode_signature()` to get `(r, s)`  
6. Calls `ecdsa_verify(public_key, tbs_data, r, s, algorithm)` from `crypto.py`, which re-encodes `(r, s)` into DER format and calls the Python `cryptography` library's ECDSA verifier with SHA-256

The signature is over the raw `tbs_data` bytes — not a hash of them — because `ecdsa_verify` in `crypto.py` passes the raw data to `public_key.verify(..., ECDSA(hashes.SHA256()))`, letting the library do the hashing internally. This avoids the double-hash pitfall.

