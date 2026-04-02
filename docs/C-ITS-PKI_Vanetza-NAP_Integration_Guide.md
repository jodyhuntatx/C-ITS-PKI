# Integrating C-ITS-PKI Certificates and Keys into Vanetza-NAP

**Document Version:** 1.0  
**Date:** 2 April 2026  
**Source Repositories:**
- [vanetza-nap](https://github.com/nap-it/vanetza-nap/tree/main) — ITS-G5 stack and socktap application
- [C-ITS-PKI](https://github.com/jodyhuntatx/C-ITS-PKI/tree/main) — ETSI TS 103 097 / IEEE 1609.2 PKI toolkit

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Background and Architecture](#2-background-and-architecture)
3. [Security Model Comparison](#3-security-model-comparison)
4. [File Format Analysis](#4-file-format-analysis)
5. [Integration Prerequisites](#5-integration-prerequisites)
6. [Step-by-Step Integration Procedure](#6-step-by-step-integration-procedure)
   - 6.1 [Generate the PKI Hierarchy with C-ITS-PKI](#61-generate-the-pki-hierarchy-with-c-its-pki)
   - 6.2 [Export the Authorization Ticket and Private Key](#62-export-the-authorization-ticket-and-private-key)
   - 6.3 [Convert the Private Key Format](#63-convert-the-private-key-format)
   - 6.4 [Convert the Certificate to Vanetza Binary Format](#64-convert-the-certificate-to-vanetza-binary-format)
   - 6.5 [Assemble the Certificate Chain Files](#65-assemble-the-certificate-chain-files)
   - 6.6 [Configure Vanetza-NAP to Use the Certificates](#66-configure-vanetza-nap-to-use-the-certificates)
   - 6.7 [Start Vanetza-NAP in `certs` Security Mode](#67-start-vanetza-nap-in-certs-security-mode)
7. [Butterfly Key Expansion (BKE) Variant](#7-butterfly-key-expansion-bke-variant)
8. [Trust Store and Certificate Chain Validation](#8-trust-store-and-certificate-chain-validation)
9. [Troubleshooting](#9-troubleshooting)
10. [Appendix A — Key Conversion Reference Script](#appendix-a--key-conversion-reference-script)
11. [Appendix B — Certificate Inspection Commands](#appendix-b--certificate-inspection-commands)
12. [Appendix C — Vanetza Security Architecture Reference](#appendix-c--vanetza-security-architecture-reference)

---

## 1. Executive Summary

**Vanetza-NAP** is a C++ ITS-G5 V2X communication stack with a `socktap` application that supports three security modes: `none`, `dummy`, and `certs`. The `certs` mode loads externally generated Authorization Tickets (ATs) and their private keys from disk for real V2X message signing and verification.

**C-ITS-PKI** is a Python toolkit implementing the full ETSI TS 103 097 / IEEE 1609.2 certificate hierarchy, generating Root CA, EA, AA, Enrolment Credentials, and Authorization Tickets as COER-encoded binary files with PEM-encoded private keys.

**The core integration challenge** is a format mismatch between the two systems:

| Artefact | C-ITS-PKI output | Vanetza-NAP expected |
|---|---|---|
| Authorization Ticket | COER-encoded binary (IEEE 1609.2 EtsiTs103097Certificate) | Vanetza custom binary serialization (ETSI TS 103 097 v1.x structures) |
| Private key | PKCS#8 PEM (SEC1 EC key, `cryptography` library) | Crypto++ DER-encoded EC private key (ANSI X9.62 format) |
| CA chain certs | COER binary | Vanetza custom binary serialization |

This document provides the complete procedure for bridging that gap, including conversion scripts, configuration options, and validation steps.

---

## 2. Background and Architecture

### 2.1 Vanetza-NAP Security Architecture

Vanetza-NAP's security layer is implemented in `tools/socktap/security.cpp`. The `create_security_entity()` function supports three modes selected by the `--security` command-line argument:

**`none`** — No security processing. Messages are sent unsigned and unsigned messages are accepted. This is the default when no `--security` flag is provided.

**`dummy`** — Signs messages with a null signer (no certificate) and accepts any incoming message regardless of signature validity. Useful for protocol testing.

**`certs`** — Full ETSI TS 103 097 security. Loads an Authorization Ticket and its private key from files, builds a `StaticCertificateProvider`, and wires up the `DefaultCertificateValidator` against a `TrustStore`. This is the production-grade mode and the target of this integration.

When `certs` mode is active, vanetza-nap requires:

1. `--certificate <path>` — The Authorization Ticket (AT) certificate file, in Vanetza's binary serialization format.
2. `--certificate-key <path>` — The AT private key file, in Crypto++ DER-encoded EC private key format.
3. `--certificate-chain <path>` (optional, repeatable) — Intermediate CA certificates (typically AA cert and Root CA cert). Root CA certificates found in the chain are automatically added to the trust store.
4. `--trusted-certificate <path>` (optional, repeatable) — Additional explicitly trusted certificates added directly to the trust store.

The persistence layer (`vanetza/security/persistence.cpp`) uses Crypto++'s `ECDSA<ECP, SHA256>::PrivateKey::Load()` for private keys and a custom Vanetza binary archive for certificates and public keys.

### 2.2 C-ITS-PKI Architecture

C-ITS-PKI (`src/pki.py`, `src/certificates.py`) generates a complete ETSI TS 103 097 hierarchy:

- **Root CA** — Self-signed root certificate, 10-year validity, signs EA and AA certificates.
- **TLM** — Self-signed Trust List Manager certificate.
- **EA (Enrolment Authority)** — Root-signed subordinate CA issuing Enrolment Credentials (ECs).
- **AA (Authorization Authority)** — Root-signed subordinate CA issuing Authorization Tickets (ATs).
- **EC (Enrolment Credential)** — EA-signed long-term identity credential for an ITS-station.
- **AT (Authorization Ticket)** — AA-signed short-lived pseudonymous certificate binding an ECDSA P-256 public key to ITS-AID permissions (e.g., PSIDs 36 for CAM, 37 for DENM).

Certificates are COER-encoded per IEEE 1609.2-2025 and saved as raw binary `.cert` files. Private keys are PKCS#8 PEM files produced by the Python `cryptography` library.

---

## 3. Security Model Comparison

### 3.1 Standard Version Differences

The most significant compatibility consideration is the **version of the security standard** each system targets:

| Aspect | C-ITS-PKI | Vanetza-NAP |
|---|---|---|
| Certificate standard | IEEE 1609.2-2025 / ETSI TS 103 097 v2.2.1 | ETSI TS 103 097 v1.x (2015-era structures) |
| Certificate encoding | COER (Canonical OER, IEEE 1609.2-2025 §6) | Vanetza custom binary archive serialization |
| Certificate structure | `EtsiTs103097Certificate` (v3 IEEE 1609.2) | Version 2 Vanetza `Certificate` struct |
| Crypto curve | ECDSA NIST P-256 or P-384 | ECDSA NIST P-256 only |
| Private key format | PKCS#8 PEM (Python `cryptography` library) | Crypto++ DER (`ECDSA<ECP,SHA256>::PrivateKey`) |
| App permissions | `appPermissions` with `PsidSsp` | `ItsAidSsp` list (subjAttr) |

> **Important:** Vanetza-NAP's internal `Certificate` type (defined in `vanetza/security/certificate.hpp`) is based on the ETSI TS 103 097 v1.2 specification — the version prior to the IEEE 1609.2-2022/2025 re-alignment. C-ITS-PKI generates certificates per the newer COER-encoded IEEE 1609.2-2025 format. **These binary formats are not directly interchangeable.**

### 3.2 Practical Consequence

Because the binary certificate formats differ, C-ITS-PKI's `.cert` files **cannot be passed directly** to Vanetza-NAP's `--certificate` and `--certificate-chain` flags. The integration requires one of two strategies:

**Strategy A (Recommended): Use Vanetza's `certify` tool** to regenerate Authorization Tickets and chain certificates in Vanetza's own format, using keys generated or exported from C-ITS-PKI.

**Strategy B (Advanced): Implement a COER → Vanetza binary converter** — parse the C-ITS-PKI COER output and re-serialize into Vanetza's archive format. This approach is more complex but preserves the full PKI hierarchy from C-ITS-PKI without regeneration.

This guide covers Strategy A in full detail and outlines the approach for Strategy B.

---

## 4. File Format Analysis

### 4.1 Vanetza Certificate Binary Format

Vanetza certificates are serialized using the `OutputArchive`/`InputArchive` template in `vanetza/security/serialization.hpp`. The functions `save_certificate_to_file()` and `load_certificate_from_file()` in `persistence.cpp` use this archive directly. The format encodes the ETSI TS 103 097 v1.x `Certificate` structure as a compact binary byte stream — it is **not** standard COER or DER.

The `certify` tool (`tools/certify/`) generates these files natively. Its commands are:

| Command | Output |
|---|---|
| `generate-key` | Crypto++ DER EC private key (`.key` file) |
| `generate-root` | Vanetza binary Root CA certificate |
| `generate-aa` | Vanetza binary AA certificate signed by Root CA |
| `generate-ticket` | Vanetza binary AT signed by AA cert |
| `extract-public-key` | Vanetza binary public key from private key |
| `show-certificate` | Human-readable dump of any Vanetza cert |

### 4.2 Vanetza Private Key Format

`load_private_key_from_file()` in `persistence.cpp` uses:

```cpp
CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey private_key;
CryptoPP::FileSource key_file(key_path.c_str(), true);
private_key.Load(key_file);
```

Crypto++ encodes ECDSA private keys in ANSI X9.62 / SEC1 DER format (not PKCS#8). This is a raw DER file, not PEM-wrapped.

### 4.3 C-ITS-PKI Private Key Format

C-ITS-PKI serializes keys using:

```python
def serialize_private_key(priv_key):
    return priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
```

This produces a standard PKCS#8 PEM file beginning with `-----BEGIN PRIVATE KEY-----`.

### 4.4 Conversion Summary

| Conversion | Tool | Command |
|---|---|---|
| PKCS#8 PEM → Crypto++ DER | OpenSSL | `openssl pkcs8 -in key.pem -nocrypt -outform DER -out key.der` followed by `openssl ec -inform DER -in key.der -outform DER -out cryptopp_key.der` |
| Vanetza binary cert → inspect | certify | `certify show-certificate cert.bin` |
| C-ITS-PKI COER cert → inspect | C-ITS-PKI | `python cli.py info --cert cert.cert` |

---

## 5. Integration Prerequisites

### 5.1 Software Requirements

The following must be installed on the host performing the integration:

- **Vanetza-NAP** — Built from source (see project README). The `certify` binary must be compiled and accessible. Build with `-DWITH_CERTIFY=ON`.
- **C-ITS-PKI** — Python 3.11+, `uv` package manager. Clone and run `uv sync` in the repo root.
- **OpenSSL 3.x** — Available as `openssl` on the PATH, used for key format conversion.
- **Python 3.11+** — For conversion helper scripts in this guide.

### 5.2 Build the `certify` Tool

```bash
# From the vanetza-nap repo root
mkdir -p build && cd build
cmake .. -DWITH_CERTIFY=ON
make -j$(nproc) certify
# Binary at: build/tools/certify/certify
export CERTIFY=$(pwd)/build/tools/certify/certify
```

### 5.3 Set Up C-ITS-PKI

```bash
git clone https://github.com/jodyhuntatx/C-ITS-PKI.git
cd C-ITS-PKI
uv sync
alias pki="uv run python cli.py"
```

---

## 6. Step-by-Step Integration Procedure

This procedure results in a set of files that Vanetza-NAP's `certs` security mode accepts directly.

### 6.1 Generate the PKI Hierarchy with C-ITS-PKI

Use C-ITS-PKI to initialise the full hierarchy and issue an Authorization Ticket for the ITS-station.

```bash
cd C-ITS-PKI

# Initialise PKI: creates Root CA, TLM, EA, and AA
pki init \
  --output pki-output \
  --algo p256 \
  --region 65535

# Enrol the ITS-station (creates Enrolment Credential)
pki enrol \
  --output pki-output \
  --name "MyITSStation-001"

# Issue an Authorization Ticket valid for 168 hours (1 week)
# PSIDs: 36 = CAM, 37 = DENM
pki issue-at \
  --output pki-output \
  --psid 36,37 \
  --validity 168
```

After this step, the following files are present under `pki-output/`:

```
pki-output/
├── root_ca.cert          ← Root CA (COER, self-signed)
├── root_ca_sign.key      ← Root CA signing key (PKCS#8 PEM)
├── ea.cert               ← Enrolment Authority cert (COER)
├── ea_sign.key           ← EA signing key (PKCS#8 PEM)
├── ea_enc.key            ← EA encryption key (PKCS#8 PEM)
├── aa.cert               ← Authorization Authority cert (COER)
├── aa_sign.key           ← AA signing key (PKCS#8 PEM)
├── aa_enc.key            ← AA encryption key (PKCS#8 PEM)
├── its-stations/
│   └── MyITSStation-001/
│       ├── ec.cert       ← Enrolment Credential (COER)
│       └── ec.key        ← EC signing key (PKCS#8 PEM)
└── tickets/
    ├── at_<id>.cert      ← Authorization Ticket (COER)
    └── at_<id>.key       ← AT signing key (PKCS#8 PEM)
```

Inspect the AT to confirm it was issued correctly:

```bash
pki info --cert pki-output/tickets/at_*.cert
```

### 6.2 Export the Authorization Ticket and Private Key

Identify the AT private key and cert files (there is typically one per issuance):

```bash
export AT_CERT=$(ls pki-output/tickets/at_*.cert)
export AT_KEY=$(ls pki-output/tickets/at_*.key)
echo "AT cert: $AT_CERT"
echo "AT key:  $AT_KEY"
```

### 6.3 Convert the Private Key Format

Vanetza-NAP requires the AT private key in **Crypto++ DER EC private key format** (raw DER, not PEM-wrapped, not PKCS#8). C-ITS-PKI produces PKCS#8 PEM. The conversion uses OpenSSL:

```bash
# Step 1: Convert PKCS#8 PEM to traditional EC DER (SEC1 format)
openssl pkcs8 \
  -in "$AT_KEY" \
  -nocrypt \
  -out at_key_sec1.pem

# Step 2: Convert SEC1 PEM to DER (this is what Crypto++ reads)
openssl ec \
  -in at_key_sec1.pem \
  -outform DER \
  -out at_key_cryptopp.der

# Clean up intermediate
rm at_key_sec1.pem
```

Verify the DER file is a valid EC key:

```bash
openssl ec -inform DER -in at_key_cryptopp.der -text -noout
```

Expected output includes `ASN1 OID: prime256v1`, confirming P-256 curve.

> **Note:** Crypto++ can also load PEM EC keys in certain configurations, but the DER format is the most reliable and is what Vanetza's `persistence.cpp` was tested with in the `certify` tool. Use DER to avoid subtle loading issues.

### 6.4 Convert the Certificate to Vanetza Binary Format

This is the most significant conversion step. Because C-ITS-PKI's COER certificate format differs from Vanetza's internal binary format, you must **rebuild** the Authorization Ticket using Vanetza's `certify` tool, but using the **same private key** (now converted to DER) so that the AT's public key is correct.

#### 6.4.1 Build a Vanetza Root CA

```bash
# Generate a new Vanetza-format Root CA key and certificate
$CERTIFY generate-key vanetza_root_ca.key

$CERTIFY generate-root \
  --sign-key vanetza_root_ca.key \
  vanetza_root_ca.cert
```

#### 6.4.2 Build a Vanetza AA Certificate

```bash
$CERTIFY generate-key vanetza_aa.key

$CERTIFY generate-aa \
  --sign-key vanetza_root_ca.key \
  --sign-cert vanetza_root_ca.cert \
  --subject-key vanetza_aa.key \
  vanetza_aa.cert
```

#### 6.4.3 Issue the Authorization Ticket

Use the `at_key_cryptopp.der` from Section 6.3 as the subject key. The AT will be signed by the Vanetza AA, and it will embed the **same public key** derived from the C-ITS-PKI AT private key.

```bash
$CERTIFY generate-ticket \
  --sign-key vanetza_aa.key \
  --sign-cert vanetza_aa.cert \
  --subject-key at_key_cryptopp.der \
  --days 7 \
  --cam-permissions "1111111111111100" \
  --denm-permissions "000000000000000000000000" \
  vanetza_at.cert
```

Inspect the resulting Vanetza-format AT to confirm it was created correctly:

```bash
$CERTIFY show-certificate vanetza_at.cert
```

You should see output confirming the Subject Type is `Authorization_Ticket` and the ITS-AIDs for CAM and DENM are listed.

### 6.5 Assemble the Certificate Chain Files

Vanetza-NAP's `--certificate-chain` argument accepts one or more certificate files. The Root CA in the chain is automatically added to the trust store. You need at minimum:

- `vanetza_root_ca.cert` — the Root CA (auto-trusted)
- `vanetza_aa.cert` — the AA (added to cert cache for chain building)

```bash
# Create an integration directory for clarity
mkdir -p vanetza_certs/
cp vanetza_at.cert     vanetza_certs/at.cert
cp at_key_cryptopp.der vanetza_certs/at.key
cp vanetza_aa.cert     vanetza_certs/aa.cert
cp vanetza_root_ca.cert vanetza_certs/root_ca.cert
```

### 6.6 Configure Vanetza-NAP to Use the Certificates

The certificate options are passed as command-line arguments to the `socktap` binary. They are parsed in `tools/socktap/security.cpp` via `add_security_options()`. There is no INI file section for certificates — they must be on the command line or in a startup script.

The complete set of certificate arguments is:

```
--security certs
--certificate vanetza_certs/at.cert
--certificate-key vanetza_certs/at.key
--certificate-chain vanetza_certs/aa.cert
--certificate-chain vanetza_certs/root_ca.cert
```

The Root CA cert passed via `--certificate-chain` is detected automatically because its `subject_type` equals `SubjectType::Root_CA`, and it is inserted into the `trust_store`. Additional explicitly trusted certificates can be added with `--trusted-certificate`.

If using Docker, mount the certs directory into the container and reference the mounted paths.

### 6.7 Start Vanetza-NAP in `certs` Security Mode

**Direct binary invocation:**

```bash
./build/tools/socktap/socktap \
  --config tools/socktap/config.ini \
  --security certs \
  --certificate vanetza_certs/at.cert \
  --certificate-key vanetza_certs/at.key \
  --certificate-chain vanetza_certs/aa.cert \
  --certificate-chain vanetza_certs/root_ca.cert
```

**Docker invocation** (using the project's `docker-compose.yml` as a base):

```yaml
# docker-compose.override.yml
services:
  vanetza:
    volumes:
      - ./vanetza_certs:/certs:ro
    command: >
      --config /config.ini
      --security certs
      --certificate /certs/at.cert
      --certificate-key /certs/at.key
      --certificate-chain /certs/aa.cert
      --certificate-chain /certs/root_ca.cert
```

**Expected startup log output:**

When security is initialised successfully, `mib.itsGnSecurity` is set to `true` and all outgoing V2X messages will be signed. Vanetza-NAP does not print an explicit "security initialised" log line, but no `std::runtime_error` will be thrown from the security entity construction path.

---

## 7. Butterfly Key Expansion (BKE) Variant

C-ITS-PKI supports Butterfly Key Expansion (BKE) per IEEE 1609.2a §6.4.3.7, issuing a batch of AT certificates derived from a single caterpillar private key:

```bash
pki butterfly-at \
  --output pki-output \
  --count 8 \
  --psid 36,37 \
  --validity 168
```

Each BKE AT has a derived private key: `sᵢ = (f + H(Cf || eᵢ)) mod n`. C-ITS-PKI computes these expanded keys using `bke_expand_private_key()` in `src/crypto.py`.

To use a BKE AT with Vanetza-NAP, follow the same procedure as Sections 6.3–6.6 for **each individual BKE AT** that you want to load. The `pki-output/bke-tickets/` directory contains:

```
bke-tickets/
├── bke_at_0.cert   ← BKE AT #0 (COER)
├── bke_at_0.key    ← Expanded private key for AT #0 (PKCS#8 PEM)
├── bke_at_1.cert
├── bke_at_1.key
...
```

Convert each `.key` file as described in Section 6.3 and generate a corresponding Vanetza-format ticket per Section 6.4. Vanetza-NAP uses a single AT at a time (the `StaticCertificateProvider` holds one AT), so select the BKE AT index you wish to use for the current station session.

---

## 8. Trust Store and Certificate Chain Validation

### 8.1 How Vanetza Validates Received Messages

When Vanetza-NAP receives a signed V2X message, the `DefaultCertificateValidator` (`vanetza/security/default_certificate_validator.cpp`) performs:

1. Extract the signer's HashedId8 from the `signer_info` field.
2. Look up the AT certificate from the `CertificateCache`.
3. Extract the AA's HashedId8 from the AT's `signer_info`.
4. Look up the AA certificate from the `CertificateCache`.
5. Check that the AA certificate's Root CA hash resolves to a certificate in the `TrustStore`.
6. Verify ECDSA signatures at each level.

For this chain to succeed for **incoming** messages from other stations, those stations' Root CAs must be trusted. If all stations in a test deployment use the same C-ITS-PKI Root CA, load `vanetza_root_ca.cert` (or equivalently the C-ITS-PKI `root_ca.cert` if you implement the COER converter) into both `--certificate-chain` and `--trusted-certificate`.

### 8.2 Configuring Non-Strict Mode

Vanetza-NAP's `main.cpp` sets:

```cpp
mib.itsGnSnDecapResultHandling = vanetza::geonet::SecurityDecapHandling::Non_Strict;
```

In Non-Strict mode, packets that fail signature verification are still delivered to the application layer (with the verification result flagged). This is the current default and suitable for testing scenarios. For production, change to `Strict` to drop unverified packets.

### 8.3 Cross-PKI Scenarios

If some ITS-stations use certificates from a different PKI (e.g., a national CPOC), add the foreign Root CA to the trust store via `--trusted-certificate <foreign_root.cert>`. The certificate must first be converted to Vanetza binary format via the procedure in Section 6.4.1 (generate a root cert embedding the same public key as the foreign PKI's root).

---

## 9. Troubleshooting

### 9.1 "Private key validation failed"

**Cause:** The `.key` file passed to `--certificate-key` is not a valid Crypto++ DER EC private key.

**Fix:** Ensure you ran both OpenSSL steps in Section 6.3. Verify with:
```bash
openssl ec -inform DER -in at.key -noout -check
```
Expected: `EC Key valid.`

### 9.2 "Either --certificate and --certificate-key must be present or none"

**Cause:** Only one of `--certificate` / `--certificate-key` was provided.

**Fix:** Both must be supplied together. Confirm both paths are present in the startup command.

### 9.3 Certificate loads but security entity is not ready

**Cause:** `build_entity()` was not called, or an exception was thrown during its construction that was silently swallowed.

**Fix:** Ensure `context->build_entity()` runs without exception. Check that `cert_provider` is not null. If using `StaticCertificateProvider`, the AT and its key must both load without error.

### 9.4 "security entity is not ready" at runtime

**Cause:** `encapsulate_packet()` was called before the security entity was fully built, or `create_security_entity()` returned null.

**Fix:** Confirm the `--security certs` flag is set and the cert/key paths resolve correctly. Look for error output before the `io_service.run()` call.

### 9.5 Certificate chain validation fails for received messages

**Cause:** The sending station's AA cert or Root CA cert is not in the cache or trust store.

**Fix:** Ensure all stations in the test share the same Root CA. Provide the Root CA via `--certificate-chain` (auto-trusted) or `--trusted-certificate`. If testing with a single node, this is not an issue since the node trusts its own AT.

### 9.6 OpenSSL "unknown key type" error during conversion

**Cause:** The C-ITS-PKI key file is PKCS#8 format but OpenSSL expects a different invocation.

**Fix:** Use the two-step conversion in Section 6.3. The intermediate `pkcs8 -nocrypt` step strips the PKCS#8 wrapper before the `ec` command converts to DER.

---

## Appendix A — Key Conversion Reference Script

The following Python script automates the key conversion from C-ITS-PKI PKCS#8 PEM format to Crypto++ DER format using only the `cryptography` library (no OpenSSL subprocess required):

```python
#!/usr/bin/env python3
"""
convert_key.py — Convert C-ITS-PKI PKCS#8 PEM key to Crypto++ DER format
for use with Vanetza-NAP.

Usage:
    python convert_key.py <input_pkcs8.pem> <output_cryptopp.der>
"""

import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def convert_pkcs8_pem_to_sec1_der(input_pem_path: str, output_der_path: str) -> None:
    with open(input_pem_path, "rb") as f:
        pem_data = f.read()

    # Load the PKCS#8 PEM key
    private_key = serialization.load_pem_private_key(
        pem_data, password=None, backend=default_backend()
    )

    # Export as SEC1 DER (traditional EC key format that Crypto++ reads)
    der_data = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # SEC1 / Crypto++ format
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(output_der_path, "wb") as f:
        f.write(der_data)

    print(f"Converted: {input_pem_path} -> {output_der_path} ({len(der_data)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.pem> <output.der>")
        sys.exit(1)
    convert_pkcs8_pem_to_sec1_der(sys.argv[1], sys.argv[2])
```

**Usage:**

```bash
python convert_key.py pki-output/tickets/at_abc123.key vanetza_certs/at.key
```

---

## Appendix B — Certificate Inspection Commands

### Inspect a C-ITS-PKI Certificate

```bash
# Show human-readable certificate details
pki info --cert pki-output/root_ca.cert
pki info --cert pki-output/aa.cert
pki info --cert pki-output/tickets/at_*.cert

# Verify certificate chain
pki verify-cert \
  --cert pki-output/tickets/at_*.cert \
  --issuer pki-output/aa.cert

# Verify AA signed by Root CA
pki verify-cert \
  --cert pki-output/aa.cert \
  --issuer pki-output/root_ca.cert
```

### Inspect a Vanetza Certificate

```bash
# Show human-readable dump of a Vanetza binary cert
$CERTIFY show-certificate vanetza_certs/at.cert
$CERTIFY show-certificate vanetza_certs/root_ca.cert
$CERTIFY show-certificate vanetza_certs/aa.cert
```

### Inspect a Converted Private Key

```bash
# Verify the DER key is valid EC P-256
openssl ec -inform DER -in vanetza_certs/at.key -text -noout

# Confirm key matches the AT certificate's public key
# (Both should show the same Q public point coordinates)
openssl ec -inform DER -in vanetza_certs/at.key -pubout -outform DER | openssl pkey -pubin -inform DER -text -noout
```

---

## Appendix C — Vanetza Security Architecture Reference

The following table summarises the key source files and their roles in the Vanetza-NAP security subsystem.

| File | Role |
|---|---|
| `tools/socktap/security.cpp` | Entry point — parses `--security`, `--certificate`, `--certificate-key`, `--certificate-chain`, `--trusted-certificate` arguments; constructs `SecurityContext` |
| `tools/socktap/security.hpp` | Declares `create_security_entity()` and `add_security_options()` |
| `vanetza/security/persistence.cpp` | `load_certificate_from_file()`, `save_certificate_to_file()`, `load_private_key_from_file()`, `load_public_key_from_file()` |
| `vanetza/security/static_certificate_provider.cpp` | Holds the AT cert + private key; returns them to the sign service |
| `vanetza/security/naive_certificate_provider.cpp` | Fallback: self-generates keys and certs in-memory (no files needed) |
| `vanetza/security/trust_store.cpp` | In-memory set of trusted Root CA certs; queried during chain validation |
| `vanetza/security/certificate_cache.cpp` | In-memory cache of all seen certs (AT, AA, Root CA); populated from chain files and received messages |
| `vanetza/security/default_certificate_validator.cpp` | Verifies cert chains against the trust store; called on every received message |
| `vanetza/security/sign_service.cpp` | Signs outgoing messages using the AT private key and cert |
| `vanetza/security/verify_service.cpp` | Verifies incoming message signatures |
| `vanetza/security/backend_cryptopp.cpp` | Crypto++ backend — ECDSA sign/verify implementation |
| `vanetza/security/backend_openssl.cpp` | OpenSSL backend alternative (selectable at build time) |
| `tools/certify/commands/generate-ticket.cpp` | Reference implementation for AT generation in Vanetza binary format |
| `tools/certify/commands/generate-root.cpp` | Reference implementation for Root CA generation |
| `tools/certify/commands/generate-aa.cpp` | Reference implementation for AA certificate generation |

### Certificate Loading Code Path (certs mode)

```
main() → create_security_entity(vm="certs")
  → load_certificate_from_file(--certificate)        # AT cert
  → load_private_key_from_file(--certificate-key)    # AT key
  → for each --certificate-chain:
       load_certificate_from_file(chain_path)
       cert_cache.insert(chain_cert)
       if SubjectType::Root_CA: trust_store.insert(chain_cert)
  → StaticCertificateProvider(AT, AT_key, chain)
  → build_entity()
       → straight_sign_service(cert_provider, backend, sign_header_policy)
       → straight_verify_service(..., cert_validator, ...)
       → DelegatingSecurityEntity(sign_service, verify_service)
```

---

*End of Document*
