# C-ITS-PKI

A Python utility that creates a complete C-ITS public key infrastructure (Root CA, TLM,
Enrolment and Authorization Authorities, Enrolment Credentials, Authorization Tickets,
IEEE 1609.2.1 butterfly AT batches), and signs, encrypts and verifies C-ITS messages.
It produces two formats, both accepted by the Vanetza-NAP V2X stack [R24], a fork of Vanetza [R25]:

- **v2**: ETSI TS 103 097 V1.2.1 [R4], the binary format of Vanetza `security/v2`.
- **v3**: ETSI TS 103 097 V1.3.1 [R3] (IEEE 1609.2-2016 [R9], COER [R12]), the format
  of Vanetza `security/v3`. Profiles are checked against TS 103 097 V2.2.1 [R1].

## Documentation

| Part | Document | Contents |
|---|---|---|
| I | [Operations Guide](operations.md) | installation, format choice, CLI reference, workflows, scripts, test suites, Vanetza-NAP usage, troubleshooting |
| II | [Implementation Details](implementation.md) | architecture, modules, encodings, certificate profiles, signed and encrypted messages, ECIES, butterfly keys, verification |
| III | [Standards Compliance and Evidence](compliance.md) | evidence methods, clause-by-clause matrices for TS 103 097 (v3 and v2) and IEEE 1609.2.1, known deviations, PRD traceability |
| — | [Design Decisions and Specification Gaps](design-decisions.md) | DD-01 … DD-18: how gaps and ambiguities in the specifications were resolved, and why |
| — | [Privacy and Deployment Notes](privacy-and-deployment-notes.md) | informative: what the mechanisms protect, parameters the standards leave open, external validation tools |
| — | [Vanetza v2 Permission Structure](perms-doc.md) | informative: how Vanetza checks v2 certificate permissions |
| Appendix | [References](references.md) | full citations [R1]–[R30] |

## Quick start

```bash
uv sync
P="uv run python cli.py"
$P init     --output pki --etsi-version v3        # Root CA, TLM, EA, AA
$P issue-at --output pki                          # one Authorization Ticket
$P butterfly-at --output pki --count 8            # IEEE 1609.2.1 butterfly batch
AT=$(ls pki/tickets/at_*.cert)
printf 'CAM_PAYLOAD' > cam.bin
$P sign-cam   --at-key ${AT%.cert}_sign.key --at-cert $AT --payload cam.bin --output cam.signed
$P verify-sig --signed cam.signed --at-cert $AT --aa pki/aa.cert --root pki/root_ca.cert
bash tests/v3/run_all.sh                          # 85 tests (v2 suite: 84)
```

## Status at a glance

(Details in [compliance](compliance.md); results from 2026-09-25.)

- **v3 certificates, signed / external-payload / encrypted / signed-and-encrypted data:**
  conformant for explicit P-256 certificates and certificate recipients.
  - Verified by Vanetza with full-chain checks.
  - Exercised in a live RSU/OBU simulation.
- **v2 certificates and messages:** conform to TS 103 097 V1.2.1 and are accepted by
  Vanetza-NAP, including stock Vanetza without the vnap-secure assurance patch (the four
  former deviations KD-1 to KD-4 were fixed on 2026-09-25).
- **Butterfly keys and ECIES:** bit-exact against the published SCMS reference test
  vectors [R22].
- **Not implemented:**
  - implicit certificates
  - NIST P-384
  - `psk` and `signedData` recipients
  - Misbehaviour Authority certificates
  - TS 102 941 protocol messages
  - PICS

## Used by vnap-secure

The [vnap-secure](https://github.com/jodyhuntatx/vnap-secure) simulation harness [R30]
includes this repository as a git submodule (`external/C-ITS-PKI`, pinned to a tested commit):

- **Per-run PKI:** vnap-secure's `vnap-pki` image is built from this repository's `src/`
  package. It runs the CA hierarchy and issues the butterfly ATs of each simulation run, so
  `src.pki`, `src.certificates`, `src.crypto` and `src.types` are an interface to vnap-secure.
- **Fixed certificate set:** `gen-vnap-certs.sh` produces the certificates committed in
  vnap-secure's `certs/c-its-pki/`.

Changes to that interface or to the certificate encoding must be checked with vnap-secure:
`tests/test_vnap_secure_interface.py` covers the interface; see
[Operations Guide §8](operations.md#8-using-the-output-with-vanetza-nap).

## Repository layout

```
C-ITS-PKI/
├── cli.py                 command-line interface
├── src/                   library (see implementation §2)
│   └── asn1/              ASN.1 modules vendored from Vanetza-NAP
├── tests/v2, tests/v3     test suites (9 files each)
├── gen-verify.sh          end-to-end workflow check
├── gen-vnap-certs.sh      Vanetza-NAP simulation certificates
├── _clean.sh              remove generated files
├── pdf/                   specifications and project documents (see references)
└── docs/                  this documentation
```

`pdf/Vanetza_Integration_Guide.pdf` predates the 2026-09 encoding fixes and describes the
earlier behaviour; the documents above supersede it.

## License

Provided for research and educational purposes.
