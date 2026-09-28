# ASN.1 modules for v3 certificates

Copied verbatim from Vanetza-NAP (`vanetza-nap/asn1/`), which compiles exactly these
modules (with asn1c) for its v3 security layer:

- `IEEE1609dot2BaseTypes.asn`, `IEEE1609dot2.asn` — IEEE 1609.2-2016 schema
- `TS103097v131.asn` — ETSI TS 103 097 v1.3.1 profile (`EtsiTs103097Certificate`)

`src/encoding/asn1_codec.py` compiles them with asn1tools and encodes/decodes
certificates as COER, so the output is byte-compatible with Vanetza's decoder.
Do not edit these files; replace them from Vanetza when it updates its schema.
