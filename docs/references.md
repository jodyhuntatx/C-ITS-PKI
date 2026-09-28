# Appendix: References

All standards-based statements in this documentation cite the entries below as
**[Rn]**, usually with a clause number, e.g. `[R1] cl. 7.2.3`. Clause numbers refer to
the edition listed here. Where a document is cited "as quoted by" another source, the
original was not available to the project and the quoting source is listed too.

Documents marked 📁 are in this repository's [`pdf/`](../pdf) folder. Documents marked
📥 were retrieved from the publisher during development. All others are cited from their
published bibliographic data.

## Standards and specifications

<a id="r1"></a>**[R1]** ETSI TS 103 097 V2.2.1 (2026-03). *Intelligent Transport Systems (ITS); Security; Security header and certificate formats; Release 2.* European Telecommunications Standards Institute, Sophia Antipolis. 📁 `pdf/ETSI-C-ITS-msg-cert-formats-103-097-V2.2.1.pdf`

<a id="r2"></a>**[R2]** ETSI TS 103 097 V1.4.1 (2020-10). *Intelligent Transport Systems (ITS); Security; Security header and certificate formats.* ETSI. 📥 <https://www.etsi.org/deliver/etsi_ts/103000_103099/103097/01.04.01_60/ts_103097v010401p.pdf>

<a id="r3"></a>**[R3]** ETSI TS 103 097 V1.3.1 (2017-10). *Intelligent Transport Systems (ITS); Security; Security header and certificate formats.* ETSI. Its ASN.1 module `EtsiTs103097Module {itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(103097) v1(0)}` is used as vendored by Vanetza [R24] (`src/asn1/TS103097v131.asn`).

<a id="r4"></a>**[R4]** ETSI TS 103 097 V1.2.1 (2015-06). *Intelligent Transport Systems (ITS); Security; Security header and certificate formats.* ETSI. 📥 <https://www.etsi.org/deliver/etsi_ts/103000_103099/103097/01.02.01_60/ts_103097v010201p.pdf>

<a id="r5"></a>**[R5]** ETSI TS 102 941 V2.2.1 (2022-11). *Intelligent Transport Systems (ITS); Security; Trust and Privacy Management; Release 2.* ETSI. 📁 `pdf/ETSI-C-ITS-trust-arch-102-941-V2.2.1.pdf`

<a id="r6"></a>**[R6]** ETSI TS 102 940. *Intelligent Transport Systems (ITS); Security; ITS communications security architecture and security management; Release 2.* ETSI (non-specific reference, as cited by [R1] [i.1]).

<a id="r7"></a>**[R7]** ETSI TS 102 965. *Intelligent Transport Systems (ITS); Application Object Identifier (ITS-AID); Registration; Release 2.* ETSI (non-specific reference, as cited by [R1] [2]).

<a id="r8"></a>**[R8]** ETSI TS 103 096-1. *Intelligent Transport Systems (ITS); Testing; Conformance test specifications for ITS Security; Part 1: Protocol Implementation Conformance Statement (PICS); Release 2.* ETSI (non-specific reference, as cited by [R1] [i.5]).

<a id="r9"></a>**[R9]** IEEE Std 1609.2™-2016. *IEEE Standard for Wireless Access in Vehicular Environments—Security Services for Applications and Management Messages.* IEEE, 2016. ASN.1 modules `IEEE1609dot2` and `IEEE1609dot2BaseTypes` (major-version-2) as vendored by Vanetza [R24] (`src/asn1/`). Not held by the project; clause references are taken from [R1], [R2] and the sources noted where used.

<a id="r10"></a>**[R10]** IEEE Std 1609.2a™-2017. *IEEE Standard for Wireless Access in Vehicular Environments—Security Services for Applications and Management Messages—Amendment 1.* IEEE, 2017. Not held by the project; cited for the ECIES `P1` parameter as quoted by [R23].

<a id="r11"></a>**[R11]** IEEE Std 1609.2.1™-2022. *IEEE Standard for Wireless Access in Vehicular Environments (WAVE)—Certificate Management Interfaces for End Entities.* IEEE, 2022 (as cited by [R5] [24]). Not held by the project; the Butterfly Key Mechanism is taken from [R5], [R21] and the reference vectors [R22].

<a id="r12"></a>**[R12]** Recommendation ITU-T X.696 (02/2021). *Information technology – ASN.1 encoding rules: Specification of Octet Encoding Rules (OER).* International Telecommunication Union.

<a id="r13"></a>**[R13]** IEEE Std 1363a™-2004. *IEEE Standard Specifications for Public-Key Cryptography—Amendment 1: Additional Techniques.* IEEE, 2004 (KDF2, ECIES, MAC1; as cited by [R4] cl. 5.9).

<a id="r14"></a>**[R14]** NIST FIPS PUB 198-1 (July 2008). *The Keyed-Hash Message Authentication Code (HMAC).* National Institute of Standards and Technology.

<a id="r15"></a>**[R15]** NIST SP 800-38C (May 2004, updated July 2007). *Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality.* NIST.

<a id="r16"></a>**[R16]** NIST FIPS PUB 186-5 (February 2023). *Digital Signature Standard (DSS).* NIST (ECDSA; NIST P-256).

<a id="r17"></a>**[R17]** ETSI EN 302 637-2. *Intelligent Transport Systems (ITS); Vehicular Communications; Basic Set of Applications; Part 2: Specification of Cooperative Awareness Basic Service.* ETSI (non-specific; defines the CAM service-specific permissions).

<a id="r18"></a>**[R18]** ETSI EN 302 637-3. *Intelligent Transport Systems (ITS); Vehicular Communications; Basic Set of Applications; Part 3: Specifications of Decentralized Environmental Notification Basic Service.* ETSI (non-specific; defines the DENM service-specific permissions).

## Research literature

<a id="r19"></a>**[R19]** W. Whyte, A. Weimerskirch, V. Kumar and T. Hehn. "A security credential management system for V2V communications." *2013 IEEE Vehicular Networking Conference (VNC)*, Boston, MA, 2013, pp. 1–8. (Origin of the butterfly key expansion.)

<a id="r20"></a>**[R20]** M. A. Simplicio Jr., E. L. Cominetti, H. Kupwade Patil, J. E. Ricardini and M. V. M. Silva. "The Unified Butterfly Effect: Efficient Security Credential Management System for Vehicular Communications." *2018 IEEE Vehicular Networking Conference (VNC)*, 2018, pp. 1–8. doi:10.1109/VNC.2018.8628369. (Unified butterfly option.)

<a id="r21"></a>**[R21]** A. Boldyreva, V. Kumar and J. Sun. "Provable Security Analysis of Butterfly Key Mechanism Protocol in IEEE 1609.2.1 Standard." *Proceedings on Privacy Enhancing Technologies (PoPETs)*, 2024; full version IACR Cryptology ePrint Archive, Report 2024/1674, 15 October 2024. <https://eprint.iacr.org/2024/1674> (Section 3.3 and Figures 2–4 formalise the IEEE 1609.2.1 protocol.)

## Reference implementations and test vectors

<a id="r22"></a>**[R22]** conz27. *crypto-test-vectors: Test Vectors for SCMS Implementation* (files `bfkeyexp.py`, `bfkeyexp.txt`, `ecies.py`, `ecies.txt`, `kdf.py`, `mac1.py`). GitHub. <https://github.com/conz27/crypto-test-vectors>. Referenced by the CAMP SCMS CV Pilots documentation (<https://wiki.campllc.org/display/SCP/Test+Vectors>).

<a id="r23"></a>**[R23]** CGI (Certificate Services). *c2c-common: IEEE 1609.2 / ETSI TS 103 097 data structures and cryptography in Java*, in particular `ieee1609dot2/datastructs/enc/RecipientInfo.java` and `common/crypto/DefaultCryptoManager.java`. GitHub. <https://github.com/pvendil/c2c-common>

<a id="r24"></a>**[R24]** NAP / Instituto de Telecomunicações. *Vanetza-NAP*, branch `release2-main`, commit `241438fd` (2026-09-01), with the vnap-secure patches (see [R30]). GitHub. <https://github.com/nap-it/vanetza-nap>. Source files cited: `vanetza/security/v2/*`, `vanetza/security/v3/*`, `vanetza/security/straight_verify_service.cpp`, `tools/certify/*`.

<a id="r25"></a>**[R25]** R. Riebl et al. *Vanetza: an open-source implementation of the ETSI C-ITS protocol suite.* GitHub. <https://github.com/riebl/vanetza> (upstream of [R24]).

## Project documents and software

<a id="r26"></a>**[R26]** *Product Requirements Document — C-ITS PKI Implementation, Certificate Generation conforming to ETSI TS 103 097 V2.2.1*, version 1.0 (Draft), 20 March 2026. 📁 `pdf/C-ITS_PKI_PRD.pdf`

<a id="r27"></a>**[R27]** E. Moqvist. *asn1tools* 0.169.0 — ASN.1 parsing, encoding and decoding (OER codec). <https://github.com/eerimoq/asn1tools>

<a id="r28"></a>**[R28]** Python Cryptographic Authority. *pyca/cryptography* ≥ 46 (OpenSSL backend: ECDSA, ECDH, AES-CCM, AES-ECB, key serialisation). <https://cryptography.io>

<a id="r29"></a>**[R29]** alexmgr (GitHub). *tinyec* 0.4.0 — elliptic curve arithmetic in pure Python. <https://github.com/alexmgr/tinyec>

<a id="r30"></a>**[R30]** *vnap-secure* companion repository (branch `jodyhuntatx`): Vanetza-NAP release2 patch set (`vnap-patches/`, `vnap-origs/`) and build (`docker-build.sh` → `vnap:latest`); simulation harness `start-vnap.sh` (docker-compose) and `vnap-docker/run-r2-sim.sh`, `vnap-docker/check-r2-cams.sh`; and the message checker `vnap-docker/msgcheck/vnap-msgcheck.cpp` (built as `vnap:msgcheck` with `vnap-docker/msgcheck/build-msgcheck.sh`). Documented in its `README.md`.
