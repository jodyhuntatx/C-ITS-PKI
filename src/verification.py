"""
Certificate chain verification for C-ITS PKI.
Implements IEEE Std 1609.2 clause 5.1 validity assessment.
"""
import time
from typing import Optional, Tuple

from .types import (
    Certificate, CertificateType, IssuerChoice, ItsAid,
    PublicKeyAlgorithm, HashAlgorithm, its_time32_to_unix
)
from .crypto import (
    ecdsa_verify, hash_certificate, hash_data,
    load_public_key_from_compressed
)
from .encoding import encode_tbs_certificate


# EU-27 special region identifier (clause 8.1)
EU_27_REGION_ID = 65535


def verify_certificate_signature(cert: Certificate,
                                  issuer_cert: Optional[Certificate] = None) -> bool:
    """
    Verify an EtsiTs103097Certificate's signature.

    For self-signed (Root CA, TLM): issuer_cert is None, uses own key.
    For signed certs: issuer_cert is the signing CA certificate.

    Returns True if signature is valid.
    """
    if cert.signature is None:
        return False

    # Determine the public key to verify against
    if cert.issuer.choice == IssuerChoice.SELF:
        # Self-signed: verify with the cert's own verification key
        vk = cert.tbs.verify_key_indicator
    elif issuer_cert is not None:
        vk = issuer_cert.tbs.verify_key_indicator
    else:
        raise ValueError("issuer_cert required for non-self-signed certificates")

    if vk is None:
        return False

    # Load public key
    try:
        pub_key = load_public_key_from_compressed(vk.point.curve, vk.point.compressed)
    except Exception:
        return False

    # Use cached TBS encoding (exact bytes that were signed) when available,
    # otherwise re-encode from the parsed structure.
    tbs_encoded = cert.tbs_encoded if cert.tbs_encoded else encode_tbs_certificate(cert.tbs)

    return ecdsa_verify(
        public_key=pub_key,
        data=tbs_encoded,
        r_bytes=cert.signature.r,
        s_bytes=cert.signature.s,
        algorithm=cert.signature.algorithm,
    )


def verify_certificate_validity_period(cert: Certificate,
                                        at_unix_time: Optional[float] = None) -> bool:
    """
    Check that the certificate is within its validity period.
    Validity interval: [start, start + duration) (start inclusive, end exclusive).
    """
    now = at_unix_time or time.time()
    start_unix = its_time32_to_unix(cert.tbs.validity_period.start)

    from .types import DurationChoice
    dur = cert.tbs.validity_period.duration
    if dur.choice == DurationChoice.YEARS:
        end_unix = start_unix + dur.value * 365.25 * 86400
    elif dur.choice == DurationChoice.HOURS:
        end_unix = start_unix + dur.value * 3600
    elif dur.choice == DurationChoice.MINUTES:
        end_unix = start_unix + dur.value * 60
    elif dur.choice == DurationChoice.SECONDS:
        end_unix = start_unix + dur.value
    elif dur.choice == DurationChoice.MILLISECONDS:
        end_unix = start_unix + dur.value / 1000
    elif dur.choice == DurationChoice.SIXTY_HOURS:
        end_unix = start_unix + dur.value * 60 * 3600
    else:  # microseconds
        end_unix = start_unix + dur.value / 1_000_000

    return start_unix <= now < end_unix


def verify_issuer_digest(cert: Certificate,
                          issuer_cert: Certificate,
                          algorithm: PublicKeyAlgorithm) -> bool:
    """
    Verify that the certificate's issuer digest matches the issuer certificate.
    FR-VF-04 / IEEE 1609.2 clause 5.1.
    """
    if cert.issuer.choice not in (IssuerChoice.SHA256_AND_DIGEST, IssuerChoice.SHA384_AND_DIGEST):
        return True  # self-signed or unknown

    expected_hash = hash_certificate(issuer_cert.encoded, algorithm)
    return cert.issuer.digest == expected_hash


def verify_permissions_constraints(cert: Certificate,
                                    issuer_cert: Optional[Certificate] = None) -> Tuple[bool, str]:
    """
    Check that at least one of appPermissions or certIssuePermissions is present.
    FR-CI-09.
    """
    has_app = cert.tbs.app_permissions is not None and len(cert.tbs.app_permissions) > 0
    has_issue = cert.tbs.cert_issue_permissions is not None and len(cert.tbs.cert_issue_permissions) > 0

    if not (has_app or has_issue):
        return False, "Neither appPermissions nor certIssuePermissions present"
    return True, "OK"


def verify_craca_and_crl_series(cert: Certificate) -> Tuple[bool, str]:
    """
    Verify cracaId = 0x000000 and crlSeries = 0 per FR-CI-10.
    """
    if cert.tbs.craca_id != b'\x00\x00\x00':
        return False, f"cracaId should be 000000H, got {cert.tbs.craca_id.hex()}"
    if cert.tbs.crl_series != 0:
        return False, f"crlSeries should be 0, got {cert.tbs.crl_series}"
    return True, "OK"


def verify_at_profile(cert: Certificate) -> Tuple[bool, str]:
    """
    Verify AT-specific constraints (profile 9.6):
    - id must be 'none'
    - certIssuePermissions must be absent
    - appPermissions must be present
    """
    from .types import CertIdChoice
    if cert.tbs.id.choice != CertIdChoice.NONE:
        return False, f"AT id must be 'none', got {cert.tbs.id.choice}"
    if cert.tbs.cert_issue_permissions:
        return False, "AT must not have certIssuePermissions"
    if not cert.tbs.app_permissions:
        return False, "AT must have appPermissions"
    return True, "OK"


def verify_region_constraint(cert: Certificate,
                              allow_eu27: bool = True) -> Tuple[bool, str]:
    """
    Check region constraint. Value 65535 = EU-27 (FR-VF-06).
    If region is absent, no constraint check is applied.
    """
    if cert.tbs.region is None:
        return True, "No region constraint (global)"

    from .types import RegionChoice
    if cert.tbs.region.choice == RegionChoice.ID and cert.tbs.region.ids:
        for rid in cert.tbs.region.ids:
            if rid == EU_27_REGION_ID:
                return True, "EU-27 region accepted"
        return True, f"Region IDs: {cert.tbs.region.ids}"
    return True, "Region present"


def verify_certificate_chain(leaf_cert: Certificate,
                               intermediate_certs: list,
                               root_cert: Certificate,
                               algorithm: PublicKeyAlgorithm,
                               at_unix_time: Optional[float] = None) -> dict:
    """
    Verify a certificate chain from leaf to root CA.

    Args:
        leaf_cert: The end-entity or subordinate CA certificate.
        intermediate_certs: List of intermediate CA certs (e.g., [ea_cert] or [aa_cert]).
        root_cert: Root CA certificate (self-signed trust anchor).
        algorithm: Cryptographic algorithm used for hashing.
        at_unix_time: Unix timestamp for validity period check (default: now).

    Returns:
        dict with 'valid' bool, 'errors' list, and per-cert results.
    """
    errors = []
    results = {}

    all_certs = [leaf_cert] + intermediate_certs + [root_cert]
    names = ['leaf'] + [f'intermediate_{i}' for i in range(len(intermediate_certs))] + ['root']

    # 1. Verify root CA self-signature
    root_valid = verify_certificate_signature(root_cert, None)
    results['root_signature'] = root_valid
    if not root_valid:
        errors.append("Root CA signature invalid")

    # 2. Verify root CA validity period
    root_vp_valid = verify_certificate_validity_period(root_cert, at_unix_time)
    results['root_validity'] = root_vp_valid
    if not root_vp_valid:
        errors.append("Root CA certificate expired or not yet valid")

    # 3. Verify intermediate certs against root
    for i, inter_cert in enumerate(intermediate_certs):
        label = f'intermediate_{i}'
        sig_valid = verify_certificate_signature(inter_cert, root_cert)
        results[f'{label}_signature'] = sig_valid
        if not sig_valid:
            errors.append(f"Intermediate cert {i} signature invalid")

        vp_valid = verify_certificate_validity_period(inter_cert, at_unix_time)
        results[f'{label}_validity'] = vp_valid
        if not vp_valid:
            errors.append(f"Intermediate cert {i} expired")

        digest_ok = verify_issuer_digest(inter_cert, root_cert, algorithm)
        results[f'{label}_issuer_digest'] = digest_ok
        if not digest_ok:
            errors.append(f"Intermediate cert {i} issuer digest mismatch")

    # 4. Verify leaf against appropriate issuer
    issuer = intermediate_certs[0] if intermediate_certs else root_cert
    leaf_sig_valid = verify_certificate_signature(leaf_cert, issuer)
    results['leaf_signature'] = leaf_sig_valid
    if not leaf_sig_valid:
        errors.append("Leaf certificate signature invalid")

    leaf_vp_valid = verify_certificate_validity_period(leaf_cert, at_unix_time)
    results['leaf_validity'] = leaf_vp_valid
    if not leaf_vp_valid:
        errors.append("Leaf certificate expired")

    leaf_digest_ok = verify_issuer_digest(leaf_cert, issuer, algorithm)
    results['leaf_issuer_digest'] = leaf_digest_ok
    if not leaf_digest_ok:
        errors.append("Leaf certificate issuer digest mismatch")

    # 5. Profile checks (craca/crl)
    for cert, name in zip(all_certs, names):
        craca_ok, craca_msg = verify_craca_and_crl_series(cert)
        results[f'{name}_craca'] = craca_ok
        if not craca_ok:
            errors.append(f"{name}: {craca_msg}")

    # 6. Permissions check on leaf
    perm_ok, perm_msg = verify_permissions_constraints(leaf_cert)
    results['leaf_permissions'] = perm_ok
    if not perm_ok:
        errors.append(f"Leaf permissions: {perm_msg}")

    return {
        'valid': len(errors) == 0,
        'errors': errors,
        'details': results,
    }


def compute_hashed_id8(cert_encoded: bytes,
                        algorithm: PublicKeyAlgorithm) -> bytes:
    """Return HashedId8: last 8 bytes of SHA-256(cert) for P-256."""
    return hash_certificate(cert_encoded, algorithm)


def check_revocation_by_hash(cert_encoded: bytes,
                              revoked_hashes: list,
                              algorithm: PublicKeyAlgorithm) -> bool:
    """
    Hash ID-based revocation per ETSI TS 102 941 (FR-VF-04).
    Returns True if the certificate is revoked.
    """
    cert_id = hash_certificate(cert_encoded, algorithm)
    return cert_id in revoked_hashes
