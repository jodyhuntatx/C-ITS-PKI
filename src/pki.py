"""
PKI Hierarchy Manager for C-ITS PKI.
Manages the full certificate hierarchy: Root CA, EA, AA, TLM, and end-entities.
"""
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .types import PublicKeyAlgorithm, ItsAid, PsidSsp, KeyPair
from .crypto import (
    generate_keypair, serialize_private_key, deserialize_private_key,
    hash_certificate, random_bytes
)
from .certificates import (
    issue_root_ca_certificate, issue_ea_certificate, issue_aa_certificate,
    issue_tlm_certificate, issue_enrolment_credential, issue_authorization_ticket,
    issue_butterfly_authorization_tickets as _issue_bke_ats
)


@dataclass
class PKIEntity:
    """Represents a PKI entity with signing and optionally encryption keys."""
    name: str
    sign_priv_key: object
    sign_pub_key: object
    enc_priv_key: Optional[object] = None
    enc_pub_key: Optional[object] = None
    certificate: object = None  # Certificate
    algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256


class CITSPKI:
    """
    C-ITS PKI Hierarchy Manager.

    Initialises and manages the full ETSI TS 103 097 compliant PKI:
      - Root CA (self-signed, trust anchor)
      - Trust List Manager (self-signed)
      - Enrolment Authority (EA, signed by Root CA)
      - Authorization Authority (AA, signed by Root CA)
      - ITS-Station enrolment (EC issued by EA)
      - Authorization Ticket issuance (AT issued by AA)
    """

    def __init__(self,
                 algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA_NIST_P256,
                 region_ids: Optional[list] = None):
        """
        Args:
            algorithm: Default signing algorithm (P-256 or P-384).
            region_ids: List of geographic region IDs. Use [65535] for EU-27.
        """
        self.algorithm = algorithm
        self.enc_algorithm = (PublicKeyAlgorithm.ECIES_NIST_P256
                              if algorithm == PublicKeyAlgorithm.ECDSA_NIST_P256
                              else PublicKeyAlgorithm.ECIES_NIST_P384)
        self.region_ids = region_ids

        self.root_ca: Optional[PKIEntity] = None
        self.tlm: Optional[PKIEntity] = None
        self.ea: Optional[PKIEntity] = None
        self.aa: Optional[PKIEntity] = None

    # ── Initialisation ────────────────────────────────────────────────────────

    def initialise(self,
                   root_ca_name: str = "C-ITS-Root-CA",
                   tlm_name: str = "C-ITS-TLM",
                   ea_name: str = "C-ITS-EA",
                   aa_name: str = "C-ITS-AA",
                   root_validity_years: int = 10,
                   tlm_validity_years: int = 10,
                   ea_validity_years: int = 5,
                   aa_validity_years: int = 5,
                   start_time: Optional[float] = None) -> dict:
        """
        Initialise the full PKI hierarchy per Appendix A.1 of the PRD.

        Returns a dict of all generated certificates (COER-encoded bytes).
        """
        t = start_time or time.time()

        # Step 1: Root CA
        print(f"[PKI] Generating Root CA key pair...")
        rca_sign_priv, rca_sign_pub = generate_keypair(self.algorithm)

        print(f"[PKI] Issuing Root CA self-signed certificate...")
        rca_cert = issue_root_ca_certificate(
            name=root_ca_name,
            sign_priv_key=rca_sign_priv,
            sign_pub_key=rca_sign_pub,
            algorithm=self.algorithm,
            validity_years=root_validity_years,
            region_ids=self.region_ids,
            start_time=t,
        )
        self.root_ca = PKIEntity(
            name=root_ca_name,
            sign_priv_key=rca_sign_priv,
            sign_pub_key=rca_sign_pub,
            certificate=rca_cert,
            algorithm=self.algorithm,
        )

        # Step 2: TLM
        print(f"[PKI] Generating TLM key pair...")
        tlm_sign_priv, tlm_sign_pub = generate_keypair(self.algorithm)

        print(f"[PKI] Issuing TLM self-signed certificate...")
        tlm_cert = issue_tlm_certificate(
            name=tlm_name,
            tlm_sign_priv_key=tlm_sign_priv,
            tlm_sign_pub_key=tlm_sign_pub,
            algorithm=self.algorithm,
            validity_years=tlm_validity_years,
            start_time=t,
        )
        self.tlm = PKIEntity(
            name=tlm_name,
            sign_priv_key=tlm_sign_priv,
            sign_pub_key=tlm_sign_pub,
            certificate=tlm_cert,
            algorithm=self.algorithm,
        )

        # Step 3: EA signing + encryption keys
        print(f"[PKI] Generating EA key pairs (signing + encryption)...")
        ea_sign_priv, ea_sign_pub = generate_keypair(self.algorithm)
        ea_enc_priv, ea_enc_pub = generate_keypair(self.enc_algorithm)

        print(f"[PKI] Issuing EA certificate (signed by Root CA)...")
        ea_cert = issue_ea_certificate(
            name=ea_name,
            ea_sign_priv_key=ea_sign_priv,
            ea_sign_pub_key=ea_sign_pub,
            ea_enc_pub_key=ea_enc_pub,
            root_ca_cert=rca_cert,
            root_ca_priv_key=rca_sign_priv,
            sign_algorithm=self.algorithm,
            enc_algorithm=self.enc_algorithm,
            validity_years=ea_validity_years,
            region_ids=self.region_ids,
            start_time=t,
        )
        self.ea = PKIEntity(
            name=ea_name,
            sign_priv_key=ea_sign_priv,
            sign_pub_key=ea_sign_pub,
            enc_priv_key=ea_enc_priv,
            enc_pub_key=ea_enc_pub,
            certificate=ea_cert,
            algorithm=self.algorithm,
        )

        # Step 4: AA signing + encryption keys
        print(f"[PKI] Generating AA key pairs (signing + encryption)...")
        aa_sign_priv, aa_sign_pub = generate_keypair(self.algorithm)
        aa_enc_priv, aa_enc_pub = generate_keypair(self.enc_algorithm)

        print(f"[PKI] Issuing AA certificate (signed by Root CA)...")
        aa_cert = issue_aa_certificate(
            name=aa_name,
            aa_sign_priv_key=aa_sign_priv,
            aa_sign_pub_key=aa_sign_pub,
            aa_enc_pub_key=aa_enc_pub,
            root_ca_cert=rca_cert,
            root_ca_priv_key=rca_sign_priv,
            sign_algorithm=self.algorithm,
            enc_algorithm=self.enc_algorithm,
            validity_years=aa_validity_years,
            region_ids=self.region_ids,
            start_time=t,
        )
        self.aa = PKIEntity(
            name=aa_name,
            sign_priv_key=aa_sign_priv,
            sign_pub_key=aa_sign_pub,
            enc_priv_key=aa_enc_priv,
            enc_pub_key=aa_enc_pub,
            certificate=aa_cert,
            algorithm=self.algorithm,
        )

        print(f"[PKI] Initialisation complete.")
        return {
            'root_ca': rca_cert.encoded,
            'tlm': tlm_cert.encoded,
            'ea': ea_cert.encoded,
            'aa': aa_cert.encoded,
        }

    # ── Butterfly Key Expansion AT Batch Provisioning ─────────────────────────
    def issue_butterfly_authorization_tickets(
        self,
        caterpillar_sign_priv,
        expansion_values: list,
        app_psids: Optional[list] = None,
        validity_hours: int = 168,
        region_ids: Optional[list] = None,
        start_time: Optional[float] = None,
    ) -> list:
        """
        Issue a batch of ATs via BKE (IEEE 1609.2a §6.4.3.7).
        Returns list of dicts: at, certificate, sign_priv_key, sign_pub_key,
        expansion_value, priv_key_pem.
        """
        if self.aa is None:
            raise RuntimeError("PKI not initialised. Call initialise() first.")
        from .crypto import bke_expand_private_key

        at_certs = _issue_bke_ats(
            caterpillar_sign_pub=caterpillar_sign_priv.public_key(),
            expansion_values=expansion_values,
            aa_cert=self.aa.certificate,
            aa_priv_key=self.aa.sign_priv_key,
            app_psids=app_psids,
            sign_algorithm=self.algorithm,
            validity_hours=validity_hours,
            region_ids=region_ids or self.region_ids,
            start_time=start_time,
        )
        results = []
        for cert, e_i in zip(at_certs, expansion_values):
            at_priv = bke_expand_private_key(caterpillar_sign_priv, e_i)
            results.append({
                'at': cert.encoded,
                'certificate': cert,
                'sign_priv_key': at_priv,
                'sign_pub_key': at_priv.public_key(),
                'expansion_value': e_i,
                'priv_key_pem': serialize_private_key(at_priv),
            })
        return results
    
    # ── ITS-Station Enrolment ─────────────────────────────────────────────────

    def enrol_its_station(self,
                          name: str,
                          validity_years: int = 1,
                          region_ids: Optional[list] = None,
                          start_time: Optional[float] = None) -> dict:
        """
        Enrol an ITS-Station and issue an Enrolment Credential (EC).
        Per Appendix A.2 of the PRD.

        Returns dict with 'ec' (COER bytes) and 'priv_key' (PEM bytes).
        """
        if self.ea is None:
            raise RuntimeError("PKI not initialised. Call initialise() first.")

        t = start_time or time.time()
        its_sign_priv, its_sign_pub = generate_keypair(self.algorithm)

        ec = issue_enrolment_credential(
            name=name,
            its_sign_priv_key=its_sign_priv,
            its_sign_pub_key=its_sign_pub,
            ea_cert=self.ea.certificate,
            ea_priv_key=self.ea.sign_priv_key,
            sign_algorithm=self.algorithm,
            validity_years=validity_years,
            region_ids=region_ids or self.region_ids,
            start_time=t,
        )

        return {
            'ec': ec.encoded,
            'certificate': ec,
            'sign_priv_key': its_sign_priv,
            'sign_pub_key': its_sign_pub,
            'priv_key_pem': serialize_private_key(its_sign_priv),
        }

    # ── Authorization Ticket Provisioning ────────────────────────────────────

    def issue_authorization_ticket(self,
                                   app_psids: Optional[list] = None,
                                   validity_hours: int = 168,
                                   region_ids: Optional[list] = None,
                                   start_time: Optional[float] = None) -> dict:
        """
        Issue an Authorization Ticket (AT) to an ITS-Station.
        Per Appendix A.3 of the PRD.

        Returns dict with 'at' (COER bytes), private key, and certificate object.
        """
        if self.aa is None:
            raise RuntimeError("PKI not initialised. Call initialise() first.")

        t = start_time or time.time()

        # Fresh AT key pair (independent from EC key)
        at_sign_priv, at_sign_pub = generate_keypair(self.algorithm)

        at = issue_authorization_ticket(
            its_sign_priv_key=at_sign_priv,
            its_sign_pub_key=at_sign_pub,
            aa_cert=self.aa.certificate,
            aa_priv_key=self.aa.sign_priv_key,
            app_psids=app_psids or [
                PsidSsp(psid=ItsAid.CAM),
                PsidSsp(psid=ItsAid.DENM),
            ],
            sign_algorithm=self.algorithm,
            validity_hours=validity_hours,
            region_ids=region_ids or self.region_ids,
            start_time=t,
        )

        return {
            'at': at.encoded,
            'certificate': at,
            'sign_priv_key': at_sign_priv,
            'sign_pub_key': at_sign_pub,
            'priv_key_pem': serialize_private_key(at_sign_priv),
        }

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, output_dir: str) -> None:
        """Save all PKI certificates and private keys to output_dir."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        entities = {
            'root_ca': self.root_ca,
            'tlm': self.tlm,
            'ea': self.ea,
            'aa': self.aa,
        }

        for entity_name, entity in entities.items():
            if entity is None:
                continue
            # Save certificate (COER binary)
            cert_path = out / f"{entity_name}.cert"
            cert_path.write_bytes(entity.certificate.encoded)

            # Save signing private key (PEM)
            key_path = out / f"{entity_name}_sign.key"
            key_path.write_bytes(serialize_private_key(entity.sign_priv_key))

            # Save encryption key if present
            if entity.enc_priv_key is not None:
                enc_key_path = out / f"{entity_name}_enc.key"
                enc_key_path.write_bytes(serialize_private_key(entity.enc_priv_key))

        # Save metadata
        meta = {
            'algorithm': int(self.algorithm),
            'region_ids': self.region_ids,
            'entities': [k for k, v in entities.items() if v is not None],
        }
        (out / 'pki_meta.json').write_text(json.dumps(meta, indent=2))
        print(f"[PKI] Saved to {output_dir}")

    def get_cert_chain(self, entity_name: str) -> list:
        """Return the certificate chain for an entity (leaf → Root CA)."""
        chain = []
        entity_map = {
            'root_ca': self.root_ca,
            'tlm': self.tlm,
            'ea': self.ea,
            'aa': self.aa,
        }
        if entity_name in ('ea', 'aa'):
            chain.append(entity_map[entity_name].certificate.encoded)
            chain.append(self.root_ca.certificate.encoded)
        elif entity_name in ('root_ca', 'tlm'):
            chain.append(entity_map[entity_name].certificate.encoded)
        return chain
