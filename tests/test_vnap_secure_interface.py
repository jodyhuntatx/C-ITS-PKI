"""Contract test: the part of src/ that vnap-secure's per-run PKI service uses
(vnap-secure sim/images/pki/pki_service.py; Operations Guide §8.2). A failure here means that
vnap-secure's per-run PKI breaks with this version of C-ITS-PKI.

  uv run --project tests/v3 python -m unittest tests/test_vnap_secure_interface.py
  (or any Python with the requirements installed, from the repository root)"""

import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import certificates, crypto, pki, types  # noqa: E402

# module -> names imported by pki_service.py
IMPORTED = {
    pki: ["CITSPKI", "PKIEntity"],
    certificates: ["issue_butterfly_authorization_tickets"],
    crypto: ["bke_butterfly_private_key", "bke_cocoon_private_key", "bke_cocoon_public_key", "deserialize_private_key",
             "generate_keypair", "public_key_to_point", "random_bytes", "serialize_private_key"],
    types: ["Certificate", "CertificateId", "CertificateType", "CertIdChoice", "Duration", "DurationChoice", "EtsiVersion",
            "IssuerChoice", "IssuerIdentifier", "PsidSsp", "PublicKeyAlgorithm", "ToBeSignedCertificate", "ValidityPeriod",
            "now_its_time32"],
}

# callable -> keyword arguments pki_service.py passes
KEYWORDS = {
    "CITSPKI": ["algorithm", "version"],
    "CITSPKI.initialise": ["root_ca_name", "tlm_name", "ea_name", "aa_name"],
    "CITSPKI.issue_authorization_ticket": ["app_psids", "validity_hours"],
    "CITSPKI.enrol_its_station": ["name"],
    "CITSPKI.issue_butterfly_authorization_tickets": ["caterpillar_sign_priv", "sign_expansion_key", "i_value", "count", "mode",
                                                      "caterpillar_enc_priv", "enc_expansion_key"],
    "PKIEntity": ["name", "sign_priv_key", "sign_pub_key", "certificate", "algorithm"],
    "issue_butterfly_authorization_tickets": ["cocoon_sign_pubs", "aa_cert", "aa_priv_key", "app_psids", "sign_algorithm",
                                              "validity_hours", "region_ids", "version"],
}


def resolve(name):
    obj = {"issue_butterfly_authorization_tickets": certificates.issue_butterfly_authorization_tickets}.get(name)
    if obj is None:
        owner, _, attr = name.partition(".")
        obj = getattr(pki, owner)
        if attr:
            obj = getattr(obj, attr)
    return obj


class VnapSecureInterface(unittest.TestCase):
    def test_imported_names_exist(self):
        for module, names in IMPORTED.items():
            for name in names:
                with self.subTest(module=module.__name__, name=name):
                    self.assertTrue(hasattr(module, name), f"{module.__name__}.{name} is gone")

    def test_keyword_arguments_are_accepted(self):
        for name, keywords in KEYWORDS.items():
            params = inspect.signature(resolve(name)).parameters
            takes_kwargs = any(p.kind is p.VAR_KEYWORD for p in params.values())
            for kw in keywords:
                with self.subTest(callable=name, keyword=kw):
                    self.assertTrue(kw in params or takes_kwargs, f"{name}() no longer takes {kw}=")

    def test_pki_members_used(self):
        for attr in ("save", "aa", "region_ids"):
            with self.subTest(attr=attr):
                self.assertTrue(hasattr(pki.CITSPKI, attr) or attr in inspect.signature(pki.CITSPKI).parameters
                                or attr in getattr(pki.CITSPKI, "__annotations__", {}) or self._instance_has(attr),
                                f"CITSPKI.{attr} is gone")

    def _instance_has(self, attr):
        obj = pki.CITSPKI(algorithm=types.PublicKeyAlgorithm(list(types.PublicKeyAlgorithm)[0].value),
                          version=list(types.EtsiVersion)[-1])
        return hasattr(obj, attr)

    def test_butterfly_expansion_is_consistent(self):
        """The station derives private keys, the PKI the matching public keys (vnap-secure key_derivation=station)."""
        caterpillar, caterpillar_pub = crypto.generate_keypair(types.PublicKeyAlgorithm.ECDSA_NIST_P256)
        expansion = crypto.random_bytes(16)
        for i_value, j in ((0, 0), (3, 7)):
            with self.subTest(i=i_value, j=j):
                private = crypto.bke_cocoon_private_key(caterpillar, expansion, i_value, j)
                public = crypto.bke_cocoon_public_key(caterpillar_pub, expansion, i_value, j)
                self.assertEqual(crypto.public_key_to_point(private.public_key()), crypto.public_key_to_point(public))


if __name__ == "__main__":
    unittest.main()
