#!/usr/bin/env python3
"""
C-ITS PKI Command-Line Interface

Two certificate/message formats, selected at init time (see docs/operations.md):
  v2 = ETSI TS 103 097 V1.2.1 binary format (vanetza security/v2)
  v3 = ETSI TS 103 097 V1.3.1 / IEEE Std 1609.2-2016 COER format (vanetza security/v3)

Usage:
    python cli.py init        [--output DIR] [--algo p256] [--region REGION_IDS]
                              [--etsi-version v2|v3]
    python cli.py enrol       --output DIR --name ITS_NAME [--validity YEARS]
    python cli.py issue-at    --output DIR [--psid 36,37] [--validity HOURS] [--at-output DIR]
    python cli.py butterfly-at --output DIR [--count 8] [--psid 36,37] [--validity 168]
                              [--mode original|unified] [--i-value N]
    python cli.py sign-cam    --at-key FILE --at-cert FILE --payload FILE [--output FILE]
    python cli.py sign-denm   --at-key FILE --at-cert FILE --payload FILE --lat LAT --lon LON
    python cli.py verify-sig  --signed FILE --at-cert FILE [--root FILE] [--aa FILE]
    python cli.py encrypt     --enc-cert FILE --enc-key FILE --payload FILE [--output FILE]
    python cli.py decrypt     --enc-cert FILE --enc-key FILE --input FILE
    python cli.py verify-cert --cert FILE [--issuer FILE] [--root FILE]
    python cli.py info        --cert FILE
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def main():
    parser = argparse.ArgumentParser(
        description='C-ITS PKI - ETSI TS 103 097 V1.2.1 / V2.2.1 Certificate Management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # init
    p_init = sub.add_parser('init', help='Initialise PKI hierarchy')
    p_init.add_argument('--output', '-o', default='pki-output', help='Output directory')
    p_init.add_argument('--algo', choices=['p256', 'p384'], default='p256',
                        help='Signing curve; only p256 is accepted for v2 and v3 certificates')
    p_init.add_argument('--region', default=None, help='Comma-separated region IDs (e.g. 65535=EU-27); omit for no region restriction')
    p_init.add_argument('--etsi-version', choices=['v2', 'v3'], default='v2',
                        dest='etsi_version',
                        help='ETSI TS 103 097 standard version: '
                             'v2 = V1.2.1 vanetza-compatible binary format [default], '
                             'v3 = V1.3.1 COER format (IEEE 1609.2-2016 schema used by vanetza)')
    p_init.add_argument('--root-name', default='C-ITS-Root-CA')
    p_init.add_argument('--tlm-name', default='C-ITS-TLM')
    p_init.add_argument('--ea-name', default='C-ITS-EA')
    p_init.add_argument('--aa-name', default='C-ITS-AA')

    # enrol
    p_enrol = sub.add_parser('enrol', help='Issue Enrolment Credential to ITS-Station')
    p_enrol.add_argument('--output', '-o', default='pki-output', help='PKI directory')
    p_enrol.add_argument('--name', required=True, help='ITS-Station name')
    p_enrol.add_argument('--validity', type=int, default=1, help='Validity in years')
    p_enrol.add_argument('--ec-output', help='Output directory for EC (default: pki-output/its-stations/NAME)')

    # issue-at
    p_at = sub.add_parser('issue-at', help='Issue Authorization Ticket')
    p_at.add_argument('--output', '-o', default='pki-output', help='PKI directory')
    p_at.add_argument('--psid', help='Comma-separated PSIDs (default: 36,37)')
    p_at.add_argument('--validity', type=int, default=168, help='Validity in hours (default: 168=1 week)')
    p_at.add_argument('--at-output', help='Output directory for AT')

    # butterfly-at
    p_bke = sub.add_parser('butterfly-at', help='Issue a batch of ATs via Butterfly Key Expansion')
    p_bke.add_argument('--output', '-o', default='pki-output')
    p_bke.add_argument('--count', type=int, default=8, help='Number of ATs to issue (default: 8)')
    p_bke.add_argument('--psid', help='Comma-separated PSIDs (default: 36,37)')
    p_bke.add_argument('--validity', type=int, default=168, help='Validity in hours (default: 168=1 week)')
    p_bke.add_argument('--at-output', help='Output directory for AT')
    p_bke.add_argument('--mode', choices=['original', 'unified'], default='original',
                       help='IEEE 1609.2.1 butterfly option (default: original)')
    p_bke.add_argument('--i-value', type=int, default=None, dest='i_value',
                       help='i-period for the expansion (default: weeks since 2004-01-01)')

    # sign-cam
    p_cam = sub.add_parser('sign-cam', help='Sign a CAM payload')
    p_cam.add_argument('--at-key', required=True)
    p_cam.add_argument('--at-cert', required=True)
    p_cam.add_argument('--payload', required=True)
    p_cam.add_argument('--output', '-o')
    p_cam.add_argument('--full-cert', action='store_true', help='Include full AT certificate (not just digest)')

    # sign-denm
    p_denm = sub.add_parser('sign-denm', help='Sign a DENM payload')
    p_denm.add_argument('--at-key', required=True)
    p_denm.add_argument('--at-cert', required=True)
    p_denm.add_argument('--payload', required=True)
    p_denm.add_argument('--lat', required=True, help='Latitude in decimal degrees')
    p_denm.add_argument('--lon', required=True, help='Longitude in decimal degrees')
    p_denm.add_argument('--elev', default='0', help='Elevation in metres')
    p_denm.add_argument('--output', '-o')

    # verify-sig
    p_vcam = sub.add_parser('verify-sig', help='Verify a signed C-ITS message file')
    p_vcam.add_argument('--signed', required=True,
                        help='Signed C-ITS message file (v3 EtsiTs103097Data-Signed or v2 SecuredMessage)')
    p_vcam.add_argument('--at-cert', required=True,
                        help='AT certificate used to sign the C-ITS message file')
    p_vcam.add_argument('--root', default=None,
                        help='Root CA certificate for chain verification')
    p_vcam.add_argument('--aa', default=None,
                        help='AA certificate for chain verification')
    p_vcam.add_argument('--etsi-version', choices=['v2', 'v3'], default=None,
                        dest='etsi_version',
                        help='ETSI TS 103 097 version of the certificate files '
                             '(auto-detected from pki_meta.json if omitted, otherwise defaults to v2)')
    
    # encrypt
    p_enc = sub.add_parser('encrypt', help='Encrypt a payload for a recipient')
    p_enc.add_argument('--enc-cert', required=True, help='Recipient certificate')
    p_enc.add_argument('--enc-key', required=True, help='Recipient encryption private key (PKCS#8 DER, unused for encryption)')
    p_enc.add_argument('--payload', required=True)
    p_enc.add_argument('--output', '-o')
    p_enc.add_argument('--etsi-version', choices=['v2', 'v3'], default=None,
                       dest='etsi_version',
                       help='ETSI TS 103 097 version of the certificate '
                            '(auto-detected from pki_meta.json if omitted, otherwise defaults to v2)')

    # decrypt
    p_dec = sub.add_parser('decrypt', help='Decrypt an encrypted message')
    p_dec.add_argument('--enc-cert', required=True, help='Your certificate')
    p_dec.add_argument('--enc-key', required=True, help='Your encryption private key (PKCS#8 DER)')
    p_dec.add_argument('--input', '-i', required=True, help='Encrypted message file')
    p_dec.add_argument('--output', '-o')

    # verify-cert
    p_ver = sub.add_parser('verify-cert', help='Verify a certificate')
    p_ver.add_argument('--cert', required=True)
    p_ver.add_argument('--issuer', help='Issuer certificate (omit for self-signed)')
    p_ver.add_argument('--root', help='Root CA certificate')
    p_ver.add_argument('--etsi-version', choices=['v2', 'v3'], default=None,
                       dest='etsi_version',
                       help='ETSI TS 103 097 version used to encode the certificate '
                            '(auto-detected from pki_meta.json if omitted, otherwise defaults to v2)')

    # info
    p_info = sub.add_parser('info', help='Display certificate information')
    p_info.add_argument('--cert', required=True)
    p_info.add_argument('--etsi-version', choices=['v2', 'v3'], default=None,
                        dest='etsi_version',
                        help='ETSI TS 103 097 version used to encode the certificate '
                             '(auto-detected from pki_meta.json if omitted, otherwise defaults to v2)')

    args = parser.parse_args()

    dispatch = {
        'init': cmd_init,
        'enrol': cmd_enrol,
        'issue-at': cmd_issue_at,
        'butterfly-at': cmd_butterfly_at,
        'sign-cam': cmd_sign_cam,
        'sign-denm': cmd_sign_denm,
        'verify-sig': cmd_verify_sig,
        'encrypt': cmd_encrypt,
        'decrypt': cmd_decrypt,
        'verify-cert': cmd_verify_cert,
        'info': cmd_info,
    }
    dispatch[args.command](args)

def _detect_version_from_cert_path(cert_path: Path, explicit_version: str = None) -> str:
    """
    Determine the ETSI version string ('v2' or 'v3') to use for decoding a cert.

    Priority:
      1. Explicit --etsi-version argument (if supplied).
      2. pki_meta.json found in the cert's directory or up to 3 parent directories.
      3. Default: 'v2' (vanetza-compatible format).
    """
    if explicit_version is not None:
        return explicit_version

    # Walk up directory tree looking for pki_meta.json
    search = cert_path.resolve().parent
    for _ in range(4):
        meta_path = search / 'pki_meta.json'
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                ev = meta.get('etsi_version')
                if ev is not None:
                    return 'v2' if int(ev) == 1 else 'v3'
            except Exception:
                pass
        parent = search.parent
        if parent == search:
            break
        search = parent

    return 'v2'   # default to vanetza-compatible format


def _get_pki(output_dir: str):
    """Load PKI metadata from the given directory and return a configured CITSPKI."""
    from src.pki import CITSPKI
    from src.types import PublicKeyAlgorithm, EtsiVersion

    meta_path = Path(output_dir) / 'pki_meta.json'
    if not meta_path.exists():
        raise FileNotFoundError(f"PKI not initialised in {output_dir}. Run 'init' first.")

    meta = json.loads(meta_path.read_text())
    algo = PublicKeyAlgorithm(meta['algorithm'])
    # Read ETSI standard version; fall back to V1_2_1 (vanetza format) for
    # pki_meta.json files that predate this field.
    ver = EtsiVersion(meta.get('etsi_version', int(EtsiVersion.V1_2_1)))
    pki = CITSPKI(algorithm=algo, region_ids=meta.get('region_ids'), version=ver)
    return pki


def cmd_init(args):
    """Initialise the PKI hierarchy."""
    from src.pki import CITSPKI
    from src.types import PublicKeyAlgorithm, EtsiVersion

    algo = PublicKeyAlgorithm.ECDSA_NIST_P256 if args.algo == 'p256' else PublicKeyAlgorithm.ECDSA_NIST_P384
    region_ids = [int(r) for r in args.region.split(',')] if args.region else None
    ver = EtsiVersion.V1_2_1 if args.etsi_version == 'v2' else EtsiVersion.V2_2_1
    if algo != PublicKeyAlgorithm.ECDSA_NIST_P256:
        # vanetza v2 is P-256 only; the IEEE 1609.2-2016 schema of vanetza v3 has no NIST P-384
        print("[ERROR] Only --algo p256 is supported for vanetza v2 and v3 certificates.")
        sys.exit(1)

    pki = CITSPKI(algorithm=algo, region_ids=region_ids, version=ver)
    certs = pki.initialise(
        root_ca_name=args.root_name,
        tlm_name=args.tlm_name,
        ea_name=args.ea_name,
        aa_name=args.aa_name,
    )
    pki.save(args.output)

    ver_label = 'V1.2.1' if ver == EtsiVersion.V1_2_1 else 'V1.3.1 (IEEE 1609.2-2016, COER)'
    print(f"\n[OK] PKI initialised in '{args.output}' (ETSI TS 103 097 {ver_label})")
    print(f"     Root CA  : {len(certs['root_ca'])} bytes")
    print(f"     TLM      : {len(certs['tlm'])} bytes")
    print(f"     EA       : {len(certs['ea'])} bytes")
    print(f"     AA       : {len(certs['aa'])} bytes")


def cmd_enrol(args):
    """Enrol an ITS-Station and issue an Enrolment Credential."""
    from src.pki import CITSPKI
    from src.types import PublicKeyAlgorithm, EtsiVersion
    from src.crypto import (
        generate_keypair, serialize_private_key, deserialize_private_key
    )
    from src.certificates import issue_enrolment_credential
    import json

    out_dir = Path(args.output)
    meta_path = out_dir / 'pki_meta.json'
    if not meta_path.exists():
        print(f"[ERROR] PKI not found in {args.output}. Run 'init' first.")
        sys.exit(1)

    meta = json.loads(meta_path.read_text())
    algo = PublicKeyAlgorithm(meta['algorithm'])
    ver = EtsiVersion(meta.get('etsi_version', int(EtsiVersion.V1_2_1)))

    # Load EA certificate bytes and private key.
    # We only need ea_cert.encoded for hashing (to compute the issuer digest);
    # full decoding is not required.
    ea_cert_bytes = (out_dir / 'ea.cert').read_bytes()
    ea_priv_der = (out_dir / 'ea_sign.key').read_bytes()

    from src.types import (
        Certificate, CertificateType, IssuerIdentifier, ToBeSignedCertificate,
        CertificateId, ValidityPeriod, Duration, IssuerChoice, CertIdChoice, DurationChoice
    )
    dummy_vp  = ValidityPeriod(start=0, duration=Duration(DurationChoice.YEARS, 1))
    dummy_tbs = ToBeSignedCertificate(
        id=CertificateId(CertIdChoice.NONE), craca_id=b'\x00\x00\x00',
        crl_series=0, validity_period=dummy_vp,
    )
    ea_cert = Certificate(
        version=2, cert_type=CertificateType.EXPLICIT,
        issuer=IssuerIdentifier(IssuerChoice.SELF), tbs=dummy_tbs,
    )
    ea_cert.encoded = ea_cert_bytes

    ea_priv_key = deserialize_private_key(ea_priv_der)

    its_sign_priv, its_sign_pub = generate_keypair(algo)
    ec = issue_enrolment_credential(
        name=args.name,
        its_sign_priv_key=its_sign_priv,
        its_sign_pub_key=its_sign_pub,
        ea_cert=ea_cert,
        ea_priv_key=ea_priv_key,
        sign_algorithm=algo,
        validity_years=args.validity,
        version=ver,
    )

    # Save
    ec_dir = Path(args.ec_output or out_dir / 'its-stations' / args.name)
    ec_dir.mkdir(parents=True, exist_ok=True)
    (ec_dir / 'ec.cert').write_bytes(ec.encoded)
    (ec_dir / 'ec_sign.key').write_bytes(serialize_private_key(its_sign_priv))

    print(f"[OK] Enrolment Credential issued for '{args.name}'")
    print(f"     EC certificate : {ec_dir / 'ec.cert'} ({len(ec.encoded)} bytes)")
    print(f"     Private key    : {ec_dir / 'ec_sign.key'}")


def cmd_issue_at(args):
    """Issue an Authorization Ticket."""
    from src.types import PublicKeyAlgorithm, PsidSsp, EtsiVersion
    from src.crypto import (
        generate_keypair, serialize_private_key, deserialize_private_key
    )
    from src.certificates import issue_authorization_ticket
    import json

    out_dir = Path(args.output)
    meta = json.loads((out_dir / 'pki_meta.json').read_text())
    algo = PublicKeyAlgorithm(meta['algorithm'])
    ver = EtsiVersion(meta.get('etsi_version', int(EtsiVersion.V1_2_1)))

    aa_cert_bytes = (out_dir / 'aa.cert').read_bytes()
    aa_priv_der = (out_dir / 'aa_sign.key').read_bytes()

    # We only need aa_cert.encoded for hashing (issuer digest); skip full decode.
    from src.types import (
        Certificate, CertificateType, IssuerIdentifier, ToBeSignedCertificate,
        CertificateId, ValidityPeriod, Duration, IssuerChoice, CertIdChoice, DurationChoice
    )
    dummy_vp  = ValidityPeriod(start=0, duration=Duration(DurationChoice.YEARS, 1))
    dummy_tbs = ToBeSignedCertificate(
        id=CertificateId(CertIdChoice.NONE), craca_id=b'\x00\x00\x00',
        crl_series=0, validity_period=dummy_vp,
    )
    aa_cert = Certificate(
        version=2, cert_type=CertificateType.EXPLICIT,
        issuer=IssuerIdentifier(IssuerChoice.SELF), tbs=dummy_tbs,
    )
    aa_cert.encoded = aa_cert_bytes

    aa_priv_key = deserialize_private_key(aa_priv_der)

    psids = [PsidSsp(psid=int(p)) for p in args.psid.split(',')] if args.psid else None

    at_sign_priv, at_sign_pub = generate_keypair(algo)
    at = issue_authorization_ticket(
        its_sign_priv_key=at_sign_priv,
        its_sign_pub_key=at_sign_pub,
        aa_cert=aa_cert,
        aa_priv_key=aa_priv_key,
        app_psids=psids,
        sign_algorithm=algo,
        validity_hours=args.validity,
        version=ver,
    )

    at_dir = Path(args.at_output or out_dir / 'tickets')
    at_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    at_cert_path = at_dir / f'at_{ts}.cert'
    at_key_path = at_dir / f'at_{ts}_sign.key'
    at_cert_path.write_bytes(at.encoded)
    at_key_path.write_bytes(serialize_private_key(at_sign_priv))

    print(f"[OK] Authorization Ticket issued")
    print(f"     AT certificate : {at_cert_path} ({len(at.encoded)} bytes)")
    print(f"     Private key    : {at_key_path}")

def cmd_butterfly_at(args):
    """
    Issue a batch of ATs with the IEEE 1609.2.1 Butterfly Key Mechanism
    (ETSI TS 102 941 clause 6.2.3.5), playing the EE, EA and AA roles locally.

    Writes to the output directory (default <pki>/bke-tickets):
      butterfly.json                     mode, i-value, count
      caterpillar_sign.key               EE caterpillar signing key (PKCS8 DER)
      sign_expansion.key                 EE signing expansion key (16 bytes)
      caterpillar_enc.key                EE caterpillar encryption key (original mode)
      enc_expansion.key                  EE encryption expansion key (original mode)
      bke_at_<j>.cert                    butterfly AT j (certifies pk_cc + r*G)
      bke_at_<j>.offset                  AA random offset r for AT j (32 bytes, big-endian)
      bke_at_<j>_sign.key                reconstructed AT private key sk_cc + r (PKCS8 DER)
    """
    from src.types import PublicKeyAlgorithm, PsidSsp, EtsiVersion, now_its_time32
    from src.crypto import generate_keypair, serialize_private_key, deserialize_private_key, random_bytes
    from src.pki import CITSPKI, PKIEntity
    import json

    out_dir = Path(args.output)
    meta = json.loads((out_dir / 'pki_meta.json').read_text())
    algo = PublicKeyAlgorithm(meta['algorithm'])
    ver = EtsiVersion(meta.get('etsi_version', int(EtsiVersion.V1_2_1)))
    aa_cert_bytes = (out_dir / 'aa.cert').read_bytes()
    aa_priv_der   = (out_dir / 'aa_sign.key').read_bytes()

    # Only aa_cert.encoded is needed (issuer digest and v3 signing input); skip full decode.
    from src.types import (
        Certificate as _Cert, CertificateType as _CT, IssuerIdentifier as _II,
        ToBeSignedCertificate as _TBS, CertificateId as _CID,
        ValidityPeriod as _VP, Duration as _Dur,
        IssuerChoice as _IC, CertIdChoice as _CIC, DurationChoice as _DC
    )
    _dummy_vp  = _VP(start=0, duration=_Dur(_DC.YEARS, 1))
    _dummy_tbs = _TBS(id=_CID(_CIC.NONE), craca_id=b'\x00\x00\x00', crl_series=0, validity_period=_dummy_vp)
    aa_cert = _Cert(version=2, cert_type=_CT.EXPLICIT, issuer=_II(_IC.SELF), tbs=_dummy_tbs)
    aa_cert.encoded = aa_cert_bytes
    aa_priv_key = deserialize_private_key(aa_priv_der)

    pki = CITSPKI(algorithm=algo, region_ids=meta.get('region_ids'), version=ver)
    pki.aa = PKIEntity(name='AA', sign_priv_key=aa_priv_key, sign_pub_key=aa_priv_key.public_key(),
                       certificate=aa_cert, algorithm=algo)

    psids = [PsidSsp(psid=int(p)) for p in args.psid.split(',')] if args.psid else None
    # i-period: weeks since the ITS epoch (2004-01-01) unless given explicitly
    i_value = args.i_value if args.i_value is not None else now_its_time32() // (7 * 86400)

    # EE: caterpillar keys and expansion keys (sent to the EA in the butterfly request)
    cat_priv, _ = generate_keypair(algo)
    sign_expansion_key = random_bytes(16)
    cat_enc_priv = enc_expansion_key = None
    if args.mode == 'original':
        cat_enc_priv, _ = generate_keypair(algo)
        enc_expansion_key = random_bytes(16)

    print(f"[BKE] Issuing {args.count} butterfly ATs ({args.mode} mode, i={i_value})...")
    tickets = pki.issue_butterfly_authorization_tickets(
        caterpillar_sign_priv=cat_priv,
        sign_expansion_key=sign_expansion_key,
        i_value=i_value,
        count=args.count,
        mode=args.mode,
        caterpillar_enc_priv=cat_enc_priv,
        enc_expansion_key=enc_expansion_key,
        app_psids=psids,
        validity_hours=args.validity,
    )

    at_dir = Path(args.at_output or out_dir / 'bke-tickets')
    at_dir.mkdir(parents=True, exist_ok=True)
    for stale in list(at_dir.glob('bke_at_*')) + list(at_dir.glob('caterpillar_*.key')) + \
            list(at_dir.glob('*_expansion.key')):
        stale.unlink()   # never mix keys and tickets of different batches
    (at_dir / 'butterfly.json').write_text(json.dumps(
        {'mode': args.mode, 'i_value': i_value, 'count': args.count, 'standard': 'IEEE 1609.2.1'}, indent=2))
    (at_dir / 'caterpillar_sign.key').write_bytes(serialize_private_key(cat_priv))
    (at_dir / 'sign_expansion.key').write_bytes(sign_expansion_key)
    if args.mode == 'original':
        (at_dir / 'caterpillar_enc.key').write_bytes(serialize_private_key(cat_enc_priv))
        (at_dir / 'enc_expansion.key').write_bytes(enc_expansion_key)

    for t in tickets:
        j = t['j']
        (at_dir / f'bke_at_{j}.cert').write_bytes(t['at'])
        (at_dir / f'bke_at_{j}.offset').write_bytes(t['offset'].to_bytes(32, 'big'))
        (at_dir / f'bke_at_{j}_sign.key').write_bytes(t['priv_key_der'])

    print(f"[OK] {args.count} butterfly ATs issued → {at_dir}")
    print(f"     each AT key reconstructed as sk_cc + r and checked against its certificate")

def cmd_sign_cam(args):
    """Sign a CAM payload."""
    from src.types import PublicKeyAlgorithm
    from src.crypto import deserialize_private_key
    from src.signing import sign_cam

    priv_key = deserialize_private_key(Path(args.at_key).read_bytes())
    at_cert = Path(args.at_cert).read_bytes()
    payload = Path(args.payload).read_bytes()

    algo = PublicKeyAlgorithm.ECDSA_NIST_P256
    signed = sign_cam(
        cam_payload=payload,
        at_priv_key=priv_key,
        at_cert_encoded=at_cert,
        algorithm=algo,
        use_digest=not args.full_cert,
    )

    out_path = Path(args.output) if args.output else Path(args.payload).with_suffix('.signed')
    out_path.write_bytes(signed)
    print(f"[OK] CAM signed → {out_path} ({len(signed)} bytes)")


def cmd_sign_denm(args):
    """Sign a DENM payload."""
    from src.types import PublicKeyAlgorithm
    from src.crypto import deserialize_private_key
    from src.signing import sign_denm

    priv_key = deserialize_private_key(Path(args.at_key).read_bytes())
    at_cert = Path(args.at_cert).read_bytes()
    payload = Path(args.payload).read_bytes()

    # Location in 0.1 micro-degree units (IEEE 1609.2 ThreeDLocation)
    lat_int = int(float(args.lat) * 10_000_000)
    lon_int = int(float(args.lon) * 10_000_000)
    elev_int = int(float(args.elev) * 10) if args.elev else 0

    signed = sign_denm(
        denm_payload=payload,
        at_priv_key=priv_key,
        at_cert_encoded=at_cert,
        generation_location=(lat_int, lon_int, elev_int),
        algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256,
    )

    out_path = Path(args.output) if args.output else Path(args.payload).with_suffix('.signed')
    out_path.write_bytes(signed)
    print(f"[OK] DENM signed → {out_path} ({len(signed)} bytes)")

def cmd_verify_sig(args):
    """
    Verify a signed CAM file.

    Performs two independent checks and reports each clearly:

      1. Message signature — the ECDSA signature over ToBeSignedData is verified
         against the AT certificate's public key.

      2. Certificate chain — the AT certificate's own signature chain is
         verified back to the root CA (when --root and --aa are supplied).
         Validity periods, issuer digests, cracaId/crlSeries, and AT profile
         constraints are all checked per IEEE 1609.2 clause 5.1.

    Either check alone is informative; both together constitute full
    end-to-end verification as required by ETSI TS 103 097 V2.2.1.
    """
    from src.types import PublicKeyAlgorithm, ItsAid, EtsiVersion
    from src.crypto import load_public_key_from_compressed
    from src.signing import verify_signed_data
    from src.verification import (
        verify_certificate_chain,
        verify_at_profile,
    )
    import datetime

    # ── Detect certificate encoding version ───────────────────────────────────
    at_cert_path = Path(args.at_cert)
    ver_str = _detect_version_from_cert_path(at_cert_path, args.etsi_version)
    ver = EtsiVersion.V1_2_1 if ver_str == 'v2' else EtsiVersion.V2_2_1

    def _load_cert(path: Path):
        """Load and decode a certificate using the detected version."""
        cert_bytes = path.read_bytes()
        if ver == EtsiVersion.V1_2_1:
            from src.v1_encoding import decode_certificate_v1
            cert, _ = decode_certificate_v1(cert_bytes)
        else:
            from src.encoding import decode_certificate
            cert, _ = decode_certificate(cert_bytes)
        cert.encoded = cert_bytes
        return cert

    # ── Load AT certificate ───────────────────────────────────────────────────
    at_cert = _load_cert(at_cert_path)

    # ── Extract AT public key ─────────────────────────────────────────────────
    vk = at_cert.tbs.verify_key_indicator
    if vk is None:
        print("[ERROR] AT certificate has no verifyKeyIndicator")
        sys.exit(1)

    try:
        at_pub_key = load_public_key_from_compressed(vk.point.curve, vk.point.compressed)
    except Exception as e:
        print(f"[ERROR] Could not load AT public key: {e}")
        sys.exit(1)

    # ── Determine algorithm from AT cert ──────────────────────────────────────
    algo = vk.algorithm   # PublicKeyAlgorithm.ECDSA_NIST_P256 or _P384

    # ── Load and verify the signed CAM ───────────────────────────────────────
    signed_bytes = Path(args.signed).read_bytes()

    print(f"\n[Signed CAM]")
    print(f"  File         : {args.signed} ({len(signed_bytes)} bytes)")
    print(f"  AT cert      : {args.at_cert} ({ver_str.upper()})")
    if signed_bytes[:1] == b'\x03' and ver_str == 'v2' or signed_bytes[:1] == b'\x02' and ver_str == 'v3':
        print(f"  [WARN] message protocol version {signed_bytes[0]} does not match the {ver_str} AT certificate")

    result = verify_signed_data(
        signed_data_bytes=signed_bytes,
        signer_pub_key=at_pub_key,
        algorithm=algo,
        signer_cert_encoded=at_cert.encoded,
    )

    # ── Report message-signature result ──────────────────────────────────────
    print(f"\n[Message Signature]")
    sig_ok = result.get('valid', False)
    fmt_label = {'v2': 'SecuredMessage (TS 103 097 v1.2.1)',
                 'v3': 'EtsiTs103097Data (TS 103 097 v1.3.1, COER)'}.get(result.get('format'), 'unknown')
    print(f"  Format       : {fmt_label}")
    print(f"  [{'PASS' if sig_ok else 'FAIL'}] ECDSA signature over ToBeSignedData")

    if not sig_ok:
        err = result.get('error', 'signature mismatch')
        print(f"         Error : {err}")
    else:
        psid = result.get('psid')
        try:
            psid_name = ItsAid(psid).name
        except ValueError:
            psid_name = str(psid)

        gen_us = result.get('generation_time_us', 0)
        # ITS epoch: 2004-01-01 00:00:00 UTC = 1072915200 Unix seconds
        ITS_EPOCH_UNIX = 1_072_915_200
        gen_unix = ITS_EPOCH_UNIX + gen_us / 1_000_000
        gen_dt = datetime.datetime.utcfromtimestamp(gen_unix).isoformat()

        signer = result.get('signer', {})
        signer_type = signer.get('type', 'unknown')
        signer_detail = (
            f"digest={signer['hash']}" if signer_type == 'digest'
            else f"certificate embedded ({signer.get('cert_len', '?')} bytes)"
        )

        payload = result.get('payload', b'')

        print(f"         PSID            : {psid_name} ({psid})")
        print(f"         GenerationTime  : {gen_dt}Z")
        print(f"         Signer          : {signer_type} ({signer_detail})")
        print(f"         Payload         : {len(payload)} bytes")

        loc = result.get('generation_location')
        if loc:
            lat_deg = loc[0] / 10_000_000
            lon_deg = loc[1] / 10_000_000
            elev_m  = loc[2] / 10
            print(f"         Location        : lat={lat_deg:.7f} lon={lon_deg:.7f} elev={elev_m:.1f}m")

    # ── Certificate chain verification (optional) ─────────────────────────────
    chain_ok = None
    if args.root:
        print(f"\n[Certificate Chain]")

        root_cert = _load_cert(Path(args.root))

        intermediates = []
        if args.aa:
            aa_cert = _load_cert(Path(args.aa))
            intermediates = [aa_cert]
            print(f"  AA cert      : {args.aa}")
        print(f"  Root CA cert : {args.root}")

        chain_result = verify_certificate_chain(
            leaf_cert=at_cert,
            intermediate_certs=intermediates,
            root_cert=root_cert,
            algorithm=algo,
        )

        chain_ok = chain_result['valid']
        details = chain_result['details']

        checks = [
            ("Root CA self-signature",    details.get('root_signature')),
            ("Root CA validity period",   details.get('root_validity')),
        ]
        if intermediates:
            checks += [
                ("AA signature (by Root CA)", details.get('intermediate_0_signature')),
                ("AA validity period",        details.get('intermediate_0_validity')),
                ("AA issuer digest",          details.get('intermediate_0_issuer_digest')),
            ]
        checks += [
            ("AT signature (by AA)",      details.get('leaf_signature')),
            ("AT validity period",        details.get('leaf_validity')),
            ("AT issuer digest",          details.get('leaf_issuer_digest')),
            ("cracaId / crlSeries",       details.get('leaf_craca')),
            ("AT appPermissions present", details.get('leaf_permissions')),
        ]

        # Check the AT-specific constraints 
        #      (id = none, no certIssuePermissions, appPermissions present)
        at_profile_ok, at_profile_msg = verify_at_profile(at_cert)
        checks.append(("AT profile constraints", at_profile_ok))

        for label, ok in checks:
            if ok is None:
                continue
            print(f"  [{'PASS' if ok else 'FAIL'}] {label}")

        if chain_result['errors']:
            print(f"\n  Errors:")
            for err in chain_result['errors']:
                print(f"    • {err}")
        if not at_profile_ok:
            print(f"    • AT profile: {at_profile_msg}")
    else:
        print(f"\n  (Certificate chain not verified — supply --root and --aa to enable)")

    # ── Overall verdict ───────────────────────────────────────────────────────
    print(f"\n[Overall]")
    if chain_ok is None:
        overall = sig_ok
        note = " (message signature only)"
    else:
        overall = sig_ok and chain_ok
        note = ""

    print(f"  {'VALID' if overall else 'INVALID'}{note}")
    sys.exit(0 if overall else 1)


def cmd_encrypt(args):
    """Encrypt a payload for a recipient."""
    from src.types import PublicKeyAlgorithm, EtsiVersion
    from src.crypto import deserialize_private_key
    from src.encryption import encrypt_data

    enc_cert_path = Path(args.enc_cert)
    ver_str = _detect_version_from_cert_path(enc_cert_path, args.etsi_version)
    ver = EtsiVersion.V1_2_1 if ver_str == 'v2' else EtsiVersion.V2_2_1

    enc_cert_bytes = enc_cert_path.read_bytes()
    if ver == EtsiVersion.V1_2_1:
        from src.v1_encoding import decode_certificate_v1
        enc_cert, _ = decode_certificate_v1(enc_cert_bytes)
    else:
        from src.encoding import decode_certificate
        enc_cert, _ = decode_certificate(enc_cert_bytes)
    enc_cert.encoded = enc_cert_bytes

    enc_pub_key = None
    if enc_cert.tbs.encryption_key:
        from src.crypto import load_public_key_from_compressed
        ek = enc_cert.tbs.encryption_key
        enc_pub_key = load_public_key_from_compressed(ek.point.curve, ek.point.compressed)
    else:
        print("[ERROR] Recipient certificate has no encryption key")
        sys.exit(1)

    payload = Path(args.payload).read_bytes()
    encrypted = encrypt_data(
        plaintext=payload,
        recipient_cert_encoded=enc_cert_bytes,
        recipient_enc_pub_key=enc_pub_key,
        algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256,
    )

    out_path = Path(args.output) if args.output else Path(args.payload).with_suffix('.enc')
    out_path.write_bytes(encrypted)
    print(f"[OK] Encrypted → {out_path} ({len(encrypted)} bytes)")


def cmd_decrypt(args):
    """Decrypt an encrypted message."""
    from src.types import PublicKeyAlgorithm
    from src.crypto import deserialize_private_key
    from src.encryption import decrypt_data

    enc_cert_bytes = Path(args.enc_cert).read_bytes()
    enc_priv_key = deserialize_private_key(Path(args.enc_key).read_bytes())
    encrypted = Path(args.input).read_bytes()

    plaintext = decrypt_data(
        encrypted_data_bytes=encrypted,
        recipient_enc_priv_key=enc_priv_key,
        my_cert_encoded=enc_cert_bytes,
        algorithm=PublicKeyAlgorithm.ECDSA_NIST_P256,
    )

    out_path = Path(args.output) if args.output else Path(args.input).with_suffix('.dec')
    out_path.write_bytes(plaintext)
    print(f"[OK] Decrypted → {out_path} ({len(plaintext)} bytes)")


def cmd_verify_cert(args):
    """Verify a certificate's signature and profile constraints."""
    from src.types import PublicKeyAlgorithm, CertIdChoice, EtsiVersion

    cert_path = Path(args.cert)
    ver_str = _detect_version_from_cert_path(cert_path, args.etsi_version)
    ver = EtsiVersion.V1_2_1 if ver_str == 'v2' else EtsiVersion.V2_2_1

    cert_bytes = cert_path.read_bytes()

    if ver == EtsiVersion.V1_2_1:
        from src.v1_encoding import decode_certificate_v1
        cert, _ = decode_certificate_v1(cert_bytes)
        cert.encoded = cert_bytes
        issuer_cert = None
        if args.issuer:
            issuer_bytes = Path(args.issuer).read_bytes()
            issuer_cert, _ = decode_certificate_v1(issuer_bytes)
            issuer_cert.encoded = issuer_bytes
    else:
        from src.encoding import decode_certificate
        cert, _ = decode_certificate(cert_bytes, version=ver)
        cert.encoded = cert_bytes
        issuer_cert = None
        if args.issuer:
            issuer_bytes = Path(args.issuer).read_bytes()
            issuer_cert, _ = decode_certificate(issuer_bytes, version=ver)
            issuer_cert.encoded = issuer_bytes

    from src.verification import (
        verify_certificate_signature, verify_certificate_validity_period,
        verify_craca_and_crl_series, verify_permissions_constraints,
        verify_region_constraint, verify_at_profile
    )

    ver_label = 'V1.2.1' if ver == EtsiVersion.V1_2_1 else 'V1.3.1 (IEEE 1609.2-2016, COER)'
    print(f"\n[Certificate Info]")
    if ver == EtsiVersion.V1_2_1:
        print(f"  Format       : ETSI TS 103 097 {ver_label} (vanetza binary)")
        print(f"  Cert version : {cert.version}  (vanetza format)")
    else:
        print(f"  ETSI Standard: ETSI TS 103 097 {ver_label}  (vanetza v3)")
        print(f"  IEEE 1609.2 Cert Version : {cert.version}  (always 3)")
        print(f"  Type         : {cert.cert_type.name}")
    print(f"  Id choice    : {cert.tbs.id.choice.name}")
    if cert.tbs.id.name:
        print(f"  Name         : {cert.tbs.id.name}")
    if ver == EtsiVersion.V2_2_1:
        print(f"  cracaId      : {cert.tbs.craca_id.hex()}")
        print(f"  crlSeries    : {cert.tbs.crl_series}")

    results = []

    sig_ok = verify_certificate_signature(cert, issuer_cert)
    results.append(("Signature", sig_ok))

    if issuer_cert is not None and cert.issuer.digest:
        from src.verification import verify_issuer_digest
        if ver == EtsiVersion.V1_2_1:
            from src.v1_encoding import hash_certificate_v1
            digest_ok = cert.issuer.digest == hash_certificate_v1(issuer_cert.encoded)
        else:
            digest_ok = verify_issuer_digest(cert, issuer_cert, PublicKeyAlgorithm.ECDSA_NIST_P256)
        results.append(("Issuer digest matches --issuer", digest_ok))

    vp_ok = verify_certificate_validity_period(cert)
    results.append(("Validity period", vp_ok))

    craca_ok, craca_msg = verify_craca_and_crl_series(cert)
    results.append(("cracaId/crlSeries", craca_ok))

    perm_ok, _ = verify_permissions_constraints(cert)
    results.append(("Permissions present", perm_ok))

    region_ok, region_msg = verify_region_constraint(cert)
    results.append((f"Region ({region_msg})", region_ok))

    if cert.tbs.id.choice == CertIdChoice.NONE:
        at_ok, at_msg = verify_at_profile(cert)
        results.append((f"AT profile ({at_msg})", at_ok))

    print(f"\n[Verification Results]")
    all_ok = True
    for label, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {label}")
        if not ok:
            all_ok = False

    print(f"\n  Overall: {'VALID' if all_ok else 'INVALID'}")
    sys.exit(0 if all_ok else 1)


def cmd_info(args):
    """Display information about a certificate."""
    from src.types import ItsAid, its_time32_to_unix, EtsiVersion
    import datetime

    cert_path = Path(args.cert)
    ver_str = _detect_version_from_cert_path(cert_path, args.etsi_version)
    ver = EtsiVersion.V1_2_1 if ver_str == 'v2' else EtsiVersion.V2_2_1

    cert_bytes = cert_path.read_bytes()

    if ver == EtsiVersion.V1_2_1:
        from src.v1_encoding import decode_certificate_v1, V1SubjectType, hash_certificate_v1
        cert, _ = decode_certificate_v1(cert_bytes)
        cert.encoded = cert_bytes
    else:
        from src.encoding import decode_certificate
        cert, _ = decode_certificate(cert_bytes, version=ver)
        cert.encoded = cert_bytes

    start_unix = its_time32_to_unix(cert.tbs.validity_period.start)
    start_dt = datetime.datetime.utcfromtimestamp(start_unix).isoformat()

    ver_label = 'V1.2.1' if ver == EtsiVersion.V1_2_1 else 'V1.3.1 (IEEE 1609.2-2016, COER)'

    print(f"\n{'='*60}")
    print(f"EtsiTs103097Certificate")
    print(f"{'='*60}")

    if ver == EtsiVersion.V1_2_1:
        # Vanetza format
        subject_type_names = {
            0: 'Enrollment_Credential',
            1: 'Authorization_Ticket',
            2: 'Authorization_Authority',
            3: 'Enrollment_Authority',
            4: 'Root_CA',
            5: 'CRL_Signer',
        }
        st = getattr(cert, 'subject_type', None)
        st_name = subject_type_names.get(st, str(st)) if st is not None else 'unknown'
        print(f"  Format          : ETSI TS 103 097 {ver_label} (vanetza binary)")
        print(f"  Cert version    : {cert.version}  (vanetza v2 format)")
        print(f"  Subject type    : {st_name} ({st})")
    else:
        print(f"  IEEE 1609.2 Cert Version : {cert.version}  (always 3 per IEEE 1609.2)")
        print(f"  ETSI Standard   : ETSI TS 103 097 {ver_label}  (vanetza v3)")
        print(f"  Type            : {cert.cert_type.name}")

    print(f"  Issuer choice   : {cert.issuer.choice.name}")
    if cert.issuer.digest:
        print(f"  Issuer digest   : {cert.issuer.digest.hex()}")
    print(f"  Id choice       : {cert.tbs.id.choice.name}")
    if cert.tbs.id.name:
        print(f"  Name            : {cert.tbs.id.name}")

    if ver == EtsiVersion.V2_2_1:
        print(f"  cracaId         : {cert.tbs.craca_id.hex()} (expected: 000000)")
        print(f"  crlSeries       : {cert.tbs.crl_series} (expected: 0)")

    print(f"  ValidityPeriod  : start={start_dt}Z  duration={cert.tbs.validity_period.duration.value} {cert.tbs.validity_period.duration.choice.name}")
    if cert.tbs.region:
        print(f"  Region IDs      : {cert.tbs.region.ids}")
    if cert.tbs.app_permissions:
        psids = [p.psid for p in cert.tbs.app_permissions]
        names = []
        for p in psids:
            try:
                names.append(ItsAid(p).name)
            except ValueError:
                names.append(str(p))
        print(f"  appPermissions  : {names} (PSIDs: {psids})")
    if ver == EtsiVersion.V2_2_1:
        if cert.tbs.cert_issue_permissions:
            print(f"  certIssuePerms  : present ({len(cert.tbs.cert_issue_permissions)} entries)")
        else:
            print(f"  certIssuePerms  : absent")
    if cert.tbs.encryption_key:
        print(f"  encryptionKey   : present ({cert.tbs.encryption_key.algorithm.name})")
    else:
        print(f"  encryptionKey   : absent")
    if cert.tbs.verify_key_indicator:
        alg = cert.tbs.verify_key_indicator.algorithm.name
        pt = cert.tbs.verify_key_indicator.point.compressed.hex()
        print(f"  verifyKey       : {alg} {pt[:16]}...")
    if cert.signature:
        print(f"  Signature alg   : {cert.signature.algorithm.name}")
    print(f"  Encoded size    : {len(cert_bytes)} bytes")
    print(f"  HashedId8       : ", end="")
    if ver == EtsiVersion.V1_2_1:
        from src.v1_encoding import hash_certificate_v1
        h8 = hash_certificate_v1(cert_bytes)
    else:
        from src.crypto import hash_certificate
        from src.types import PublicKeyAlgorithm
        h8 = hash_certificate(cert_bytes, PublicKeyAlgorithm.ECDSA_NIST_P256)
    print(h8.hex())
    print()

if __name__ == '__main__':
    main()
