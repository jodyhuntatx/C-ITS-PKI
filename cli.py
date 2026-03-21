#!/usr/bin/env python3
"""
C-ITS PKI Command-Line Interface
Conforming to ETSI TS 103 097 V2.2.1 / IEEE Std 1609.2-2025.

Usage:
    python cli.py init        [--output DIR] [--algo p256|p384] [--region 65535]
    python cli.py enrol       --output DIR --name ITS_NAME [--ec-validity 1]
    python cli.py issue-at    --output DIR [--psid 36,37] [--at-validity 168]
    python cli.py sign-cam    --at-key FILE --at-cert FILE --payload FILE [--output FILE]
    python cli.py sign-denm   --at-key FILE --at-cert FILE --payload FILE --lat LAT --lon LON
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


def _get_pki(output_dir: str):
    """Load or initialise a PKI from the given directory."""
    from src.pki import CITSPKI
    from src.types import PublicKeyAlgorithm

    meta_path = Path(output_dir) / 'pki_meta.json'
    if not meta_path.exists():
        raise FileNotFoundError(f"PKI not initialised in {output_dir}. Run 'init' first.")

    meta = json.loads(meta_path.read_text())
    algo = PublicKeyAlgorithm(meta['algorithm'])
    pki = CITSPKI(algorithm=algo, region_ids=meta.get('region_ids'))
    return pki


def cmd_init(args):
    """Initialise the PKI hierarchy."""
    from src.pki import CITSPKI
    from src.types import PublicKeyAlgorithm

    algo = PublicKeyAlgorithm.ECDSA_NIST_P256 if args.algo == 'p256' else PublicKeyAlgorithm.ECDSA_NIST_P384
    region_ids = [int(r) for r in args.region.split(',')] if args.region else None

    pki = CITSPKI(algorithm=algo, region_ids=region_ids)
    certs = pki.initialise(
        root_ca_name=args.root_name,
        tlm_name=args.tlm_name,
        ea_name=args.ea_name,
        aa_name=args.aa_name,
    )
    pki.save(args.output)

    print(f"\n[OK] PKI initialised in '{args.output}'")
    print(f"     Root CA  : {len(certs['root_ca'])} bytes")
    print(f"     TLM      : {len(certs['tlm'])} bytes")
    print(f"     EA       : {len(certs['ea'])} bytes")
    print(f"     AA       : {len(certs['aa'])} bytes")


def cmd_enrol(args):
    """Enrol an ITS-Station and issue an Enrolment Credential."""
    from src.pki import CITSPKI
    from src.types import PublicKeyAlgorithm
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

    # Load EA certificate and private key
    ea_cert_bytes = (out_dir / 'ea.cert').read_bytes()
    ea_priv_pem = (out_dir / 'ea_sign.key').read_bytes()

    from src.encoding import decode_certificate
    ea_cert, _ = decode_certificate(ea_cert_bytes)
    ea_priv_key = deserialize_private_key(ea_priv_pem)

    # Set ea_cert.encoded so hash_certificate works
    ea_cert.encoded = ea_cert_bytes

    its_sign_priv, its_sign_pub = generate_keypair(algo)
    ec = issue_enrolment_credential(
        name=args.name,
        its_sign_priv_key=its_sign_priv,
        its_sign_pub_key=its_sign_pub,
        ea_cert=ea_cert,
        ea_priv_key=ea_priv_key,
        sign_algorithm=algo,
        validity_years=args.validity,
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
    from src.types import PublicKeyAlgorithm, PsidSsp
    from src.crypto import (
        generate_keypair, serialize_private_key, deserialize_private_key
    )
    from src.certificates import issue_authorization_ticket
    from src.encoding import decode_certificate
    import json

    out_dir = Path(args.output)
    meta = json.loads((out_dir / 'pki_meta.json').read_text())
    algo = PublicKeyAlgorithm(meta['algorithm'])

    aa_cert_bytes = (out_dir / 'aa.cert').read_bytes()
    aa_priv_pem = (out_dir / 'aa_sign.key').read_bytes()
    aa_cert, _ = decode_certificate(aa_cert_bytes)
    aa_cert.encoded = aa_cert_bytes
    aa_priv_key = deserialize_private_key(aa_priv_pem)

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


def cmd_encrypt(args):
    """Encrypt a payload for a recipient."""
    from src.types import PublicKeyAlgorithm
    from src.crypto import deserialize_private_key
    from src.encryption import encrypt_data
    from src.encoding import decode_certificate

    enc_cert_bytes = Path(args.enc_cert).read_bytes()
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
    from src.encoding import decode_certificate
    from src.types import PublicKeyAlgorithm
    from src.verification import (
        verify_certificate_signature, verify_certificate_validity_period,
        verify_craca_and_crl_series, verify_permissions_constraints,
        verify_region_constraint
    )

    cert_bytes = Path(args.cert).read_bytes()
    cert, _ = decode_certificate(cert_bytes)
    cert.encoded = cert_bytes

    issuer_cert = None
    if args.issuer:
        issuer_bytes = Path(args.issuer).read_bytes()
        issuer_cert, _ = decode_certificate(issuer_bytes)
        issuer_cert.encoded = issuer_bytes

    print(f"\n[Certificate Info]")
    print(f"  Version      : {cert.version}")
    print(f"  Type         : {cert.cert_type.name}")
    print(f"  Id choice    : {cert.tbs.id.choice.name}")
    if cert.tbs.id.name:
        print(f"  Name         : {cert.tbs.id.name}")
    print(f"  cracaId      : {cert.tbs.craca_id.hex()}")
    print(f"  crlSeries    : {cert.tbs.crl_series}")

    results = []

    sig_ok = verify_certificate_signature(cert, issuer_cert)
    results.append(("Signature", sig_ok))

    vp_ok = verify_certificate_validity_period(cert)
    results.append(("Validity period", vp_ok))

    craca_ok, craca_msg = verify_craca_and_crl_series(cert)
    results.append(("cracaId/crlSeries", craca_ok))

    perm_ok, _ = verify_permissions_constraints(cert)
    results.append(("Permissions present", perm_ok))

    region_ok, region_msg = verify_region_constraint(cert)
    results.append((f"Region ({region_msg})", region_ok))

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
    from src.encoding import decode_certificate
    from src.types import ItsAid, its_time32_to_unix
    import datetime

    cert_bytes = Path(args.cert).read_bytes()
    cert, _ = decode_certificate(cert_bytes)
    cert.encoded = cert_bytes

    start_unix = its_time32_to_unix(cert.tbs.validity_period.start)
    start_dt = datetime.datetime.utcfromtimestamp(start_unix).isoformat()

    print(f"\n{'='*60}")
    print(f"EtsiTs103097Certificate")
    print(f"{'='*60}")
    print(f"  Version         : {cert.version}")
    print(f"  Type            : {cert.cert_type.name}")
    print(f"  Issuer choice   : {cert.issuer.choice.name}")
    if cert.issuer.digest:
        print(f"  Issuer digest   : {cert.issuer.digest.hex()}")
    print(f"  Id choice       : {cert.tbs.id.choice.name}")
    if cert.tbs.id.name:
        print(f"  Name            : {cert.tbs.id.name}")
    print(f"  cracaId         : {cert.tbs.craca_id.hex()} (expected: 000000)")
    print(f"  crlSeries       : {cert.tbs.crl_series} (expected: 0)")
    print(f"  ValidityPeriod  : start={start_dt}Z, duration={cert.tbs.validity_period.duration.value} {cert.tbs.validity_period.duration.choice.name}")
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
    print(f"  COER size       : {len(cert_bytes)} bytes")
    print(f"  HashedId8       : ", end="")
    from src.crypto import hash_certificate
    from src.types import PublicKeyAlgorithm
    h8 = hash_certificate(cert_bytes, PublicKeyAlgorithm.ECDSA_NIST_P256)
    print(h8.hex())
    print()


def main():
    parser = argparse.ArgumentParser(
        description='C-ITS PKI — ETSI TS 103 097 V2.2.1 Certificate Management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # init
    p_init = sub.add_parser('init', help='Initialise PKI hierarchy')
    p_init.add_argument('--output', '-o', default='pki-output', help='Output directory')
    p_init.add_argument('--algo', choices=['p256', 'p384'], default='p256')
    p_init.add_argument('--region', default='65535', help='Comma-separated region IDs (65535=EU-27)')
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

    # encrypt
    p_enc = sub.add_parser('encrypt', help='Encrypt a payload for a recipient')
    p_enc.add_argument('--enc-cert', required=True, help='Recipient certificate (COER)')
    p_enc.add_argument('--enc-key', required=True, help='Recipient encryption private key (PEM)')
    p_enc.add_argument('--payload', required=True)
    p_enc.add_argument('--output', '-o')

    # decrypt
    p_dec = sub.add_parser('decrypt', help='Decrypt an encrypted message')
    p_dec.add_argument('--enc-cert', required=True, help='Your certificate (COER)')
    p_dec.add_argument('--enc-key', required=True, help='Your encryption private key (PEM)')
    p_dec.add_argument('--input', '-i', required=True, help='Encrypted message file')
    p_dec.add_argument('--output', '-o')

    # verify-cert
    p_ver = sub.add_parser('verify-cert', help='Verify a certificate')
    p_ver.add_argument('--cert', required=True)
    p_ver.add_argument('--issuer', help='Issuer certificate (omit for self-signed)')
    p_ver.add_argument('--root', help='Root CA certificate')

    # info
    p_info = sub.add_parser('info', help='Display certificate information')
    p_info.add_argument('--cert', required=True)

    args = parser.parse_args()

    dispatch = {
        'init': cmd_init,
        'enrol': cmd_enrol,
        'issue-at': cmd_issue_at,
        'sign-cam': cmd_sign_cam,
        'sign-denm': cmd_sign_denm,
        'encrypt': cmd_encrypt,
        'decrypt': cmd_decrypt,
        'verify-cert': cmd_verify_cert,
        'info': cmd_info,
    }
    dispatch[args.command](args)


if __name__ == '__main__':
    main()
