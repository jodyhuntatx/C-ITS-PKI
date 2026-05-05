#!/bin/bash

# Generate certs for Vanetza-NAP simulations

OUTPUT_DIR=${VAR:-"./vnap-certs"}

PYTHON="uv run python"

# ── PKI project root ──────────────────────────────────────────────────────────
PKI_ROOT="$(pwd)"
PKI_CMD="$PYTHON $PKI_ROOT/cli.py"
PKI_PY="$PYTHON -c"

main() {
  case $# in
    0)
      ETSI_VERSION="v2"
      gen_vnap_certs
      ;;
    1)
      ETSI_VERSION="v2"
      OUTPUT_DIR=$1
      gen_vnap_certs
      ;;
    *)
      echo "Usage: $0 <full-path-to-output-directory>"; exit -1
      ;;
  esac
}

gen_vnap_certs() {
  mkdir -p $OUTPUT_DIR
  rm -rf $OUTPUT_DIR/*
  echo; echo; echo "Generating ETSI $ETSI_VERSION certs for vanetza-nap..."; echo
  init_pki
  issue_auth_ticket
exit
  enroll_its_station
  issue_bke_tickets
  sign_and_verify_a_cam
  sign_and_verify_a_denm
  encrypt_a_message
  decrypt_and_verify_a_message
}

#===================================
init_pki() {
  uv sync
  $PKI_CMD init --output $OUTPUT_DIR \
                --algo p256 \
                --region 65535 \
                --etsi-version $ETSI_VERSION
  echo; echo; echo "######################"
  echo "Root cert:"
  echo "######################"
  $PKI_CMD info --cert $OUTPUT_DIR/root_ca.cert \
                --etsi-version $ETSI_VERSION
  echo; echo; echo "######################"
  echo "Enrollment Authority cert:"
  echo "######################"
  $PKI_CMD info --cert $OUTPUT_DIR/ea.cert \
                --etsi-version $ETSI_VERSION
  echo "Verifying signed by root cert..."
  $PKI_CMD verify-cert --cert $OUTPUT_DIR/ea.cert \
	               --issuer $OUTPUT_DIR/root_ca.cert \
                       --etsi-version $ETSI_VERSION
  echo; echo; echo "######################"
  echo "Authorization Authority:"
  echo "######################"
  $PKI_CMD info --cert $OUTPUT_DIR/aa.cert \
                --etsi-version $ETSI_VERSION
  echo "Verifying signed by root cert..."
  $PKI_CMD verify-cert --cert $OUTPUT_DIR/aa.cert \
		       --issuer $OUTPUT_DIR/root_ca.cert \
                       --etsi-version $ETSI_VERSION
}

#===================================
issue_auth_ticket() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Issue an Authorization Ticket"
  rm -rf $OUTPUT_DIR/tickets
  $PKI_CMD issue-at --output $OUTPUT_DIR \
                    --psid 36,37 \
                    --validity 168
  mv $OUTPUT_DIR/tickets/at_*.cert $OUTPUT_DIR/at.cert
  AUTH_TICKET=$OUTPUT_DIR/at.cert
  $PKI_CMD info --cert $AUTH_TICKET  \
                --etsi-version $ETSI_VERSION
  echo "Verifying signed by AA cert..."
  SIGN_KEY=$(ls $OUTPUT_DIR/aa.cert)
  $PKI_CMD verify-cert --cert $AUTH_TICKET \
                       --issuer $SIGN_KEY  \
                       --etsi-version $ETSI_VERSION

  echo "Converting private key PEM format to DER format accepted by Vanetza-NAP..."
  mv $OUTPUT_DIR/tickets/at_*_sign.key $OUTPUT_DIR/at_sign.key
  openssl pkcs8 -topk8 -nocrypt -in $OUTPUT_DIR/at_sign.key \
				-outform DER -out $OUTPUT_DIR/at.der
  openssl pkey -in $OUTPUT_DIR/at.der -inform DER -text -noout
}

#===================================
issue_bke_tickets() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Issue BKE Authorization Tickets"
  rm -rf $OUTPUT_DIR/bke-tickets
  $PKI_CMD butterfly-at --output $OUTPUT_DIR \
                        --count 8 \
                        --psid 36,37 \
                        --validity 168
  AUTH_TICKET=$(ls $OUTPUT_DIR/bke-tickets/bke_at_0.cert)
  $PKI_CMD info --cert $AUTH_TICKET  \
                --etsi-version $ETSI_VERSION
  echo "Verifying butterfly AT cert was signed by AA cert..."
  SIGN_KEY=$(ls $OUTPUT_DIR/aa.cert)
  $PKI_CMD verify-cert --cert $AUTH_TICKET \
                       --issuer $SIGN_KEY  \
                       --etsi-version $ETSI_VERSION
}

#===================================
enroll_its_station() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Enroll an ITS-Station"
  $PKI_CMD enrol --output $OUTPUT_DIR \
                 --name "ITS-Station-001"
  $PKI_CMD info --cert $OUTPUT_DIR/its-stations/ITS-Station-001/ec.cert  \
                --etsi-version $ETSI_VERSION
  $PKI_CMD verify-cert --cert $OUTPUT_DIR/its-stations/ITS-Station-001/ec.cert \
		       --issuer $OUTPUT_DIR/ea.cert \
                       --etsi-version $ETSI_VERSION
}

#===================================
sign_and_verify_a_cam() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Sign & verify a CAM"
  echo -n "CAM_PAYLOAD" > cam.bin
  AUTH_TICKET=$OUTPUT_DIR/at.cert
  SIGN_KEY=$OUTPUT_DIR/at_sign.key
  $PKI_CMD sign-cam --at-key $SIGN_KEY \
                    --at-cert $AUTH_TICKET \
                    --payload cam.bin \
                    --output cam.signed
  echo; echo "-------------------------------"
  echo "Verify CAM signature (fast):"
  $PKI_CMD verify-sig --signed  cam.signed \
                      --at-cert $AUTH_TICKET \
                      --etsi-version $ETSI_VERSION
  echo; echo "-------------------------------"
  echo "Verify CAM signature (full chain):"
  $PKI_CMD verify-sig --signed  cam.signed \
                      --at-cert $AUTH_TICKET \
                      --aa      $OUTPUT_DIR/aa.cert \
                      --root    $OUTPUT_DIR/root_ca.cert \
                      --etsi-version $ETSI_VERSION
}

#===================================
sign_and_verify_a_denm() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Sign & verify a DENM"
  echo -n "DENM_PAYLOAD" > denm.bin
  AUTH_TICKET=$OUTPUT_DIR/at.cert
  SIGN_KEY=$OUTPUT_DIR/at_sign.key
  $PKI_CMD sign-denm --at-key $SIGN_KEY \
                     --at-cert $AUTH_TICKET \
                     --payload denm.bin \
                     --lat 52.5200 --lon 13.4050 \
                     --output denm.signed
  echo; echo "-------------------------------"
  echo "Verify DENM signature (fast):"
  $PKI_CMD verify-sig --signed  denm.signed \
                      --at-cert $AUTH_TICKET \
                      --etsi-version $ETSI_VERSION
  echo; echo "-------------------------------"
  echo "Verify DENM signature (full chain):"
  $PKI_CMD verify-sig --signed  denm.signed \
                      --at-cert $AUTH_TICKET \
                      --aa      $OUTPUT_DIR/aa.cert \
                      --root    $OUTPUT_DIR/root_ca.cert \
                      --etsi-version $ETSI_VERSION
}

#===================================
encrypt_a_message() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Encrypt a message (for the EA)"
  $PKI_CMD encrypt --enc-cert $OUTPUT_DIR/ea.cert \
                   --enc-key $OUTPUT_DIR/ea_enc.key \
                   --payload cam.signed \
                   --output cam.enc \
                   --etsi-version $ETSI_VERSION
}

#===================================
decrypt_and_verify_a_message() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Decrypt & verify a message"
  $PKI_CMD decrypt --enc-cert $OUTPUT_DIR/ea.cert \
                   --enc-key $OUTPUT_DIR/ea_enc.key \
                   --input cam.enc \
                   --output cam.decrypted
  echo; echo "-------------------------------"
  echo "Verify decrypted CAM signature (fast):"
  AUTH_TICKET=$OUTPUT_DIR/at.cert
  $PKI_CMD verify-sig --signed  cam.decrypted \
                      --at-cert $AUTH_TICKET \
                      --etsi-version $ETSI_VERSION
}

main "$@"
