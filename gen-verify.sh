#!/bin/bash

PYTHON="uv run python"

# ── PKI project root ──────────────────────────────────────────────────────────
PKI_ROOT="$(pwd)"
PKI_CMD="$PYTHON $PKI_ROOT/cli.py"
PKI_PY="$PYTHON -c"


main() {
  init_pki
  enroll_its_station
  issue_auth_ticket
  sign_a_cam
  sign_a_denm
  encrypt_a_message
  decrypt_a_message
}

#===================================
init_pki() {
  uv sync
  $PKI_CMD init --output pki-output --algo p256 --region 65535
  echo; echo; echo "######################"
  echo "Root cert:"
  echo "######################"
  $PKI_CMD info --cert pki-output/root_ca.cert
  echo; echo; echo "######################"
  echo "Enrollment Authority cert:"
  echo "######################"
  $PKI_CMD info --cert pki-output/ea.cert
  echo "Verifying signed by root cert..."
  $PKI_CMD verify-cert --cert pki-output/ea.cert \
			                 --issuer pki-output/root_ca.cert
  echo; echo; echo "######################"
  echo "Authorization Authority:"
  echo "######################"
  $PKI_CMD info --cert pki-output/aa.cert
  echo "Verifying signed by root cert..."
  $PKI_CMD verify-cert --cert pki-output/aa.cert \
			                 --issuer pki-output/root_ca.cert
}

#===================================
enroll_its_station() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Enroll an ITS-Station"
  $PKI_CMD enrol --output pki-output --name "ITS-Station-001"
  $PKI_CMD info --cert pki-output/its-stations/ITS-Station-001/ec.cert
  $PKI_CMD verify-cert --cert pki-output/its-stations/ITS-Station-001/ec.cert \
			                 --issuer pki-output/ea.cert
}

#===================================
issue_auth_ticket() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Issue an Authorization Ticket"
  rm -rf pki-output/tickets/at_*
  $PKI_CMD issue-at --output pki-output --psid 36,37 --validity 168
  AUTH_TICKET=$(ls ./pki-output/tickets/*.cert)
  $PKI_CMD info --cert $AUTH_TICKET
  echo "Verifying signed by AA cert..."
  SIGN_KEY=$(ls ./pki-output/aa.cert)
  $PKI_CMD verify-cert --cert $AUTH_TICKET --issuer $SIGN_KEY
}


#===================================
sign_a_cam() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Sign a CAM"
  echo -n "CAM_PAYLOAD" > cam.bin
  AUTH_TICKET=$(ls ./pki-output/tickets/*.cert)
  SIGN_KEY=$(ls ./pki-output/tickets/*.key)
  $PKI_CMD sign-cam \
    --at-key $SIGN_KEY \
    --at-cert $AUTH_TICKET \
    --payload cam.bin \
    --output cam.signed
  echo; echo "Verify CAM signature (fast):"
  $PKI_CMD verify-cam \
  --signed  cam.signed \
  --at-cert $AUTH_TICKET
  echo; echo "Verify CAM signature (full chain):"
  $PKI_CMD verify-cam \
  --signed  cam.signed \
  --at-cert $AUTH_TICKET \
  --aa      pki-output/aa.cert \
  --root    pki-output/root_ca.cert
}

#===================================
sign_a_denm() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Sign a DENM"
  echo -n "DENM_PAYLOAD" > denm.bin
  AUTH_TICKET=$(ls ./pki-output/tickets/*.cert)
  SIGN_KEY=$(ls ./pki-output/tickets/*.key)
  $PKI_CMD sign-denm \
    --at-key $SIGN_KEY \
    --at-cert $AUTH_TICKET \
    --payload denm.bin \
    --lat 52.5200 --lon 13.4050 \
    --output denm.signed
}

#===================================
encrypt_a_message() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Encrypt a message (for the EA)"
  $PKI_CMD encrypt \
    --enc-cert pki-output/ea.cert \
    --enc-key pki-output/ea_enc.key \
    --payload cam.signed \
    --output cam.enc
}

#===================================
decrypt_a_message() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Decrypt a message"
  $PKI_CMD decrypt \
    --enc-cert pki-output/ea.cert \
    --enc-key pki-output/ea_enc.key \
    --input cam.enc \
    --output cam.decrypted
  echo; echo "Verify decrypted CAM signature (fast):"
  AUTH_TICKET=$(ls ./pki-output/tickets/*.cert)
  $PKI_CMD verify-cam \
  --signed  cam.decrypted \
  --at-cert $AUTH_TICKET
}

main "$@"
