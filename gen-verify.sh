#!/bin/bash

PYTHON="uv run python"

# ── PKI project root ──────────────────────────────────────────────────────────
PKI_ROOT="$(pwd)"
PKI_CMD="$PYTHON $PKI_ROOT/cli.py"
PKI_PY="$PYTHON -c"

$PKI_CMD init --output pki-output --algo p256 --region 65535

main() {
  enroll_its_station
  issue_auth_ticket
}

#===================================
enroll_its_station() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Enroll an ITS-Station"
  $PKI_CMD enrol --output pki-output --name "ITS-Station-001"
  $PKI_CMD info --cert pki-output/its-stations/ITS-Station-001/ec.cert
  $PKI_CMD verify-cert --cert pki-output/its-stations/ITS-Station-001/ec.cert \
			--issuer pki-output/root_ca.cert
}

#===================================
issue_auth_ticket() {
  echo; echo; echo; echo; 
  echo "######################"
  echo "Issue an Authorization Ticket"
  $PKI_CMD issue-at --output pki-output --psid 36,37 --validity 168
  $PKI_CMD info --cert pki-output/tickets/at_1774065363.cert
#  $PKI_CMD verify-cert --cert pki-output/tickets/at_1774065363_sign.key \
#			--issuer pki-output/root_ca.cert
}

main "$@"
