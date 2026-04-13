#!/bin/bash

# User certify to generate PKI authority creds to compare w/ those from C-ITS-PKI

# ./certify generate-key
# Available options:
#   --help                Print out available options.
#   --output arg          Output file.
./certify generate-key --output root_ca_sign_v1.key

# ./certify generate-root:
# Available options:
#   --help                                Print out available options.
#   --output arg                          Output file.
#   --subject-key arg                     Private key file.
#   --subject-name arg (=Hello World Root-CA)
#                                         Subject name.
#   --days arg (=365)                     Validity in days.
#   --aid arg                             Allowed ITS-AIDs to restrict 
#                                         permissions, defaults to 36 (CA) and 37
#                                         (DEN) if empty.
./certify generate-root --output root_ca_v1.cert \
                        --subject-key ./root_ca_sign_v1.key \
                        --subject-name "Test root CA"