#!/bin/bash
echo "Size before: $(du -sh | cut -f1)"
rm ./cam.* ./denm.* ./*.key
rm -rf vnap-certs
rm -rf src/__pycache__/
rm -rf .venv ./tests/v2/.venv ./tests/v3/.venv
echo "Size after: $(du -sh | cut -f1)"
