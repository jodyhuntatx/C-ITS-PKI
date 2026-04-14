#!/bin/bash
echo "Size before: $(du -sh | cut -f1)"
rm ./cam.* ./denm.* ./*.key
rm -rf pki-output
rm -rf src/__pycache__/
rm -rf .venv ./tests/v1/.venv ./tests/v2/.venv
echo "Size after: $(du -sh | cut -f1)"
