#!/bin/bash
echo "Size before: $(du -sh | cut -f1)"
rm -rf pki-output
rm -rf src/__pycache__/
rm -rf .venv
echo "Size after: $(du -sh | cut -f1)"
