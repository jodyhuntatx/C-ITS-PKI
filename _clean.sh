#!/bin/bash
echo "Size before: $(du -sh | cut -f1)"
rm -rf vanetza-docker/vanetza-nap
rm ./cam.* ./denm.*
rm -rf pki-output
rm -rf src/__pycache__/
rm -rf .venv
echo "Size after: $(du -sh | cut -f1)"
