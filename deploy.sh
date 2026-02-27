#!/usr/bin/env bash
set -euo pipefail

echo "Deploying cltv-scan to Fly.io..."
flyctl deploy --local-only
