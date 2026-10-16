#!/usr/bin/env bash
# Builds the INERT test fixtures that validate the scanner's detectors.
# Both binaries are harmless: each prints one line and exits. See src/demo_vendor_app.c.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin

# "Vulnerable" build: keeps the synthetic markers, compiled WITHOUT hardening.
#   -fno-stack-protector : no stack canary
#   -no-pie              : not a position-independent executable
#   -Wl,-z,norelro       : no RELRO
# Expected to FAIL several controls (see answer_key.yaml).
gcc -O0 -fno-stack-protector -no-pie -Wl,-z,norelro \
    src/demo_vendor_app.c -o bin/demo_vendor_app

# "Remediated" build: markers removed, compiled WITH hardening. Expected to PASS.
gcc -O2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now \
    -DREMEDIATED src/demo_vendor_app.c -o bin/demo_vendor_app_hardened

echo "built:"
echo "  bin/demo_vendor_app            (vulnerable fixture)"
echo "  bin/demo_vendor_app_hardened   (remediated fixture)"
