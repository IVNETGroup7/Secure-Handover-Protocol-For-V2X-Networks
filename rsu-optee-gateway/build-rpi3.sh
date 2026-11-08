#!/bin/bash
# ==============================================================================
# Build & Deploy script for Raspberry Pi 3 (Arm Cortex-A53, ARMv8-A 64-bit)
# Cross-compiles the OP-TEE Trusted Application (TA) and Normal World host app.
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Target configuration
OPTEE_RPI3_DIR="${OPTEE_RPI3_DIR:-$HOME/optee-rpi3}"
TA_UUID="9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718"

echo "=== 1. Detecting OP-TEE RPi3 Toolchain and SDK ==="
if [ ! -d "$OPTEE_RPI3_DIR" ]; then
    echo "Error: OPTEE_RPI3_DIR not found at '$OPTEE_RPI3_DIR'."
    echo "Set OPTEE_RPI3_DIR=/path/to/optee-rpi3 before running this script."
    exit 1
fi

TA_DEV_KIT_DIR="${TA_DEV_KIT_DIR:-$OPTEE_RPI3_DIR/optee_os/out/arm/export-ta_arm64}"
TOOLCHAIN_DIR="${TOOLCHAIN_DIR:-$OPTEE_RPI3_DIR/toolchains/aarch64/aarch64-none-linux-gnu}"
CROSS_COMPILE_TA="${CROSS_COMPILE_TA:-$OPTEE_RPI3_DIR/toolchains/aarch64/bin/aarch64-none-linux-gnu-}"
CROSS_COMPILE_HOST="${CROSS_COMPILE_HOST:-$OPTEE_RPI3_DIR/out-br/host/bin/aarch64-linux-gnu-}"
SYSROOT="${SYSROOT:-$OPTEE_RPI3_DIR/out-br/host/aarch64-buildroot-linux-gnu/sysroot}"

SIGN_SCRIPT="$(find "$OPTEE_RPI3_DIR" -name "sign_encrypt.py" 2>/dev/null | head -n 1)"
SIGN_KEY="$(find "$OPTEE_RPI3_DIR" -name "default_ta.pem" 2>/dev/null | head -n 1)"

if [ ! -d "$TA_DEV_KIT_DIR" ]; then
    echo "Error: TA DevKit not found at $TA_DEV_KIT_DIR"
    exit 1
fi
if [ ! -f "$SIGN_SCRIPT" ] || [ ! -f "$SIGN_KEY" ]; then
    echo "Error: Signing tools (sign_encrypt.py / default_ta.pem) not found under $OPTEE_RPI3_DIR"
    exit 1
fi

echo "  TA DevKit:       $TA_DEV_KIT_DIR"
echo "  TA Toolchain:    $CROSS_COMPILE_TA"
echo "  Host Toolchain:  $CROSS_COMPILE_HOST"
echo "  Target Sysroot:  $SYSROOT"

echo "=== 2. Building Trusted Application (TA) ==="
cd "$SCRIPT_DIR/ta"
make clean TA_DEV_KIT_DIR="$TA_DEV_KIT_DIR"

CPPFLAGS_TA="-I$TOOLCHAIN_DIR/include/c++/14.3.1 -I$TOOLCHAIN_DIR/include/c++/14.3.1/aarch64-none-linux-gnu -I$TOOLCHAIN_DIR/libc/usr/include"

make CROSS_COMPILE="$CROSS_COMPILE_TA" \
     TA_DEV_KIT_DIR="$TA_DEV_KIT_DIR" \
     CPPFLAGS="$CPPFLAGS_TA"

# Strip unnecessary GNU sections
"${CROSS_COMPILE_TA}strip" --strip-unneeded -R .comment -R .note.gnu.gold-version -R .note.gnu.property \
    "${TA_UUID}.elf" -o "${TA_UUID}.stripped.elf"

# OP-TEE OS on RPi3 expects EI_OSABI to be System V (0x00) rather than GNU (0x03)
python3 -c "
with open('${TA_UUID}.stripped.elf', 'r+b') as f:
    f.seek(7)
    f.write(b'\x00')
"

# Package and sign with OP-TEE header
python3 "$SIGN_SCRIPT" \
    --uuid "$TA_UUID" \
    --key "$SIGN_KEY" \
    --in "${TA_UUID}.stripped.elf" \
    --out "${TA_UUID}.ta"

echo "  -> Built: $SCRIPT_DIR/ta/${TA_UUID}.ta"

echo "=== 3. Building Host Application (app) ==="
cd "$SCRIPT_DIR"
make clean
make app \
    TEE_MODE=OPTEE \
    CROSS_COMPILE="$CROSS_COMPILE_HOST" \
    CPU_FLAGS="-mcpu=cortex-a53" \
    TEEC_EXPORT="$SYSROOT/usr"

echo "  -> Built: $SCRIPT_DIR/app"

echo "=== 4. Cross-compiling bootstrap runner ==="
cd "$ROOT_DIR"
"${CROSS_COMPILE_HOST}g++" -std=c++17 -O2 -mcpu=cortex-a53 \
    -Icommon -Iprotocol -Inet \
    main.cpp common/*.cpp protocol/*.cpp net/*.cpp \
    -lssl -lcrypto -lpthread -o bootstrap

echo "  -> Built: $ROOT_DIR/bootstrap"

echo ""
echo "Build complete!"

if [ -n "$1" ]; then
    PI_IP="$1"
    echo "=== 5. Deploying to Raspberry Pi 3 at $PI_IP ==="
    ssh "root@$PI_IP" "mkdir -p /lib/optee_armtz /root"
    scp "$SCRIPT_DIR/ta/${TA_UUID}.ta" "root@$PI_IP:/lib/optee_armtz/"
    scp "$SCRIPT_DIR/app" "$ROOT_DIR/bootstrap" "$SCRIPT_DIR/cloud.crt" "root@$PI_IP:/root/" 2>/dev/null || true
    echo "Files transferred successfully to $PI_IP!"
    echo "To test on the Pi, run:"
    echo "  ssh root@$PI_IP"
    echo "  ./app"
else
    echo "To deploy manually to your Pi 3, run:"
    echo "  $0 <PI_IP>"
    echo "or:"
    echo "  scp $SCRIPT_DIR/ta/${TA_UUID}.ta root@<PI_IP>:/lib/optee_armtz/"
    echo "  scp $SCRIPT_DIR/app root@<PI_IP>:/root/"
fi

