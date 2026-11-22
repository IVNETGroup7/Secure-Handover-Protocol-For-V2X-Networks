#!/bin/bash
# ==============================================================================
# Build & Deploy script for Raspberry Pi 3 (Arm Cortex-A53, ARMv8-A 64-bit)
# Cross-compiles the OP-TEE Trusted Application (TA) and Normal World host app.
#
# Uses the repo-vendored SDK & sysroot under rsu-optee-gateway/rpi3-sdk/ plus
# the host's aarch64-linux-gnu- cross-compiler by default (set OPTEE_RPI3_DIR
# to use a full OP-TEE Buildroot tree instead).
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Target configuration
RPI3_SDK_DIR="${RPI3_SDK_DIR:-$SCRIPT_DIR/rpi3-sdk}"
TA_UUID="9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718"

echo "=== 1. Detecting OP-TEE RPi3 Toolchain and SDK ==="
if [ -n "${OPTEE_RPI3_DIR:-}" ]; then
    if [ ! -d "$OPTEE_RPI3_DIR" ]; then
        echo "Error: OPTEE_RPI3_DIR not found at '$OPTEE_RPI3_DIR'."
        exit 1
    fi
    TA_DEV_KIT_DIR="${TA_DEV_KIT_DIR:-$OPTEE_RPI3_DIR/optee_os/out/arm/export-ta_arm64}"
    CROSS_COMPILE_TA="${CROSS_COMPILE_TA:-$OPTEE_RPI3_DIR/toolchains/aarch64/bin/aarch64-none-linux-gnu-}"
    CROSS_COMPILE_HOST="${CROSS_COMPILE_HOST:-$OPTEE_RPI3_DIR/out-br/host/bin/aarch64-linux-gnu-}"
    SYSROOT="${SYSROOT:-$OPTEE_RPI3_DIR/out-br/host/aarch64-buildroot-linux-gnu/sysroot}"
else
    TA_DEV_KIT_DIR="${TA_DEV_KIT_DIR:-$RPI3_SDK_DIR/export-ta_arm64}"
    SYSROOT="${SYSROOT:-$RPI3_SDK_DIR/sysroot}"
    CROSS_COMPILE_TA="${CROSS_COMPILE_TA:-aarch64-linux-gnu-}"
    CROSS_COMPILE_HOST="${CROSS_COMPILE_HOST:-aarch64-linux-gnu-}"
fi

SIGN_SCRIPT="${SIGN_SCRIPT:-$TA_DEV_KIT_DIR/scripts/sign_encrypt.py}"
SIGN_KEY="${SIGN_KEY:-$TA_DEV_KIT_DIR/keys/default_ta.pem}"

if [ ! -d "$TA_DEV_KIT_DIR" ]; then
    echo "Error: TA DevKit not found at $TA_DEV_KIT_DIR"
    exit 1
fi
if [ ! -d "$SYSROOT" ]; then
    echo "Error: Target sysroot not found at $SYSROOT"
    exit 1
fi
if [ ! -f "$SIGN_SCRIPT" ] || [ ! -f "$SIGN_KEY" ]; then
    echo "Error: Signing tools (sign_encrypt.py / default_ta.pem) not found under $TA_DEV_KIT_DIR"
    exit 1
fi
for prefix in "$CROSS_COMPILE_TA" "$CROSS_COMPILE_HOST"; do
    if ! command -v "${prefix}g++" >/dev/null 2>&1; then
        echo "Error: Cross-compiler '${prefix}g++' not found in PATH."
        echo "Install the AArch64 cross-toolchain for your distro:"
        echo "  Ubuntu/Debian: sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu"
        echo "  Arch Linux:    sudo pacman -S aarch64-linux-gnu-gcc aarch64-linux-gnu-binutils"
        echo "  Fedora:        sudo dnf install gcc-aarch64-linux-gnu gcc-c++-aarch64-linux-gnu binutils-aarch64-linux-gnu"
        exit 1
    fi
done

echo "  TA DevKit:       $TA_DEV_KIT_DIR"
echo "  TA Toolchain:    $CROSS_COMPILE_TA"
echo "  Host Toolchain:  $CROSS_COMPILE_HOST"
echo "  Target Sysroot:  $SYSROOT"

echo "=== 2. Building Trusted Application (TA) ==="
cd "$SCRIPT_DIR"
make clean
cd "$SCRIPT_DIR/ta"

CPPFLAGS_TA="$("${CROSS_COMPILE_TA}g++" -E -x c++ - -v </dev/null 2>&1 \
    | sed -n '/#include <...> search starts here:/,/End of search list./p' \
    | grep '^ ' \
    | awk '{printf "-I%s ", $1}')"

make CROSS_COMPILE="$CROSS_COMPILE_TA" \
     TA_DEV_KIT_DIR="$TA_DEV_KIT_DIR" \
     EXTRA_CPPFLAGS="$CPPFLAGS_TA"

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
make app \
    TEE_MODE=OPTEE \
    CROSS_COMPILE="$CROSS_COMPILE_HOST" \
    CPU_FLAGS="-mcpu=cortex-a53 --sysroot=$SYSROOT -static-libstdc++ -static-libgcc" \
    TEEC_EXPORT="$SYSROOT/usr"

echo "  -> Built: $SCRIPT_DIR/app"

echo ""
echo "Build complete!"

if [ -n "$1" ]; then
    PI_IP="$1"
    echo "=== 4. Deploying to Raspberry Pi 3 at $PI_IP ==="
    ssh "root@$PI_IP" "mkdir -p /lib/optee_armtz /root && (killall -q app 2>/dev/null || true) && rm -f /root/app"
    scp "$SCRIPT_DIR/ta/${TA_UUID}.ta" "root@$PI_IP:/lib/optee_armtz/"
    scp "$SCRIPT_DIR/app" "root@$PI_IP:/root/"
    echo "Files transferred successfully to $PI_IP!"
    echo "To run the self-test on the Pi:"
    echo "  ssh root@$PI_IP /root/app"
    echo "To launch quad-RSU HIL (rsu[0]..rsu[3]) paired with Artery on the host:"
    echo "  ./rsu-quad-ssh.sh --pi-ip $PI_IP"
else
    echo "To deploy manually to your Pi 3, run:"
    echo "  $0 <PI_IP>"
    echo "or:"
    echo "  scp $SCRIPT_DIR/ta/${TA_UUID}.ta root@<PI_IP>:/lib/optee_armtz/"
    echo "  scp $SCRIPT_DIR/app root@<PI_IP>:/root/"
fi
