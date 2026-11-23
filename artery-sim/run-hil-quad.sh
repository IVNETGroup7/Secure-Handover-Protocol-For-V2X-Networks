#!/usr/bin/env bash
set -euo pipefail

# Host-PC launcher for the quad-RSU (4-RSU) Raspberry Pi 3 Hardware-in-the-Loop test.
#
# All 4 RSUs (rsu[0]..rsu[3]) run physically on the Raspberry Pi 3 (via rsu-quad-ssh.sh),
# while Artery on this host runs Root CA, Human Operator, ESA, the vehicle, Cloud backhaul, SUMO, and radio PHY/MAC.
# Requires opp_run_release to hold cap_net_raw+ep (configured by setup_artery.sh).

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/deps/artery/build"

IFACE="${HIL_IFACE:-}"
OTP_ALGO="${OTP_ALGO:-${OTP:-ascon}}"
USE_GUI=0
REBUILD=0
EXTRA_FLAGS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") --iface <nic> [options] [-- <extra opp_run flags>]

Options:
  --iface <nic>          Host Ethernet interface connected to the Raspberry Pi 3
                         (or export HIL_IFACE=<nic>)
  --otp ascon|poly1305   Select OTP/MAC algorithm for the whole run (default: ascon)
  --gui                  Run HIL_RPi3_QuadRsu_GUI (launches sumo-gui) instead of headless
  --rebuild              Rebuild the tee_v2x shared library before running
  -h, --help             Show this help message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --iface)
            [ $# -ge 2 ] || { echo "error: --iface requires an argument" >&2; exit 2; }
            IFACE="$2"
            shift 2
            ;;
        --otp)
            [ $# -ge 2 ] || { echo "error: --otp requires an argument" >&2; exit 2; }
            OTP_ALGO="$2"
            shift 2
            ;;
        --gui)
            USE_GUI=1
            shift
            ;;
        --rebuild)
            REBUILD=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            EXTRA_FLAGS+=("$@")
            break
            ;;
        *)
            echo "error: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ -z "$IFACE" ]; then
    echo "error: host Ethernet interface is required (--iface <nic> or HIL_IFACE=<nic>)" >&2
    usage >&2
    exit 2
fi

if [ "$OTP_ALGO" != "ascon" ] && [ "$OTP_ALGO" != "poly1305" ]; then
    echo "error: invalid --otp '$OTP_ALGO' (expected 'ascon' or 'poly1305')" >&2
    exit 2
fi

if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
    echo "error: Artery build directory not initialized ($BUILD_DIR); run $SCRIPT_DIR/setup_artery.sh first" >&2
    exit 1
fi

if [ "$REBUILD" -eq 1 ]; then
    echo "[run-hil-quad] rebuilding tee_v2x..."
    cmake --build "$BUILD_DIR" --target tee_v2x -j"$(nproc)"
fi

CONFIG="HIL_RPi3_QuadRsu"
if [ "$USE_GUI" -eq 1 ]; then
    CONFIG="HIL_RPi3_QuadRsu_GUI"
fi

RUN_FLAGS="-u Cmdenv -c $CONFIG --scheduler-class=omnetpp::cRealTimeScheduler"
if [ ${#EXTRA_FLAGS[@]} -gt 0 ]; then
    RUN_FLAGS="$RUN_FLAGS ${EXTRA_FLAGS[*]}"
fi

export HIL_IFACE="$IFACE"
export OTP_ALGO="$OTP_ALGO"
echo "[run-hil-quad] HIL_IFACE=$HIL_IFACE OTP_ALGO=$OTP_ALGO config=$CONFIG"

cmake -DRUN_FLAGS="$RUN_FLAGS" "$BUILD_DIR"
exec cmake --build "$BUILD_DIR" --target run_tee_v2x_handover

