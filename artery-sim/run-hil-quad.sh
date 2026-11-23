#!/usr/bin/env bash
set -euo pipefail

# Host-PC launcher for the 5G NR quad-RSU (4-RSU) Raspberry Pi 3 / OP-TEE VM Hardware-in-the-Loop test.
#
# All 4 RSUs (rsu[0]..rsu[3]) run physically on the Raspberry Pi 3 / OP-TEE VM,
# while CrowNet (OMNeT++ 6.3 + Artery + Simu5G) on this host runs Root CA, Human Operator,
# ESA, the 5G NR vehicle UE, 4 gNodeBs + UPF + Router, Cloud backhaul, and host SUMO 1.26.0.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

IFACE="${HIL_IFACE:-}"
OTP_ALGO="${OTP_ALGO:-${OTP:-ascon}}"
CSV_PREFIX="${CSV_PREFIX:-}"
VERBOSE="${V2X_VERBOSE:-0}"
USE_GUI=0
REBUILD=0
EXTRA_FLAGS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") --iface <nic> [options] [-- <extra opp_run flags>]

Options:
  --iface <nic>          Host Ethernet interface connected to the Raspberry Pi 3 / VM
                         (or export HIL_IFACE=<nic>)
  --otp ascon|poly1305   Select OTP/MAC algorithm for the whole run (default: ascon)
  --csv-prefix <path>    Prefix for CSV exports (<prefix>-{summary,handovers,packets}.csv)
  --verbose              Enable full per-step cryptographic trace (default: focused output)
  --gui                  Run HIL_RPi3_QuadRsu_GUI (launches sumo-gui) instead of headless
  --rebuild              Rebuild libtee_v2x.so before running
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
        --csv-prefix)
            [ $# -ge 2 ] || { echo "error: --csv-prefix requires an argument" >&2; exit 2; }
            CSV_PREFIX="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=1
            shift
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

CONFIG="HIL_RPi3_QuadRsu"
ARGS=(--config "$CONFIG" --iface "$IFACE" --otp "$OTP_ALGO")
if [ "$USE_GUI" -eq 1 ]; then
    CONFIG="HIL_RPi3_QuadRsu_GUI"
    ARGS=(--config "$CONFIG" --iface "$IFACE" --otp "$OTP_ALGO" --gui)
fi
if [ "$REBUILD" -eq 1 ]; then
    ARGS+=(--rebuild)
fi
if [ -n "$CSV_PREFIX" ]; then
    ARGS+=(--csv-prefix "$CSV_PREFIX")
fi
if [ "$VERBOSE" = "1" ]; then
    ARGS+=(--verbose)
fi
if [ ${#EXTRA_FLAGS[@]} -gt 0 ]; then
    ARGS+=(-- "${EXTRA_FLAGS[@]}")
fi

exec "$SCRIPT_DIR/run-sim.sh" "${ARGS[@]}"
