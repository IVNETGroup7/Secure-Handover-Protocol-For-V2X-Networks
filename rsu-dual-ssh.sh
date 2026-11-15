#!/bin/bash
# Launch BOTH logically separated RSUs (rsu[0] and rsu[1]) concurrently on the same
# Raspberry Pi 3, each backed by its own Arm TrustZone OP-TEE TA session and Secure Storage
# object (rsu0.sealed / rsu1.sealed), for Artery Hardware-in-the-Loop (HIL_RPi3_DualRsu).
set -euo pipefail

PI_IP="${PI_IP:-}"
RSU_IFACE="${RSU_IFACE:-eth0}"
SESSION_TIMEOUT="${SESSION_TIMEOUT:-120}"
FRESH=1
REMOTE_APP="/root/app"

usage() {
    cat <<EOF
Usage: $0 --pi-ip <ip> [--rsu-iface <iface>] [--session-timeout <sec>] [--keep-state] [--remote-app <path>]
   or: PI_IP=<ip> [RSU_IFACE=eth0] $0

Starts two concurrent RSU gateway processes on the Raspberry Pi 3:
  1. rsu[0] -> OP-TEE TA session #1, Secure Storage ID "rsu0.sealed"
  2. rsu[1] -> OP-TEE TA session #2, Secure Storage ID "rsu1.sealed"
Both share the single Ethernet NIC ($RSU_IFACE) via EtherTypes 0x88b5 (radio) and 0x88b6 (backhaul).

Pair with Artery on the host PC:
  ./artery-sim/run-hil-dual.sh --iface <host_iface> [--gui]
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pi-ip)
            PI_IP="$2"
            shift 2
            ;;
        --rsu-iface)
            RSU_IFACE="$2"
            shift 2
            ;;
        --session-timeout)
            SESSION_TIMEOUT="$2"
            shift 2
            ;;
        --keep-state)
            FRESH=0
            shift
            ;;
        --remote-app)
            REMOTE_APP="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown argument '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "$PI_IP" ]]; then
    echo "Error: Raspberry Pi IP not specified (pass --pi-ip <ip> or set PI_IP=<ip>)." >&2
    usage >&2
    exit 1
fi

FRESH_FLAG=""
if [[ "$FRESH" -eq 1 ]]; then
    FRESH_FLAG="--fresh"
fi

HOST_TIME="$(date -u +'%Y-%m-%d %H:%M:%S')"
echo "Starting rsu[0] + rsu[1] (two OP-TEE TA sessions) on root@$PI_IP ($RSU_IFACE)..."

ssh -t "root@$PI_IP" "
    date -u -s '$HOST_TIME' >/dev/null 2>&1 || true
    pkill -f '$REMOTE_APP rsu' 2>/dev/null || true
    cleanup() {
        kill -TERM \${PID0:-} \${PID1:-} 2>/dev/null || true
        wait \${PID0:-} \${PID1:-} 2>/dev/null || true
    }
    trap cleanup EXIT INT TERM
    $REMOTE_APP rsu --name rsu[0] --iface '$RSU_IFACE' --sealed rsu0.sealed $FRESH_FLAG --session-timeout '$SESSION_TIMEOUT' &
    PID0=\$!
    $REMOTE_APP rsu --name rsu[1] --iface '$RSU_IFACE' --sealed rsu1.sealed $FRESH_FLAG --session-timeout '$SESSION_TIMEOUT' &
    PID1=\$!
    echo '[pi] Both OP-TEE RSU instances running (rsu[0] pid='\"\$PID0\"', rsu[1] pid='\"\$PID1\"'). Press Ctrl+C when done.'
    wait \$PID0 \$PID1
"

