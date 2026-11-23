#!/bin/bash
# Launch all 4 logically separated Manhattan Grid RSUs (rsu[0], rsu[1], rsu[2], rsu[3]) concurrently
# on the same Raspberry Pi 3, each backed by its own Arm TrustZone OP-TEE TA session and Secure Storage
# object (rsu0.sealed .. rsu3.sealed), for Artery Hardware-in-the-Loop (HIL_RPi3_QuadRsu).
set -euo pipefail

PI_IP="${PI_IP:-}"
RSU_IFACE="${RSU_IFACE:-eth0}"
SESSION_TIMEOUT="${SESSION_TIMEOUT:-120}"
FRESH=1
REMOTE_APP="/root/app"
OTP_ALGO="${OTP:-}"

usage() {
    cat <<EOF
Usage: $0 --pi-ip <ip> [--rsu-iface <iface>] [--otp ascon|poly1305] [--session-timeout <sec>] [--keep-state] [--remote-app <path>]
   or: PI_IP=<ip> [RSU_IFACE=eth0] [OTP=ascon|poly1305] $0

Starts 4 concurrent RSU gateway processes on the Raspberry Pi 3 (Manhattan Grid edges):
  1. rsu[0] (West edge)  -> OP-TEE TA session #1, Secure Storage ID "rsu0.sealed"
  2. rsu[1] (North edge) -> OP-TEE TA session #2, Secure Storage ID "rsu1.sealed"
  3. rsu[2] (East edge)  -> OP-TEE TA session #3, Secure Storage ID "rsu2.sealed"
  4. rsu[3] (South edge) -> OP-TEE TA session #4, Secure Storage ID "rsu3.sealed"
All 4 share the single Ethernet NIC ($RSU_IFACE) via EtherTypes 0x88b5 (radio) and 0x88b6 (backhaul).
If --otp is omitted, each RSU adopts the OTP algorithm sent by Artery in Session_Ack.

Pair with Artery on the host PC:
  ./artery-sim/run-hil-quad.sh --iface <host_iface> [--otp ascon|poly1305] [--gui]
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
        --otp)
            OTP_ALGO="$2"
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

OTP_FLAG=""
if [[ -n "$OTP_ALGO" ]]; then
    if [[ "$OTP_ALGO" != "ascon" && "$OTP_ALGO" != "poly1305" ]]; then
        echo "Error: invalid --otp '$OTP_ALGO' (expected 'ascon' or 'poly1305')." >&2
        exit 2
    fi
    OTP_FLAG="--otp $OTP_ALGO"
fi

FRESH_FLAG=""
if [[ "$FRESH" -eq 1 ]]; then
    FRESH_FLAG="--fresh"
fi

HOST_TIME="$(date -u +'%Y-%m-%d %H:%M:%S')"
echo "Starting rsu[0]..rsu[3] (4 OP-TEE TA sessions${OTP_ALGO:+, otp=$OTP_ALGO}) on root@$PI_IP ($RSU_IFACE)..."

ssh -t "root@$PI_IP" "
    date -u -s '$HOST_TIME' >/dev/null 2>&1 || true
    killall -q app 2>/dev/null || pkill -f '$REMOTE_APP rsu' 2>/dev/null || true
    cleanup() {
        kill -TERM \${PID0:-} \${PID1:-} \${PID2:-} \${PID3:-} 2>/dev/null || true
        wait \${PID0:-} \${PID1:-} \${PID2:-} \${PID3:-} 2>/dev/null || true
    }
    trap cleanup EXIT INT TERM
    $REMOTE_APP rsu --name rsu[0] --iface '$RSU_IFACE' --sealed rsu0.sealed $FRESH_FLAG $OTP_FLAG --session-timeout '$SESSION_TIMEOUT' &
    PID0=\$!
    $REMOTE_APP rsu --name rsu[1] --iface '$RSU_IFACE' --sealed rsu1.sealed $FRESH_FLAG $OTP_FLAG --session-timeout '$SESSION_TIMEOUT' &
    PID1=\$!
    $REMOTE_APP rsu --name rsu[2] --iface '$RSU_IFACE' --sealed rsu2.sealed $FRESH_FLAG $OTP_FLAG --session-timeout '$SESSION_TIMEOUT' &
    PID2=\$!
    $REMOTE_APP rsu --name rsu[3] --iface '$RSU_IFACE' --sealed rsu3.sealed $FRESH_FLAG $OTP_FLAG --session-timeout '$SESSION_TIMEOUT' &
    PID3=\$!
    echo '[pi] All 4 OP-TEE RSU instances running (rsu[0] pid='\"\$PID0\"', rsu[1] pid='\"\$PID1\"', rsu[2] pid='\"\$PID2\"', rsu[3] pid='\"\$PID3\"'). Press Ctrl+C when done.'
    wait \$PID0 \$PID1 \$PID2 \$PID3
"
