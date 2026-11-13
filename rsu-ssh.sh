#!/bin/bash
PI_IP="${PI_IP:-}"
HOST_IFACE="${HOST_IFACE:-}"
RSU_IFACE="${RSU_IFACE:-eth0}"

usage() {
    echo "Usage: $0 --pi-ip <ip> --host-iface <iface> [--rsu-iface <iface>] [app-args...]"
    echo "   or: PI_IP=<ip> HOST_IFACE=<iface> [RSU_IFACE=<iface>] $0 [app-args...]"
    echo "       (When invoked via './bootstrap --iface <iface> --rsu-exec $0', --iface is used as HOST_IFACE.)"
}

# Extract wrapper/ready-fd options if passed
READY_FD=""
REMOTE_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pi-ip)
            PI_IP="$2"
            shift 2
            ;;
        --host-iface)
            HOST_IFACE="$2"
            shift 2
            ;;
        --rsu-iface)
            RSU_IFACE="$2"
            shift 2
            ;;
        --iface)
            if [[ -z "$HOST_IFACE" ]]; then
                HOST_IFACE="$2"
            fi
            REMOTE_ARGS+=("$1" "$2")
            shift 2
            ;;
        --ready-fd)
            READY_FD="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            REMOTE_ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ -z "$PI_IP" ]]; then
    echo "Error: Raspberry Pi IP not specified (pass --pi-ip <ip> or set PI_IP=<ip>)." >&2
    usage >&2
    exit 1
fi

if [[ -z "$HOST_IFACE" ]]; then
    echo "Error: Host interface not specified (pass --host-iface <iface>, --iface <iface>, or set HOST_IFACE=<iface>)." >&2
    usage >&2
    exit 1
fi

HOST_IP=$(ip -4 addr show "$HOST_IFACE" | awk '/inet / {print $2}' | cut -d/ -f1)
if [[ -z "$HOST_IP" ]]; then
    echo "Error: Could not determine IPv4 address for host interface '$HOST_IFACE'." >&2
    exit 1
fi

# Sync the cloud certificate to the Pi
scp -q cloud.crt "root@$PI_IP:/root/cloud.crt" 2>/dev/null || true

# Map interface ($HOST_IFACE -> $RSU_IFACE), certificate path, and cloud address to PC
ARGS="${REMOTE_ARGS[*]//$HOST_IFACE/$RSU_IFACE}"
ARGS="${ARGS//cloud.crt/\/root/cloud.crt}"

# Run SSH and monitor for the RSU's public key (signal readiness to host)
HOST_TIME=$(date -u +'%Y-%m-%d %H:%M:%S')
ssh root@$PI_IP "date -u -s '$HOST_TIME' >/dev/null 2>&1 || true; /root/app $ARGS --cloud-address $HOST_IP" 2>&1 | while IFS= read -r line; do
    echo "$line"
    # When RSU prints CY_g, signal ready to the parent process if ready-fd was set
    if [[ -n "$READY_FD" && "$line" =~ CY_g[[:space:]]*=[[:space:]]*([0-9a-fA-F]+) ]]; then
        CY_G_HEX="${BASH_REMATCH[1]}"
        # Write byte 0x01 then the binary DER bytes to the ready fd
        python3 -c "import sys, os; os.write($READY_FD, b'\x01' + bytes.fromhex('$CY_G_HEX'))" 2>/dev/null || true
        READY_FD=""
    fi
done
