#!/bin/bash
PI_IP="192.168.15.18"
HOST_IP=$(ip -4 addr show enp3s0 | awk '/inet / {print $2}' | cut -d/ -f1)

# Sync the cloud certificate to the Pi
scp -q cloud.crt root@$PI_IP:/root/cloud.crt 2>/dev/null || true

# Extract ready-fd if passed
READY_FD=""
REMOTE_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ready-fd)
            READY_FD="$2"
            shift 2
            ;;
        *)
            REMOTE_ARGS+=("$1")
            shift
            ;;
    esac
done

# Map interface (enp3s0 -> eth0), certificate path, and cloud address to PC
ARGS="${REMOTE_ARGS[*]//enp3s0/eth0}"
ARGS="${ARGS//cloud.crt/\/root/cloud.crt}"

# Run SSH and monitor for the RSU's public key (signal readiness to host)
ssh root@$PI_IP "/root/app $ARGS --cloud-address $HOST_IP" 2>&1 | while IFS= read -r line; do
    echo "$line"
    # When RSU prints CY_g, signal ready to the parent process if ready-fd was set
    if [[ -n "$READY_FD" && "$line" =~ CY_g[[:space:]]*=[[:space:]]*([0-9a-fA-F]+) ]]; then
        CY_G_HEX="${BASH_REMATCH[1]}"
        # Write byte 0x01 then the binary DER bytes to the ready fd
        python3 -c "import sys, os; os.write($READY_FD, b'\x01' + bytes.fromhex('$CY_G_HEX'))" 2>/dev/null || true
        READY_FD=""
    fi
done
