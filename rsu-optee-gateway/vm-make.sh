#!/bin/bash
set -e

VM_NAME=${VM_NAME:-optee-arm64-vm}
VM_DIR=${VM_DIR:-v2x}
VM_USER=${VM_USER:-optee}
REPO=$(cd "$(dirname "$0")/.." && pwd)
export LIBVIRT_DEFAULT_URI=qemu:///system
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new)
for key in "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_ed25519"; do
    [ -f "$key" ] && SSH+=(-i "$key")
done

if ! virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    echo "error: no OP-TEE SDK here and no VM '$VM_NAME': create it with ../setup-vm.sh" >&2
    exit 1
fi
if [ "$(virsh domstate "$VM_NAME")" != "running" ]; then
    echo "[vm] starting $VM_NAME"
    virsh start "$VM_NAME" >/dev/null
fi

# the address comes from the DHCP lease of libvirt's default network; ssh answers once the VM has booted
for _ in $(seq 60); do
    if [ -z "$VM_HOST" ]; then
        address=$(virsh domifaddr "$VM_NAME" 2>/dev/null | awk '$3 == "ipv4" { split($4, a, "/"); print a[1]; exit }')
        if [ -n "$address" ]; then
            for u in "$VM_USER" ubuntu; do
                if "${SSH[@]}" "$u@$address" true 2>/dev/null; then
                    host="$u@$address"
                    break 2
                fi
            done
        fi
    else
        host=$VM_HOST
        if "${SSH[@]}" "$host" true 2>/dev/null; then
            break
        fi
    fi
    host=
    sleep 2
done
if [ -z "$host" ]; then
    echo "error: no ssh to $VM_NAME (VM_HOST=user@address if its address is not libvirt's)" >&2
    exit 1
fi

# Ensure target directory exists and user owns their home
"${SSH[@]}" "$host" "sudo chown -R \$(id -un):\$(id -gn) \$HOME && mkdir -p \$HOME/$VM_DIR" 2>/dev/null || true

rsync -rlp --checksum --delete -e "${SSH[*]}" \
    --exclude=.git --exclude=.vscode --exclude='*.pdf' --exclude=/bootstrap --exclude='build*/' \
    --exclude='*.o' --exclude='*.d' --exclude='*.ta' --exclude=/rsu-optee-gateway/app \
    --exclude='.caps_*' --exclude='gateway.sealed*' --exclude=cloud.crt \
    --exclude=/artery-sim/deps/ --exclude=/artery-sim/scenario/results/ --exclude='/artery-sim/scenario/*.sealed' \
    --exclude=/artery-sim/scenario/.cmdenv-log --exclude=/artery-sim/scenario/.qtenvrc \
    "$REPO/" "$host:$VM_DIR/"

tty=
[ -t 0 ] && [ -t 1 ] && tty=-t
status=0
"${SSH[@]}" $tty "$host" "cd $VM_DIR/rsu-optee-gateway && source /etc/profile.d/optee.sh 2>/dev/null || true && make $(printf '%q ' "$@")" \
    || status=$?
exit $status

