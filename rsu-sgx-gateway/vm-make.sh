#!/bin/bash
# make on a machine without the Intel SGX SDK: runs the same make in the VM of setup-vm.sh, which has the SDK and
# SGX-SSL. Starts the VM if needed, copies the repository there (rsync: only what changed), runs make and copies
# back the headers sgx_edger8r generated, for the editor (App/Enclave_u.h, Enclave/Enclave_t.h).
#
#   ./vm-make.sh <make arguments>        (the Makefile calls it when $(SGX_SDK) does not exist)
#   VM_NAME   libvirt domain             (default: ubuntu24-tee-vm, as in setup-vm.sh)
#   VM_HOST   user@address               (default: ubuntu@<the VM's address, from libvirt>)
#   VM_DIR    copy of the repository     (default: v2x, in the VM user's home)
set -e

VM_NAME=${VM_NAME:-ubuntu24-tee-vm}
VM_DIR=${VM_DIR:-v2x}
REPO=$(cd "$(dirname "$0")/.." && pwd)
export LIBVIRT_DEFAULT_URI=qemu:///system
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new)
for key in "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_ed25519"; do
    [ -f "$key" ] && SSH+=(-i "$key")
done

if ! virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    echo "error: no Intel SGX SDK here and no VM '$VM_NAME': create it with ../setup-vm.sh" >&2
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
        host=${address:+ubuntu@$address}
    else
        host=$VM_HOST
    fi
    if [ -n "$host" ] && "${SSH[@]}" "$host" true 2>/dev/null; then
        break
    fi
    host=
    sleep 2
done
if [ -z "$host" ]; then
    echo "error: no ssh to $VM_NAME (VM_HOST=user@address if its address is not libvirt's)" >&2
    exit 1
fi

# sources only: build outputs, keys and state of each side stay where they are (excluded: not deleted either).
# Compared by content, and what changed gets the VM's current time (no -t): a file put back to an older version
# is still newer than its object files, so make rebuilds it
rsync -rlp --checksum --delete -e "${SSH[*]}" \
    --exclude=.git --exclude=.vscode --exclude='*.pdf' --exclude=/bootstrap --exclude=build/ \
    --exclude='*.o' --exclude='*.d' --exclude='*.so' --exclude=/rsu-sgx-gateway/app \
    --exclude='.config_*' --exclude='.caps_*' --exclude=gateway.sealed --exclude=cloud.crt --exclude=Enclave_private.pem \
    --exclude='Enclave_u.*' --exclude='Enclave_t.*' \
    "$REPO/" "$host:$VM_DIR/"

# a terminal: ssh -t, so Ctrl-C reaches make
tty=
[ -t 0 ] && [ -t 1 ] && tty=-t
status=0
"${SSH[@]}" $tty "$host" "cd $VM_DIR/rsu-sgx-gateway && source /opt/intel/sgxsdk/environment && make $(printf '%q ' "$@")" \
    || status=$?

# the generated bridge headers, for the editor's IntelliSense (ignored by git)
rsync -a -e "${SSH[*]}" --include='Enclave_u.h' --include='Enclave_t.h' --include='App/' --include='Enclave/' \
    --exclude='*' "$host:$VM_DIR/rsu-sgx-gateway/" "$REPO/rsu-sgx-gateway/" 2>/dev/null || true
exit $status
