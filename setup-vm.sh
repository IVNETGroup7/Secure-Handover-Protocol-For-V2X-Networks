#!/bin/bash
set -e

# Sets up the Arm TrustZone + OP-TEE development, simulation (QEMU ARMv8-A), and
# Raspberry Pi 5 (Arm Cortex-A76) cross-compilation environment.
#
# Run as your normal user: the script calls sudo itself where needed.
if [ "$EUID" -eq 0 ]; then
    echo "Error: run this script without sudo (as your normal user)."
    exit 1
fi

export LIBVIRT_DEFAULT_URI="qemu:///system"

VM_NAME="optee-arm64-vm"
VM_RAM="4096"        # 4GB RAM
VM_CPUS="2"          # 2 vCPUs
DISK_SIZE="20G"      # 20 GB Disk
IMG_DIR="$HOME/libvirt/images"
DISK_PATH="$IMG_DIR/$VM_NAME.qcow2"
CLOUD_ISO="$IMG_DIR/seed-optee.iso"

# Host directory shared into the VM (via virtiofs) at /home/ubuntu/project
SHARE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARE_TAG="project"
GUEST_MOUNT="/home/ubuntu/project"

RECREATE=false
for arg in "$@"; do
    case "$arg" in
        --recreate) RECREATE=true ;;
        -h|--help)
            echo "Usage: $0 [--recreate]"
            echo "  (default)   Reuse the existing OP-TEE VM if it exists (just start it)."
            echo "  --recreate  DESTROY the existing OP-TEE VM and its disk, then build a fresh one."
            exit 0 ;;
        *) echo "Unknown option: $arg (see --help)"; exit 1 ;;
    esac
done

echo "=== Step 1: Detecting Linux Distribution ==="
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
elif type lsb_release >/dev/null 2>&1; then
    DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
else
    DISTRO="unknown"
fi

echo "Detected distribution: $DISTRO"

echo "=== Step 2: Installing ARM64 Cross-Compilation & QEMU/KVM Dependencies ==="
case "$DISTRO" in
    ubuntu|debian|linuxmint)
        sudo apt-get update
        sudo apt-get install -y \
            build-essential cmake libssl-dev git wget curl rsync \
            gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
            device-tree-compiler python3-pyelftools python3-cryptography \
            qemu-kvm qemu-system-arm qemu-utils libvirt-daemon-system libvirt-clients virtinst genisoimage virtiofsd
        ;;

    fedora|rhel|centos)
        sudo dnf install -y \
            gcc gcc-c++ make cmake openssl-devel wget curl rsync \
            gcc-aarch64-linux-gnu gcc-c++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
            dtc python3-pyelftools python3-cryptography \
            qemu-kvm qemu-system-aarch64 libvirt virt-install genisoimage virtiofsd
        ;;

    arch|manjaro|endeavouros)
        sudo pacman -Syu --noconfirm
        sudo pacman -S --needed --noconfirm \
            base-devel cmake openssl git wget curl rsync \
            aarch64-linux-gnu-gcc aarch64-linux-gnu-binutils \
            dtc python-pyelftools python-cryptography \
            qemu-full libvirt virt-install cdrtools dnsmasq virtiofsd
        ;;

    *)
        echo "Error: Unsupported distribution '$DISTRO'."
        exit 1
        ;;
esac

echo "=== Step 3: Configuring KVM & Libvirt Services ==="
if [ "$DISTRO" = "arch" ]; then
    sudo systemctl enable --now libvirtd.service
else
    sudo systemctl enable --now libvirtd
fi

sudo usermod -aG kvm,libvirt "$USER"

if ! sudo virsh net-info default >/dev/null 2>&1; then
    sudo virsh net-define /etc/libvirt/qemu/networks/default.xml 2>/dev/null \
        || sudo virsh net-define /usr/share/libvirt/networks/default.xml
fi
if ! sudo virsh net-info default | grep -q "Active:.*yes"; then
    sudo virsh net-start default
fi
sudo virsh net-autostart default

if systemctl is-active --quiet docker && sudo iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    sudo iptables -C DOCKER-USER -i virbr0 -j ACCEPT 2>/dev/null || sudo iptables -I DOCKER-USER -i virbr0 -j ACCEPT
    sudo iptables -C DOCKER-USER -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
        || sudo iptables -I DOCKER-USER -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fi

mkdir -p "$IMG_DIR"
if command -v setfacl >/dev/null 2>&1; then
    setfacl -m u:libvirt-qemu:x "$HOME" 2>/dev/null || setfacl -m u:qemu:x "$HOME" 2>/dev/null || true
fi

if virsh dominfo "$VM_NAME" >/dev/null 2>&1 && [ "$RECREATE" = false ]; then
    echo "=== VM '$VM_NAME' already exists: reusing it (use --recreate to rebuild from scratch) ==="
    if ! virsh domstate "$VM_NAME" | grep -q running; then
        virsh start "$VM_NAME"
    fi
    printf 'Waiting for IP'
    for _ in $(seq 1 30); do
        VM_IP=$(virsh domifaddr "$VM_NAME" 2>/dev/null | awk '/ipv4/ {split($4,a,"/"); print a[1]}')
        [ -n "$VM_IP" ] && break
        printf '.'; sleep 2
    done
    echo
    echo "VM is running. IP: ${VM_IP:-unknown}"
    echo "SSH: ssh ubuntu@${VM_IP:-<VM-IP>}   (repo mounted at $GUEST_MOUNT)"
    exit 0
fi

if [ "$RECREATE" = true ] && virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    echo "WARNING: --recreate will DELETE '$VM_NAME' and everything inside it (files in $SHARE_DIR are safe)."
    read -r -p "Type 'yes' to continue: " CONFIRM
    [ "$CONFIRM" = "yes" ] || { echo "Aborted."; exit 1; }
    virsh destroy "$VM_NAME" 2>/dev/null || true
    virsh undefine "$VM_NAME" || true
fi

echo "=== Step 4: Downloading official Ubuntu 24.04 Cloud Image ==="
UBUNTU_IMG_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
LOCAL_IMG="$IMG_DIR/noble-server-cloudimg-amd64.img"

if [ ! -f "$LOCAL_IMG" ]; then
    wget -O "$LOCAL_IMG" "$UBUNTU_IMG_URL"
fi

echo "=== Step 5: Preparing VM Disk and Cloud-Init Configuration (OP-TEE OS + TA DevKit + libteec) ==="
rm -f "$DISK_PATH"
qemu-img create -f qcow2 -F qcow2 -b "$LOCAL_IMG" "$DISK_PATH" "$DISK_SIZE"

# Guest-side script: installs ARM64 cross-compilers, QEMU ARMv8-A (virt + TrustZone EL3/S-EL1),
# OP-TEE OS (export-ta_arm64 devkit for QEMU ARMv8-A & Raspberry Pi 5 Cortex-A76), and optee_client (libteec).
cat <<'GUEST' > "$IMG_DIR/install-optee-sdk.sh"
#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
    build-essential python-is-python3 python3-pip python3-pyelftools python3-cryptography \
    libssl-dev wget curl git cmake ninja-build pkg-config uuid-dev \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf device-tree-compiler qemu-system-arm

OPTEE_DIR=/opt/optee
OPTEE_TAG=4.4.0
mkdir -p "$OPTEE_DIR"

# 1. Build OP-TEE OS for QEMU ARMv8-A (vexpress-qemu_armv8a) -> produces Secure World bl32.bin + export-ta_arm64 DevKit
if [ ! -d "$OPTEE_DIR/optee_os" ]; then
    git clone --depth 1 --branch "$OPTEE_TAG" https://github.com/OP-TEE/optee_os.git "$OPTEE_DIR/optee_os"
fi
make -C "$OPTEE_DIR/optee_os" -j"$(nproc)" \
    PLATFORM=vexpress-qemu_armv8a \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CROSS_COMPILE_core=aarch64-linux-gnu- \
    CROSS_COMPILE_ta_arm64=aarch64-linux-gnu- \
    CFG_ARM64_core=y \
    CFG_TEE_CORE_LOG_LEVEL=2 \
    ta_dev_kit

# 2. Build OP-TEE Client (libteec + tee-supplicant)
if [ ! -d "$OPTEE_DIR/optee_client" ]; then
    git clone --depth 1 --branch "$OPTEE_TAG" https://github.com/OP-TEE/optee_client.git "$OPTEE_DIR/optee_client"
fi
make -C "$OPTEE_DIR/optee_client" -j"$(nproc)" \
    CROSS_COMPILE=aarch64-linux-gnu- \
    WITH_TEEACL=0 \
    O="$OPTEE_DIR/optee_client/out"

cat <<'EOF' > /etc/profile.d/optee.sh
export OPTEE_DIR=/opt/optee
export TA_DEV_KIT_DIR=/opt/optee/optee_os/out/arm-plat-vexpress/export-ta_arm64
export TEEC_EXPORT=/opt/optee/optee_client/out/export/usr
EOF
grep -q /etc/profile.d/optee.sh /home/ubuntu/.bashrc || \
    echo 'source /etc/profile.d/optee.sh' >> /home/ubuntu/.bashrc

chown -R ubuntu:ubuntu "$OPTEE_DIR" /home/ubuntu || true
touch /var/log/optee-sdk-installed
GUEST

cat <<EOF > "$IMG_DIR/user-data"
#cloud-config
users:
  - name: ubuntu
    ssh_authorized_keys:
$(for k in ~/.ssh/id_rsa.pub ~/.ssh/id_ed25519.pub; do [ -f "$k" ] && echo "      - $(cat "$k")"; done)
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    lock_passwd: false
chpasswd:
  list: |
    ubuntu:ubuntu
  expire: False
ssh_pwauth: true
package_update: true
packages:
  - qemu-guest-agent
write_files:
  - path: /usr/local/bin/install-optee-sdk.sh
    permissions: '0755'
    content: |
$(sed 's/^/      /' "$IMG_DIR/install-optee-sdk.sh")
runcmd:
  - [ systemctl, enable, --now, qemu-guest-agent ]
  - [ bash, -c, "/usr/local/bin/install-optee-sdk.sh > /var/log/optee-sdk-install.log 2>&1" ]
output:
  all: ">> /var/log/cloud-init-output.log"
bootcmd:
  - [ sh, -c, "echo 3 > /proc/sys/kernel/printk" ]
mounts:
  - [ $SHARE_TAG, $GUEST_MOUNT, virtiofs, "defaults,nofail", "0", "0" ]
ssh:
  emit_keys_to_console: false
no_ssh_fingerprints: true
EOF

cat <<EOF > "$IMG_DIR/meta-data"
instance-id: $VM_NAME
local-hostname: $VM_NAME
EOF

rm -f "$CLOUD_ISO"
genisoimage -output "$CLOUD_ISO" -volid cidata -joliet -rock "$IMG_DIR/user-data" "$IMG_DIR/meta-data" >/dev/null

echo "=== Step 6: Defining and Launching OP-TEE VM via libvirt ==="
virt-install \
    --name "$VM_NAME" \
    --memory "$VM_RAM" \
    --vcpus "$VM_CPUS" \
    --disk path="$DISK_PATH",format=qcow2,bus=virtio \
    --disk path="$CLOUD_ISO",device=cdrom \
    --os-variant ubuntu24.04 \
    --network network=default,model=virtio \
    --memorybacking source.type=memfd,access.mode=shared \
    --filesystem source="$SHARE_DIR",target="$SHARE_TAG",driver.type=virtiofs \
    --graphics none \
    --noautoconsole \
    --import

echo "=== Step 7: Waiting for cloud-init + OP-TEE OS & TA DevKit build to finish ==="
TIMEOUT=1800; ELAPSED=0
until virsh qemu-agent-command "$VM_NAME" \
        '{"execute":"guest-file-open","arguments":{"path":"/var/lib/cloud/instance/boot-finished"}}' \
        >/dev/null 2>&1; do
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo; echo "Timed out waiting for cloud-init. Check /var/log/cloud-init-output.log in the VM."
        break
    fi
    printf '.'; sleep 10; ELAPSED=$((ELAPSED + 10))
done
echo

if virsh qemu-agent-command "$VM_NAME" \
        '{"execute":"guest-file-open","arguments":{"path":"/var/log/optee-sdk-installed"}}' >/dev/null 2>&1; then
    echo "OP-TEE OS (ARMv8-A TA DevKit) and optee_client (libteec) installed."
else
    echo "WARNING: OP-TEE SDK install did not complete. See /var/log/optee-sdk-install.log in the VM."
fi

VM_IP=$(virsh domifaddr "$VM_NAME" 2>/dev/null | awk '/ipv4/ {split($4,a,"/"); print a[1]}')
echo "=== Success! Environment configured and VM '$VM_NAME' is running ==="
echo "IP address: ${VM_IP:-unknown}  (virsh domifaddr $VM_NAME)"
echo "SSH (login: ubuntu / ubuntu): ssh ubuntu@${VM_IP:-<VM-IP>}"
echo "Host repo $SHARE_DIR is mounted in the VM at $GUEST_MOUNT"
echo "Console: virsh console $VM_NAME  (exit with Ctrl + ])"
