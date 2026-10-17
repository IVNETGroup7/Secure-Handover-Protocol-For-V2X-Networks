#!/bin/bash
set -e

# Run as your normal user: the script calls sudo itself where needed. Under sudo, $HOME would be /root,
# $USER root (usermod would add root to the groups) and the VM would get root's SSH key instead of yours.
if [ "$EUID" -eq 0 ]; then
    echo "Error: run this script without sudo (as your normal user)."
    exit 1
fi

export LIBVIRT_DEFAULT_URI="qemu:///system"

VM_NAME="ubuntu24-tee-vm"
VM_RAM="4096"        # 4GB RAM
VM_CPUS="2"         # 2 vCPUs
DISK_SIZE="20G"     # 20 GB Disk
# Not a hidden directory: on Ubuntu, AppArmor's virt-aa-helper profile denies reading @{HOME}/.*/**,
# so it cannot follow the qcow2 to its backing image and QEMU gets "Permission denied" on it
IMG_DIR="$HOME/libvirt/images"
DISK_PATH="$IMG_DIR/$VM_NAME.qcow2"
CLOUD_ISO="$IMG_DIR/seed.iso"

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

echo "=== Step 2: Installing Development & QEMU/KVM Dependencies ==="
case "$DISTRO" in
    ubuntu|debian|linuxmint)
        sudo apt-get update
        sudo apt-get install -y \
            build-essential cmake libssl-dev git wget curl \
            ocaml ocamlbuild automake autoconf libtool \
            qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients virtinst genisoimage
        ;;

    fedora|rhel|centos)
        sudo dnf install -y \
            gcc gcc-c++ make cmake openssl-devel wget curl \
            ocaml ocamlbuild autoconf automake libtool \
            qemu-kvm libvirt virt-install genisoimage
        ;;

    arch|manjaro|endeavouros)
        sudo pacman -Syu --noconfirm
        sudo pacman -S --needed --noconfirm \
            base-devel cmake openssl git wget curl \
            ocaml ocamlbuild autoconf automake libtool \
            qemu-full libvirt virt-install cdrtools dnsmasq
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

# Ensure the 'default' NAT network exists, is active and autostarts
# (on Arch it is defined but NOT started by default)
if ! sudo virsh net-info default >/dev/null 2>&1; then
    sudo virsh net-define /etc/libvirt/qemu/networks/default.xml 2>/dev/null \
        || sudo virsh net-define /usr/share/libvirt/networks/default.xml
fi
if ! sudo virsh net-info default | grep -q "Active:.*yes"; then
    sudo virsh net-start default
fi
sudo virsh net-autostart default

# Docker sets the iptables FORWARD policy to DROP, which kills libvirt NAT.
# Allow traffic to/from virbr0 through Docker's user chain.
if systemctl is-active --quiet docker && sudo iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    sudo iptables -C DOCKER-USER -i virbr0 -j ACCEPT 2>/dev/null || sudo iptables -I DOCKER-USER -i virbr0 -j ACCEPT
    sudo iptables -C DOCKER-USER -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
        || sudo iptables -I DOCKER-USER -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fi

mkdir -p "$IMG_DIR"
# Allow libvirt-qemu to traverse $HOME to reach the disk images
if command -v setfacl >/dev/null 2>&1; then
    setfacl -m u:libvirt-qemu:x "$HOME" 2>/dev/null || setfacl -m u:qemu:x "$HOME" 2>/dev/null || true
fi

echo "=== Step 4: Downloading official Ubuntu 24.04 Cloud Image ==="
UBUNTU_IMG_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
LOCAL_IMG="$IMG_DIR/noble-server-cloudimg-amd64.img"

if [ ! -f "$LOCAL_IMG" ]; then
    wget -O "$LOCAL_IMG" "$UBUNTU_IMG_URL"
fi

echo "=== Step 5: Preparing VM Disk and Cloud-Init Configuration ==="
qemu-img create -f qcow2 -F qcow2 -b "$LOCAL_IMG" "$DISK_PATH" "$DISK_SIZE"

# Guest-side script: installs Intel SGX SDK for SIMULATION mode only
# (no SGX driver / PSW / AESM needed, works on any CPU)
cat <<'GUEST' > "$IMG_DIR/install-sgx-sdk.sh"
#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
    build-essential python-is-python3 libssl-dev wget curl

SGX_REPO="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu24.04-server"
SDK_BIN=$(curl -fsSL "$SGX_REPO/" | grep -oE 'sgx_linux_x64_sdk_[0-9.]+\.bin' | sort -uV | tail -n1)
[ -n "$SDK_BIN" ] || { echo "Could not find SGX SDK installer at $SGX_REPO"; exit 1; }

cd /tmp
wget -q "$SGX_REPO/$SDK_BIN" -O "$SDK_BIN"
chmod +x "$SDK_BIN"
echo yes | ./"$SDK_BIN" --prefix=/opt/intel

echo 'source /opt/intel/sgxsdk/environment' > /etc/profile.d/sgxsdk.sh
grep -q sgxsdk/environment /home/ubuntu/.bashrc || \
    echo 'source /opt/intel/sgxsdk/environment' >> /home/ubuntu/.bashrc
echo 'export SGX_MODE=SIM' >> /etc/profile.d/sgxsdk.sh

# Smoke test: build & run SampleEnclave in simulation mode
source /opt/intel/sgxsdk/environment
cp -r /opt/intel/sgxsdk/SampleCode/SampleEnclave /tmp/SampleEnclave
make -C /tmp/SampleEnclave SGX_MODE=SIM
(cd /tmp/SampleEnclave && ./app)

# Intel SGX-SSL: OpenSSL 3.0 inside the enclave (the gateway needs AES-256-GCM and Poly1305, which the
# SDK's sgx_tcrypto lacks). Installs to /opt/intel/sgxssl; its unit tests run in an enclave (SIM)
SGXSSL_TAG=3.0_Rev5.4
OPENSSL_VER=openssl-3.0.21
OPENSSL_SHA256=617e29af8e421f46649484a4937e48c685e47f46488167c982f88bc4ec1d522f
apt-get install -y nasm git perl
rm -rf /tmp/intel-sgx-ssl
git clone --depth 1 --branch "$SGXSSL_TAG" https://github.com/intel/intel-sgx-ssl.git /tmp/intel-sgx-ssl
wget -q "https://github.com/openssl/openssl/releases/download/$OPENSSL_VER/$OPENSSL_VER.tar.gz" \
    -O "/tmp/intel-sgx-ssl/openssl_source/$OPENSSL_VER.tar.gz"
echo "$OPENSSL_SHA256  /tmp/intel-sgx-ssl/openssl_source/$OPENSSL_VER.tar.gz" | sha256sum -c -
make -C /tmp/intel-sgx-ssl/Linux all test SGX_MODE=SIM
make -C /tmp/intel-sgx-ssl/Linux install
touch /var/log/sgx-sdk-installed
GUEST

# Create lightweight cloud-init configuration to inject SSH keys and set password
cat <<EOF > "$IMG_DIR/user-data"
#cloud-config
users:
  - name: ubuntu
    ssh_authorized_keys:
      - $(cat ~/.ssh/id_rsa.pub 2>/dev/null || cat ~/.ssh/id_ed25519.pub 2>/dev/null || echo "")
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
  - path: /usr/local/bin/install-sgx-sdk.sh
    permissions: '0755'
    content: |
$(sed 's/^/      /' "$IMG_DIR/install-sgx-sdk.sh")
runcmd:
  - [ systemctl, enable, --now, qemu-guest-agent ]
  - [ bash, -c, "/usr/local/bin/install-sgx-sdk.sh > /var/log/sgx-sdk-install.log 2>&1" ]
# Keep cloud-init output off the console (default tees to /dev/console)
output:
  all: ">> /var/log/cloud-init-output.log"
bootcmd:
  - [ sh, -c, "echo 3 > /proc/sys/kernel/printk" ]
# Don't dump SSH host keys/fingerprints to the console
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

echo "=== Step 6: Defining and Launching VM via libvirt ==="
if virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    virsh destroy "$VM_NAME" || true
    virsh undefine "$VM_NAME" || true
fi

virt-install \
    --name "$VM_NAME" \
    --memory "$VM_RAM" \
    --vcpus "$VM_CPUS" \
    --disk path="$DISK_PATH",format=qcow2,bus=virtio \
    --disk path="$CLOUD_ISO",device=cdrom \
    --os-variant ubuntu24.04 \
    --network network=default,model=virtio \
    --graphics none \
    --noautoconsole \
    --import

echo "=== Step 7: Waiting for cloud-init + SGX SDK and SGX-SSL install to finish (usually 10-20 min) ==="
# Polls the guest agent for /var/lib/cloud/instance/boot-finished, which
# cloud-init writes after ALL modules (incl. runcmd/SGX install) are done.
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
        '{"execute":"guest-file-open","arguments":{"path":"/var/log/sgx-sdk-installed"}}' >/dev/null 2>&1; then
    echo "SGX SDK (simulation mode) and SGX-SSL installed; SampleEnclave and SGX-SSL tests passed."
else
    echo "WARNING: SGX SDK install did not complete. See /var/log/sgx-sdk-install.log in the VM."
fi

echo "=== Success! Environment configured and VM '$VM_NAME' is running ==="
echo "To check IP address: sudo virsh domifaddr $VM_NAME"
echo "To attach to console: virsh console $VM_NAME"
echo "To SSH into VM (default login: ubuntu / ubuntu): ssh ubuntu@<VM-IP>"