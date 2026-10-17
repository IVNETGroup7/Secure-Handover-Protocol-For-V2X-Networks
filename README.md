# Secure-Handover-Protocol-For-V2X-Networks

## Development VM (Intel SGX SDK – simulation mode)

[`setup-vm.sh`](setup-vm.sh) creates an Ubuntu 24.04 VM (QEMU/KVM + libvirt) with the
**Intel SGX SDK installed in simulation mode**, so enclaves can be built and run on any CPU
(no SGX hardware, driver or PSW needed).

### Supported hosts

- Arch / Manjaro / EndeavourOS
- Ubuntu / Debian / Linux Mint
- Fedora / RHEL / CentOS

### What the script does

1. Installs host dependencies (QEMU, libvirt, virt-install, dnsmasq, ISO tools, build tools).
2. Enables `libvirtd`, starts/autostarts the `default` NAT network, and adds your user to the
   `kvm` and `libvirt` groups. If Docker is running, it whitelists `virbr0` so the VM has internet.
3. Downloads the official Ubuntu 24.04 cloud image to `~/.libvirt/images/`.
4. Creates a 20 GB disk and a cloud-init seed that:
   - creates user `ubuntu` / password `ubuntu` (passwordless `sudo`),
   - injects your `~/.ssh/id_rsa.pub` or `~/.ssh/id_ed25519.pub` if present,
   - installs the SGX SDK to `/opt/intel/sgxsdk` and sets `SGX_MODE=SIM`,
   - builds and runs `SampleEnclave` as a smoke test.
5. Boots the VM headless and waits until provisioning finishes (usually 2–4 min).

### Usage

```bash
./setup-vm.sh
```

You'll be asked for your `sudo` password. On success you'll see:

```
SGX SDK (simulation mode) installed and SampleEnclave test passed.
=== Success! Environment configured and VM 'ubuntu24-tee-vm' is running ===
```

> [!WARNING]
> Re-running the script **destroys and recreates** the VM (fresh disk). Don't keep
> un-pushed work only inside the VM.

> [!NOTE]
> After the first run, log out and back in so the `libvirt` group membership takes effect.
> Until then, prefix `virsh` commands with `sudo` or use `-c qemu:///system`.

### Useful commands

Tip: avoid typing `-c qemu:///system` every time:

```bash
echo 'export LIBVIRT_DEFAULT_URI=qemu:///system' >> ~/.bashrc && source ~/.bashrc
```

| Task | Command |
|---|---|
| List VMs and their state | `virsh list --all` |
| Get the VM's IP | `virsh domifaddr ubuntu24-tee-vm` |
| SSH into the VM | `ssh ubuntu@<IP>` (password `ubuntu`) |
| Attach to serial console | `virsh console ubuntu24-tee-vm` (exit with `Ctrl + ]`) |
| Start the VM | `virsh start ubuntu24-tee-vm` |
| Graceful shutdown | `virsh shutdown ubuntu24-tee-vm` (or `sudo poweroff` inside) |
| Force power off | `virsh destroy ubuntu24-tee-vm` |
| Delete the VM definition | `virsh undefine ubuntu24-tee-vm` |
| Stop all running VMs | `for vm in $(virsh list --name); do virsh destroy "$vm"; done` |

SSH in one line (uses the IP without the `/24` suffix):

```bash
ssh ubuntu@$(virsh domifaddr ubuntu24-tee-vm | awk '/ipv4/ {split($4,a,"/"); print a[1]}')
```

Copy files to/from the VM:

```bash
scp -r ./my-enclave ubuntu@<IP>:~/
scp ubuntu@<IP>:~/output.log .
```

> [!TIP]
> Every rebuild generates new SSH host keys. If SSH complains about a changed host key, run
> `ssh-keygen -R <IP>`.

### Inside the VM

```bash
source /opt/intel/sgxsdk/environment   # already done in ~/.bashrc
echo $SGX_MODE                         # SIM

# Build & run the sample enclave
cp -r /opt/intel/sgxsdk/SampleCode/SampleEnclave ~/
cd ~/SampleEnclave && make SGX_MODE=SIM && ./app
```

Logs:

| Log | Contents |
|---|---|
| `/var/log/cloud-init-output.log` | Full cloud-init provisioning output |
| `/var/log/sgx-sdk-install.log` | SGX SDK install + SampleEnclave test |
| `/var/log/sgx-sdk-installed` | Marker file: exists only if install succeeded |

### Troubleshooting

| Symptom | Fix |
|---|---|
| `network 'default' is not active` | `sudo virsh net-start default && sudo virsh net-autostart default` |
| VM has no internet (apt `Network is unreachable`) | Docker blocks forwarding: `sudo iptables -I DOCKER-USER -i virbr0 -j ACCEPT` and `sudo iptables -I DOCKER-USER -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` |
| `may not be accessible by the hypervisor` | `setfacl -m u:libvirt-qemu:x ~` |
| `Host key verification failed` | `ssh-keygen -R <IP>` then SSH again (answer `yes`) |
| `poweroff`: *Interactive authentication required* | Use `sudo poweroff` |
| Script errors with strange syntax errors | Don't edit `setup-vm.sh` while it's running |