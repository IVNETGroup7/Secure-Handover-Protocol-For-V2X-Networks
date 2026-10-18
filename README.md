# Secure-Handover-Protocol-For-V2X-Networks

Secure bootstrap / handover protocol between a **vehicle**, an **RSU** (Road-Side Unit) and an
**ESA** (External Security Agent), written in C++17 + OpenSSL 3. Each node runs as its own process and
they talk over raw Ethernet sockets (no Artery/OMNeT++). There are two RSU options:

- the **plain RSU**, part of `./bootstrap` itself;
- the **SGX RSU gateway** ([`rsu-sgx-gateway/`](rsu-sgx-gateway)): the RSU's secrets and crypto live in an
  Intel SGX enclave (simulation mode, so any CPU works).

## Repository layout

| Path | Contents |
|---|---|
| [`common/`](common) | Messages, payloads, crypto, vehicle traits, simulated time, tracing |
| [`protocol/`](protocol) | Bootstrap protocol (`BootstrapService`, `ExternalSecurityAgent`) and its API (`Bootstrap.h`) |
| [`net/`](net) | Raw Ethernet sockets (`AF_PACKET`) |
| [`main.cpp`](main.cpp), [`TraceView.cpp`](TraceView.cpp) | One process per node; the sequence diagram that `--view` draws |
| [`rsu-sgx-gateway/`](rsu-sgx-gateway) | SGX RSU: `App/` (untrusted side), `Enclave/` (trusted side), `vm-make.sh` |
| [`setup-vm.sh`](setup-vm.sh) | Builds the Ubuntu VM that has the SGX SDK + SGX-SSL |

## Quick start

```bash
# 1. Plain protocol: ESA + RSU + vehicle (needs Docker, no SGX)
make view

# 2. Same protocol, RSU running inside an SGX enclave (needs the VM, see below)
./setup-vm.sh                 # once
cd rsu-sgx-gateway && make view
```

---

## 1. Plain bootstrap (root `Makefile`)

Requirements: `g++` (C++17), OpenSSL 3 (static `libcrypto`), Docker.

Raw sockets need `CAP_NET_RAW`. To avoid `sudo`, the `run`/`pretty`/`view` targets put the static
`./bootstrap` binary in an empty image (`FROM scratch`) and run it with `--network none` (the container's
own loopback only).

| Command | What it does |
|---|---|
| `make` / `make run` | Builds and runs the 3 processes (ESA, RSU, vehicle) |
| `make pretty` | Same, with each component's output separated by a bar |
| `make view` | Same, drawn as a sequence diagram: messages, carried values, validations (ok / failed) and the keys each node kept, compared in a summary |
| `make build` | Only builds `./bootstrap` |
| `make clean` | Removes `build/`, `./bootstrap` and the Docker image |

### Running `./bootstrap` directly

Without Docker you need `CAP_NET_RAW` (`sudo setcap cap_net_raw=ep ./bootstrap` or `sudo`):

```text
./bootstrap [--pretty | --view [--color]] [--rsu-exec <program>]    # ESA, RSU and vehicle
./bootstrap esa|rsu|vehicle [--option value ...]                    # a single node
```

| Option | Meaning |
|---|---|
| `--pretty` | Output of each node separated by a bar |
| `--view` | Sequence diagram at the end (`--color` adds ANSI colors) |
| `--rsu-exec <program>` | Use another program as the RSU (e.g. the SGX gateway `app`) |
| `--iface <if>` | Network interface (default `lo`) — single node |
| `--name <n>` | Node name (`rsu[0]`, `node[0]`, …) — single node |
| `--seed <n>` | RNG seed — single node |
| `--clock-offset <s>` | Vehicle clock offset in seconds — vehicle |
| `--timeout <s>` | Vehicle timeout (default `5`) — vehicle |

See [`main.cpp`](main.cpp) for the full list.

---

## 2. SGX RSU gateway (`rsu-sgx-gateway/Makefile`)

The enclave uses the Intel SGX SDK and Intel SGX-SSL (OpenSSL inside the enclave).

- **If the host has `/opt/intel/sgxsdk`**, it builds locally.
- **If it doesn't**, the same `make` runs inside the VM for you through
  [`vm-make.sh`](rsu-sgx-gateway/vm-make.sh). The script starts the VM if needed, `rsync`s the repo to
  `~/v2x` in the VM, runs `make` there and copies the generated `Enclave_u.h` / `Enclave_t.h` back for your
  editor. You only need the VM from step 3 and an SSH key in it.

| Command (inside `rsu-sgx-gateway/`) | What it does |
|---|---|
| `make` / `make all` | Builds `./app` and the signed enclave `enclave.signed.so` |
| `make run` | Builds and runs `./app` (the gateway's self-test against the repo's vehicle and ESA) |
| `make network` | Runs `../bootstrap --pretty --rsu-exec ./app`: real ESA + vehicle, RSU = the enclave |
| `make view` | Same as `network`, drawn as the sequence diagram |
| `make clean` | Removes build outputs, the sealed state (`gateway.sealed`) and capability stamps |

`network` and `view` call `sudo setcap cap_net_raw=ep` on `app` and `../bootstrap`, so expect a `sudo` prompt
(inside the VM it is passwordless).

### Variables

| Variable | Default | Meaning |
|---|---|---|
| `SGX_MODE` | `SIM` | `SIM` (any CPU) or `HW` (real SGX hardware + driver/PSW) |
| `SGX_DEBUG` | `1` | `1` = `-O0 -g` debug enclave, `0` = optimized |
| `SGX_SDK` | `/opt/intel/sgxsdk` | SDK path; if missing, the build goes to the VM |
| `SGXSSL` | `/opt/intel/sgxssl` | SGX-SSL path |
| `VM_NAME` | `ubuntu24-tee-vm` | libvirt domain that `vm-make.sh` uses |
| `VM_HOST` | `ubuntu@<libvirt IP>` | Override the SSH target |
| `VM_DIR` | `v2x` | Where the repo is copied in the VM's home |

Example: `make view SGX_DEBUG=0`. If you change `SGX_MODE` or `SGX_DEBUG`, everything rebuilds.

> [!NOTE]
> The enclave signing key (`Enclave/Enclave_private.pem`, RSA-3072, e=3) is generated on the first build and
> is never committed.

---

## 3. Development VM (`setup-vm.sh`)

[`setup-vm.sh`](setup-vm.sh) creates an Ubuntu 24.04 VM (QEMU/KVM + libvirt) with the **Intel SGX SDK
(simulation mode)** and **Intel SGX-SSL** installed. No SGX hardware, driver or PSW needed.

Supported hosts: Arch / Manjaro / EndeavourOS, Ubuntu / Debian / Mint, Fedora / RHEL / CentOS.

### Usage

Run it as your **normal user**, not with `sudo` (it calls `sudo` itself):

```bash
./setup-vm.sh                 # create the VM (does nothing if it already exists)
RECREATE=1 ./setup-vm.sh      # delete the VM and rebuild it from scratch (erases its disk)
```

On success:

```
=== Success! Environment configured and VM 'ubuntu24-tee-vm' is running ===
```

### What the script does

1. Installs host dependencies (QEMU, libvirt, virt-install, dnsmasq, ISO tools, build tools).
2. Enables `libvirtd`, starts/autostarts the `default` NAT network, adds you to the `kvm` and `libvirt`
   groups, and whitelists `virbr0` if Docker is running (so the VM has internet).
3. Downloads the Ubuntu 24.04 cloud image to `~/libvirt/images/`.
4. Creates a 20 GB disk and a cloud-init seed that:
   - creates user `ubuntu` / password `ubuntu` (passwordless `sudo`),
   - injects your `~/.ssh/id_rsa.pub` or `~/.ssh/id_ed25519.pub` (needed by `vm-make.sh`),
   - installs the SGX SDK to `/opt/intel/sgxsdk` (`SGX_MODE=SIM`) and SGX-SSL to `/opt/intel/sgxssl`,
   - builds and runs `SampleEnclave` and the SGX-SSL tests as a smoke test.
5. Boots the VM headless and waits until provisioning finishes.

VM defaults (edit the top of the script to change): 4 GB RAM, 2 vCPUs, 20 GB disk, name `ubuntu24-tee-vm`.

> [!NOTE]
> After the first run, log out and back in so the `libvirt` group takes effect. Until then, prefix `virsh`
> with `sudo` or use `-c qemu:///system`.

### Useful commands

```bash
echo 'export LIBVIRT_DEFAULT_URI=qemu:///system' >> ~/.bashrc && source ~/.bashrc
```

| Task | Command |
|---|---|
| List VMs | `virsh list --all` |
| VM IP | `virsh domifaddr ubuntu24-tee-vm` |
| SSH | `ssh ubuntu@<IP>` (password `ubuntu`) |
| Serial console | `virsh console ubuntu24-tee-vm` (exit with `Ctrl + ]`) |
| Start / shutdown | `virsh start ubuntu24-tee-vm` / `virsh shutdown ubuntu24-tee-vm` |
| Force off | `virsh destroy ubuntu24-tee-vm` |
| Delete | `virsh undefine ubuntu24-tee-vm` |

One-line SSH:

```bash
ssh ubuntu@$(virsh domifaddr ubuntu24-tee-vm | awk '/ipv4/ {split($4,a,"/"); print a[1]}')
```

### Logs inside the VM

| Log | Contents |
|---|---|
| `/var/log/cloud-init-output.log` | Full provisioning output |
| `/var/log/sgx-sdk-install.log` | SGX SDK / SGX-SSL install and tests |
| `/var/log/sgx-sdk-installed` | Exists only if the install succeeded |

### Troubleshooting

| Symptom | Fix |
|---|---|
| `Unable to open /dev/net/tun ... No such device` | The kernel was upgraded but not booted yet (modules missing). Reboot, or `sudo modprobe tun` |
| `qemu-img: ... Permission denied` on the disk | Old images in `~/.libvirt/images` are owned by libvirt; use this branch's script (`~/libvirt/images`) or `sudo rm` the old file |
| `network 'default' is not active` | `sudo virsh net-start default && sudo virsh net-autostart default` |
| VM has no internet | Docker blocks forwarding: `sudo iptables -I DOCKER-USER -i virbr0 -j ACCEPT` and `sudo iptables -I DOCKER-USER -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` |
| `may not be accessible by the hypervisor` | `setfacl -m u:libvirt-qemu:x ~` |
| `Host key verification failed` (after `RECREATE=1`) | `ssh-keygen -R <IP>` |
| `vm-make.sh`: `no ssh to ubuntu24-tee-vm` | No SSH key in the VM: create one (`ssh-keygen -t ed25519`) and `RECREATE=1 ./setup-vm.sh`, or `ssh-copy-id ubuntu@<IP>` |
| `error: run this script without sudo` | Run `./setup-vm.sh` as your normal user |