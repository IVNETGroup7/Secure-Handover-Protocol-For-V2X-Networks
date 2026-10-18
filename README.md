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

### Shared project folder

This repository (the folder containing `setup-vm.sh`) is shared into the VM via **virtiofs**
and mounted at `/home/ubuntu/project`. Edit code on the host with your usual editor, then
build and test inside the VM:

```bash
ssh ubuntu@<IP>
cd ~/project
make SGX_MODE=SIM
```

Changes are live in both directions, and your code is safe even if the VM is recreated.

You'll be asked for your `sudo` password. On success you'll see:

```
SGX SDK (simulation mode) installed and SampleEnclave test passed.
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
| `~/project` is empty in the VM | VM was created before virtiofs support: run `./setup-vm.sh --recreate`. Otherwise try `sudo mount -a` |