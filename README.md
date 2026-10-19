# Secure-Handover-Protocol-For-V2X-Networks

Secure bootstrap / handover protocol between a **vehicle**, an **RSU** (Road-Side Unit) and an
**ESA** (External Security Agent), written in C++17 + OpenSSL 3. Each node runs as its own process and
they talk over raw Ethernet sockets (no Artery/OMNeT++). There are two RSU options:

- the **plain RSU**, part of `./bootstrap` itself;
- the **SGX RSU gateway** ([`rsu-sgx-gateway/`](rsu-sgx-gateway)): the RSU's secrets and crypto live in an
  Intel SGX enclave (simulation mode, so any CPU works).

Once activated, a vehicle moves to the next RSU by **Secrecy Forwarding** (RSU-to-RSU handover, no ESA and no
new bootstrap, [`common/Handover.h`](common/Handover.h)), which the SGX gateway implements in its enclave. The
same code also runs in an **Artery + OMNeT++ + SUMO** simulation ([`artery-sim/`](artery-sim)).

## Repository layout

| Path | Contents |
|---|---|
| [`common/`](common) | Messages, payloads, crypto, vehicle traits, simulated time, tracing, the Secrecy Forwarding equations (`Handover.h`) |
| [`protocol/`](protocol) | Bootstrap protocol (`BootstrapService`, `ExternalSecurityAgent`) and its API (`Bootstrap.h`) |
| [`net/`](net) | Raw Ethernet sockets (`AF_PACKET`) |
| [`main.cpp`](main.cpp) | One process per node |
| [`rsu-sgx-gateway/`](rsu-sgx-gateway) | SGX RSU: `App/` (untrusted side), `Enclave/` (trusted side), `vm-make.sh` |
| [`artery-sim/`](artery-sim) | Artery scenario: 2 SGX RSUs, 1 vehicle, handover on a 1 km highway (`setup_artery.sh`) |
| [`setup-vm.sh`](setup-vm.sh) | Builds the Ubuntu VM that has the SGX SDK + SGX-SSL |

## Quick start

```bash
# 1. Plain protocol: ESA + RSU + vehicle (needs Docker, no SGX)
make pretty

# 2. Same protocol, RSU running inside an SGX enclave (needs the VM, see below)
./setup-vm.sh                 # once
cd rsu-sgx-gateway && make network

# 3. The enclave's self-test, including the handover between two enclaves (rsu[0] -> rsu[1])
make -C rsu-sgx-gateway run

# 4. The Artery simulation (installs OMNeT++, Artery, SUMO; the SGX SDK with --install-sgx)
artery-sim/setup_artery.sh --install-sgx
```

---

## 1. Plain bootstrap (root `Makefile`)

Requirements: `g++` (C++17), OpenSSL 3 (static `libcrypto`), Docker.

Raw sockets need `CAP_NET_RAW`. To avoid `sudo`, the `run`/`pretty` targets put the static
`./bootstrap` binary in an empty image (`FROM scratch`) and run it with `--network none` (the container's
own loopback only).

| Command | What it does |
|---|---|
| `make` / `make run` | Builds and runs the 3 processes (ESA, RSU, vehicle) |
| `make pretty` | Same, with each component's output separated by a bar |
| `make build` | Only builds `./bootstrap` |
| `make clean` | Removes `build/`, `./bootstrap` and the Docker image |

### Running `./bootstrap` directly

Without Docker you need `CAP_NET_RAW` (`sudo setcap cap_net_raw=ep ./bootstrap` or `sudo`):

```text
./bootstrap [--pretty] [--rsu-exec <program>]                       # ESA, RSU and vehicle
./bootstrap esa|rsu|vehicle [--option value ...]                    # a single node
```

| Option | Meaning |
|---|---|
| `--pretty` | Output of each node separated by a bar |
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
| `make run` | Builds and runs `./app` (the gateway's self-test against the repo's vehicle and ESA, and the handover to a second enclave) |
| `make network` | Runs `../bootstrap --pretty --rsu-exec ./app`: real ESA + vehicle, RSU = the enclave |
| `make clean` | Removes build outputs, the sealed state (`gateway.sealed*`) and capability stamps |

`network` and `bench` call `sudo setcap cap_net_raw=ep` on `app` and `../bootstrap`, so expect a `sudo` prompt
(inside the VM it is passwordless).

### Secrecy Forwarding (handover)

A vehicle activated with RSU G<sub>i+1</sub> is handed over to the next RSU G<sub>i+2</sub>
([`common/Handover.h`](common/Handover.h) has the equations, used by both the vehicle and the enclave):

| # | Message | From → to | What it carries / does |
|---|---|---|---|
| 1 | `Forwarding_Notice` (16) | G<sub>i+1</sub> → G<sub>i+2</sub> (HTTPS) | Y<sub>V</sub>, Auth<sub>d</sub>, τ<sub>i+2</sub> = Poly1305(K<sub>dg</sub>, t<sub>i</sub>, m): `ecall_trigger_handover` |
| 2 | `Handover_Command` (17) | G<sub>i+2</sub> → G<sub>i+1</sub> → vehicle | Y<sub>G<sub>i+2</sub></sub>; G<sub>i+2</sub> pre-computed K<sub>dh</sub>, KT<sub>i</sub>, auth<sub>i+2</sub>: `ecall_receive_forwarding_notice` |
| 3 | `Forwarding_Request` (18) | vehicle → G<sub>i+2</sub> | auth<sub>i+2</sub> = SHA256(τ), OTP = Poly1305(KT<sub>i</sub>, auth ⊕ t<sub>c</sub>, m) |
| 4 | `Forwarding_Granted` (19) | G<sub>i+2</sub> → vehicle | AES-128-GCM(KT<sub>i</sub>, { auth′, K<sub>G<sub>i+2</sub></sub>, OTP }): the vehicle now uses G<sub>i+2</sub>'s K<sub>g</sub> |
| – | `Secure_Data` (20) | vehicle → its RSU | the SmartData OT packet, marshaled in that RSU's enclave |

t<sub>i</sub> is the slot of the OTP that activated the vehicle, kept by both sides. The self-test (`make run`,
scenario 4) creates a second enclave in the same process for `rsu[1]` (own memory, K<sub>g</sub> and sealed state
`gateway.sealed.rsu1`), hands `node[0]` over to it and checks that its SmartData is then marshaled by `rsu[1]`.

### Artery simulation (`artery-sim/`)

[`artery-sim/setup_artery.sh`](artery-sim/setup_artery.sh) installs the dependencies (Ubuntu 22.04/24.04 or Arch),
builds OMNeT++ 5.7.1 and Artery under `artery-sim/deps/`, registers the scenario in Artery's CMake build and builds
it. The RSUs need the Intel SGX SDK and SGX-SSL **on the same machine** as Artery (`--install-sgx` installs them,
simulation mode); with an Artery you already have (e.g. an `opp_env` workspace) use `--artery-dir <dir>`.

| Path | Contents |
|---|---|
| `src/TeeRsuService` | RSU: one SGX enclave each (`sgx_create_enclave`), `PacketManager` over Vanetza BTP port 2025 |
| `src/VehicleTeeService` | Vehicle: bootstrap, `Secure_Data` at 10 Hz, `Forwarding_Request` at x = 500 m |
| `src/BackhaulBroker` | HTTPS backhaul (RSU ↔ ESA, RSU ↔ RSU), the ESA and the cloud |
| `scenario/` | `HighwayHandover.ned`, `omnetpp.ini` (`D250m_80211p`, `D500m_5G`), SUMO highway, `services*.xml` |

```bash
cmake -DRUN_FLAGS="-u Cmdenv -c D250m_80211p" artery-sim/deps/artery/build
cmake --build artery-sim/deps/artery/build --target run_tee_v2x_handover
```

Results go to `artery-sim/scenario/results/`; the scenario's own statistics: `marshaledPackets`,
`marshalLatencyUs`, `handoversGranted` (RSUs), `bootstrapDelay`, `handoverE2EDelayMs`, `secureDataSent` (vehicle),
`cloudStored` (backhaul).

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