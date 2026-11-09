# Secure-Handover-Protocol-For-V2X-Networks

Secure bootstrap, **Secrecy Forwarding** (RSU-to-RSU handover), and **Secure Marshaling** (OT → IT Cloud HTTPS) protocol between a **vehicle**, an **RSU** (Road-Side Unit), and an **ESA** (External Security Agent), implemented in C++17 + OpenSSL 3 and **Arm TrustZone (OP-TEE)**.

The primary physical hardware testbed platform is the **Raspberry Pi 3 Model B (Broadcom BCM2837, Quad-core Arm Cortex-A53 @ 1.2 GHz, 64-bit Armv8-A)** running **OP-TEE OS 4.x**. A complementary virtualized **QEMU ARMv8-A VM** is also provided for development without physical hardware.

Each node runs as an independent process communicating over raw Layer-2 Ethernet sockets (`AF_PACKET`, EtherType `0x88b5` for OT radio and `0x88b6` for IT backhaul) and TLS 1.3 HTTPS. There are two RSU implementations:

- the **plain RSU**, built directly into `./bootstrap`;
- the **OP-TEE RSU gateway** ([`rsu-optee-gateway/`](rsu-optee-gateway)): gateway identity keys ($K_g$), active session contexts, Poly1305 One-Time Password (OTP) validation, and Secure Marshaling execute inside a hardware-isolated **Arm TrustZone OP-TEE Trusted Application (TA)** (`9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta`).

Once activated, a vehicle transitions between RSUs via **Secrecy Forwarding** (RSU-to-RSU handover with no ESA involvement and no re-bootstrap, [`common/Handover.h`](common/Handover.h)). The protocol can also be co-simulated on a host PC using **Artery + OMNeT++ + SUMO** ([`artery-sim/`](artery-sim)), including a real-time **Hardware-in-the-Loop (HIL)** bridge to the physical Raspberry Pi 3.

---

## Repository layout

| Path | Contents |
|---|---|
| [`common/`](common) | Messages, payloads, crypto traits, simulated time, tracing, Secrecy Forwarding equations (`Handover.h`) |
| [`protocol/`](protocol) | Bootstrap & handover state engines (`BootstrapService`, `ExternalSecurityAgent`) and API (`Bootstrap.h`) |
| [`net/`](net) | Raw Ethernet sockets (`AF_PACKET`), Layer-2 framing (`Link.h`), and TLS 1.3 HTTPS client/server (`Https.h`) |
| [`main.cpp`](main.cpp) | Multi-process runner (ESA, RSU, vehicle, cloud) |
| [`rsu-optee-gateway/`](rsu-optee-gateway) | Arm TrustZone OP-TEE RSU gateway: `include/gateway_ta.h`, `ta/` (Secure World TA using GlobalPlatform TEE Internal Core API), `host/` (Normal World Client Application using `libteec`), cross-compilation toolchains (`build-rpi3.sh`) |
| [`artery-sim/`](artery-sim) | Host PC Artery/OMNeT++/SUMO simulation & Hardware-in-the-Loop bridge (`setup_artery.sh`) |
| [`setup-vm.sh`](setup-vm.sh) | *(Complementary)* Sets up an ARM64 QEMU ARMv8-A VM with `optee_os` and `optee_client` for virtual development |

---

## Quick start

```bash
# 1. Host quick test: OP-TEE gateway self-test in in-process HOST_SIM mode
make -C rsu-optee-gateway run

# 2. Main Physical Testbench: Cross-compile for Raspberry Pi 3 (Arm Cortex-A53)
make -C rsu-optee-gateway rpi3

# (Optional) Cross-compile and deploy over SSH to the Raspberry Pi 3 in one command:
make -C rsu-optee-gateway rpi3 PI_IP=xxx.xxx.xxx.xxx

# 3. Full network test on host PC
make pretty

# 4. Host PC Artery simulation (OMNeT++ 5.7, Artery, Simu5G, SUMO):
artery-sim/setup_artery.sh

# 5. Complementary: Virtual QEMU ARMv8-A OP-TEE VM:
./setup-vm.sh
```

---

## 1. Plain bootstrap (root `Makefile`)

Requirements: `g++` (C++17), OpenSSL 3, Docker (optional, for rootless `CAP_NET_RAW`).

| Command | What it does |
|---|---|
| `make` / `make run` | Builds and runs the 3 processes (ESA, RSU, vehicle) |
| `make pretty` | Same, with each component's output separated by an ANSI color bar |
| `make build` | Only builds `./bootstrap` |
| `make clean` | Removes `build/`, `./bootstrap` and temporary artifacts |

### Running `./bootstrap` directly

Without Docker you need `CAP_NET_RAW` (`sudo setcap cap_net_raw=ep ./bootstrap` or run with `sudo`):

```text
./bootstrap [--pretty] [--rsu-exec <program>]                       # ESA, RSU and vehicle
            [--cloud <certificate.pem>]                             # start the HTTPS cloud server
            [--smartdata <size,size,...> [--smartdata-count <n>] [--smartdata-interval <ms>]]
./bootstrap esa|rsu|vehicle|cloud [--option value ...]              # a single node
```

---

## 2. OP-TEE RSU Gateway (`rsu-optee-gateway/`)

The OP-TEE RSU gateway isolates untrusted network operations from sensitive cryptographic state:
- **Normal World (`host/`)**: Client Application (`./app`) that manages raw Ethernet sockets (`0x88b5` radio, `0x88b6` backhaul), PTP timestamps, and TLS transport to the Cloud, invoking the Trusted Application via `TeeSession` (`TEEC_InitializeContext`, `TEEC_OpenSession`, `TEEC_InvokeCommand`).
- **Secure World (`ta/`)**: Trusted Application (`9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta`) written against the **GlobalPlatform TEE Internal Core API 1.2** (`<tee_internal_api.h>`):
  - **P-256 ECDH & ECDSA**: `TEE_TYPE_ECDH_KEYPAIR`, `TEE_ALG_ECDH_P256`, `TEE_ALG_ECDSA_P256` (`TEE_GenerateKey`, `TEE_AsymmetricDeriveKey`, `TEE_AsymmetricVerifyDigest`).
  - **Authenticated Encryption**: `TEE_ALG_AES_GCM` (`TEE_AEInit`, `TEE_AEEncryptFinal`, `TEE_AEDecryptFinal`) for 128-bit (`K_g`, `KT_i`) and 256-bit (`K_dg`, `K_eg`) keys.
  - **One-Time Passwords (`OTP_dt`)**: RFC 8439 Poly1305 (`poly1305Aes`) for sub-millisecond per-frame authenticators.
  - **Secure Storage**: `TEE_CreatePersistentObject` / `TEE_OpenPersistentObject` (`TEE_STORAGE_PRIVATE`) to seal active vehicle sessions and $K_g$ across power cycles.

### Build modes (`rsu-optee-gateway/Makefile`)

- **`TEE_MODE=OPTEE`**: Links `./app` against `-lteec` (`<tee_client_api.h>`) to communicate with `/dev/tee0` and `tee-supplicant` on the physical Raspberry Pi 3 or in the QEMU VM, building `ta/9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta`.
- **`TEE_MODE=HOST_SIM`**: Links `./app` with the TA session state machine in-process for native debugging on x86_64 host PCs without `/dev/tee0`.

| Command (inside `rsu-optee-gateway/`) | What it does |
|---|---|
| `make` / `make all` | Builds `./app` (and `ta/*.ta` when `TA_DEV_KIT_DIR` is set) |
| `make run` | Builds and runs `./app` in self-test mode (scenarios 1–6: bootstrap, tamper checks, Secure Marshaling 4a–4g, Secrecy Forwarding 4h–4m) |
| `make network` | Runs `../bootstrap --pretty --rsu-exec ./app`: real ESA + vehicle + Cloud, with RSU = OP-TEE gateway |
| `make bench` | Runs the Secure Marshaling benchmark (32 B to 64 KB SmartData payloads, 100 packets each) |
| `make rpi3` | Cross-compiles `./app`, `.ta`, and `bootstrap` for **Raspberry Pi 3** (`-mcpu=cortex-a53`) |
| `make vm` | *(Complementary)* Runs build/test inside the ARM64 QEMU OP-TEE VM via `./vm-make.sh` |
| `make clean` | Removes build outputs, sealed state files (`gateway.sealed*`), and capability stamps |

---

### Main Physical Testbench: Raspberry Pi 3 (Arm Cortex-A53)

The primary physical evaluation executes on a physical **Raspberry Pi 3 Model B** running an OP-TEE OS 4.x + Linux Buildroot environment (`/dev/tee0` and `tee-supplicant`).

#### 1. Cross-compilation and Deployment

The project provides an automated toolchain script ([`rsu-optee-gateway/build-rpi3.sh`](rsu-optee-gateway/build-rpi3.sh)) that compiles the TA, patches the ELF OS/ABI header (`EI_OSABI` to `0x00`), signs the TA with the OP-TEE key, cross-compiles `./app` and `./bootstrap`, and deploys them over SSH:

```bash
# Build TA, host app, and bootstrap:
make -C rsu-optee-gateway rpi3

# Or build and automatically deploy over SSH in one step:
make -C rsu-optee-gateway rpi3 PI_IP=XXX.XXX.XXX.XXX
```

#### 2. Running on the Raspberry Pi 3

On the board via SSH or serial console:

```bash
# 1. Ensure tee-supplicant is running in the background:
pgrep tee-supplicant || tee-supplicant &

# 2. Run the complete self-test suite on the real TrustZone core:
./app
```

Expected output:
```text
[gateway] ta    init_gateway: CY_e prime256v1 (91 bytes), K_g generated inside (16 bytes)
[gateway] ta    ✔ 1. normal bootstrap: activation token accepted, session #1 active
[gateway] ta    ✔ 2. tampered OTP rejected
[gateway] ta    ✔ 3. late auth rejected
[gateway] ta    ✔ 4a-4g. Secure Marshaling (32 B .. 64 KB SmartData)
[gateway] ta    ✔ 4h-4m. Secrecy Forwarding: Forwarding_Notice -> Handover_Command -> Forwarding_Request -> Forwarding_Granted
[gateway] ta    ✔ 5. rogue gateway rejected
[gateway] ta    ✔ 6. early arrival rejected
[gateway] gateway OK
```

#### 3. Running the Full Network Testbench with Host PC

To execute the full distributed protocol across the physical network (Raspberry Pi 3 as RSU, Host PC running vehicle, ESA, and Cloud):

1. **On the Raspberry Pi 3**, launch the gateway daemon on Ethernet interface `eth0`:
   ```bash
   ./app rsu --iface eth0 --name rsu[0]
   ```
2. **On the Host PC**, run the network nodes pointing to your local Ethernet interface (e.g. `enp3s0`):
   ```bash
   # Run the ESA, Cloud HTTPS server, and vehicle against the physical RSU:
   ./bootstrap --pretty --iface <your-ethernet-network-interface> \
       --cloud cloud.crt \
       --rsu-exec ./rsu-ssh.sh \
       --smartdata 32,1024,65535
   ```

---

### Complementary: Virtual QEMU ARMv8-A VM (`setup-vm.sh`)

A complementary virtualized OP-TEE environment is available:

```bash
# Set up the QEMU ARMv8-A VM with OP-TEE OS and libteec:
./setup-vm.sh

# Build and execute within the VM:
make -C rsu-optee-gateway vm
```

---

## 3. Secrecy Forwarding (RSU-to-RSU Handover)

A vehicle activated with source RSU $G_{i+1}$ transitions to target RSU $G_{i+2}$ without contacting the ESA or performing asymmetric key handshakes ([`common/Handover.h`](common/Handover.h)):

| # | Message | From → To | Transport | What it carries / does |
|---|---|---|---|---|
| 1 | `Forwarding_Notice` (16) | $G_{i+1} \to G_{i+2}$ | HTTPS Backhaul (`0x88b6`) | $Y_V$, $\text{Auth}_d$, $\tau_{i+2} = \text{Poly1305}(K_{dg}, t_i, m)$: `TA_GATEWAY_CMD_TRIGGER_HANDOVER` |
| 2 | `Handover_Command` (17) | $G_{i+2} \to G_{i+1} \to \text{Vehicle}$ | Backhaul / Radio | $Y_{G_{i+2}}$; $G_{i+2}$ pre-computes $K_{dh}, KT_i, \text{auth}_{i+2}$: `TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE` |
| 3 | `Forwarding_Request` (18) | $\text{Vehicle} \to G_{i+2}$ | Radio (`0x88b5`) | $\text{auth}_{i+2} = \text{SHA256}(\tau)$, $\text{OTP} = \text{Poly1305}(KT_i^{32}, \text{auth} \oplus t_c, m)$ |
| 4 | `Forwarding_Granted` (19) | $G_{i+2} \to \text{Vehicle}$ | Radio (`0x88b5`) | $\text{AES-128-GCM}(KT_i, \{ \text{auth}', K_{G_{i+2}}, \text{OTP} \})$: vehicle switches to target key $K_{G_{i+2}}$ |
| – | `Secure_Data` (20) | $\text{Vehicle} \to \text{RSU}$ | Radio (`0x88b5`) | SmartData OT packet, marshaled in RSU TA (`TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT`) $\to$ Cloud HTTPS |

---

## 4. Artery Simulation & Hardware-in-the-Loop (`artery-sim/`)

[`artery-sim/`](artery-sim) runs on the host PC, integrating **OMNeT++ 5.7**, **Artery / Vanetza** (ITS-G5 802.11p), **Simu5G** (5G NR) and **SUMO** road mobility.

### Simulation Configurations (`scenario/omnetpp.ini`)

1. **`D250m_80211p`**: IEEE 802.11p / ITS-G5 at 5.9 GHz, 6 Mbps, 200 mW (~250 m coverage per RSU).
2. **`D500m_5G`**: 5G New Radio (NR) via **Simu5G**: 3.5 GHz (FR1 n78), 20 MHz (50 Resource Blocks), numerology 1 (30 kHz subcarrier spacing), 3GPP TR 38.901 Urban Microcell, gNodeB X2 handover between gNodeB[0] (x=250m) and gNodeB[1] (x=750m).
3. **`HIL_RPi3_TargetHandover` (Hardware-in-the-Loop)**: Simulated vehicle in SUMO bootstraps with simulated `rsu[0]`, then hands over at $x = 500\,\text{m}$ across the Ethernet wire (`enp3s0`) to the **physical Raspberry Pi 3** acting as `rsu[1]`.

### Running Simulations

```bash
# Setup dependencies and build simulation:
artery-sim/setup_artery.sh

# Run IEEE 802.11p configuration (250 m per RSU):
cmake -DRUN_FLAGS="-u Cmdenv -c D250m_80211p" artery-sim/deps/artery/build
cmake --build artery-sim/deps/artery/build --target run_tee_v2x_handover

# Run 5G New Radio configuration (500 m per RSU):
cmake -DRUN_FLAGS="-u Cmdenv -c D500m_5G" artery-sim/deps/artery/build
cmake --build artery-sim/deps/artery/build --target run_tee_v2x_handover

# Run Hardware-in-the-Loop with physical Raspberry Pi 3:
# (1. Ensure Raspberry Pi 3 is running: ./app rsu --iface eth0 --name rsu[1])
# (2. Ensure raw socket capability on PC: sudo setcap cap_net_raw+ep artery-sim/deps/omnetpp-5.7.1/bin/opp_run_release)
cmake -DRUN_FLAGS="-u Cmdenv -c HIL_RPi3_TargetHandover" artery-sim/deps/artery/build
cmake --build artery-sim/deps/artery/build --target run_tee_v2x_handover
```
