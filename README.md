# Secure-Handover-Protocol-For-V2X-Networks

Secure bootstrap, **Secrecy Forwarding** (RSU-to-RSU handover), and **Secure Marshaling** (OT → IT Cloud HTTPS) protocol between a **vehicle**, an **RSU** (Road-Side Unit), and an **ESA** (External Security Agent), written in C++17 + OpenSSL 3 and **Arm TrustZone (OP-TEE)**.

Each node runs as its own process and communicates over raw Ethernet sockets (`AF_PACKET`, without requiring Artery/OMNeT++). There are two RSU implementations:

- the **plain RSU**, part of `./bootstrap` itself;
- the **OP-TEE RSU gateway** ([`rsu-optee-gateway/`](rsu-optee-gateway)): the RSU's secrets, session keys, OTP validation, and Secure Marshaling live inside an **Arm TrustZone OP-TEE Trusted Application (TA)** (`9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta`), designed for simulation on **QEMU ARMv8-A** and deployment on a **Raspberry Pi 5** (Arm Cortex-A76).

Once activated, a vehicle moves to the next RSU via **Secrecy Forwarding** (RSU-to-RSU handover with no ESA involvement and no re-bootstrap, [`common/Handover.h`](common/Handover.h)), which the OP-TEE gateway executes inside its Trusted Application. The same protocol also runs in an **Artery + OMNeT++ + SUMO** simulation on a host PC ([`artery-sim/`](artery-sim)).

## Repository layout

| Path | Contents |
|---|---|
| [`common/`](common) | Messages, payloads, crypto, vehicle traits, simulated time, tracing, Secrecy Forwarding equations (`Handover.h`) |
| [`protocol/`](protocol) | Bootstrap & handover protocol (`BootstrapService`, `ExternalSecurityAgent`) and its API (`Bootstrap.h`) |
| [`net/`](net) | Raw Ethernet sockets (`AF_PACKET`) and TLS 1.3 HTTPS client/server (`Https.h`) |
| [`main.cpp`](main.cpp) | Multi-process runner (ESA, RSU, vehicle, cloud) |
| [`rsu-optee-gateway/`](rsu-optee-gateway) | Arm TrustZone OP-TEE RSU gateway: `include/gateway_ta.h`, `ta/` (Secure World TA using GlobalPlatform TEE Internal Core API), `host/` (Normal World Client Application using `libteec` + host simulation backend) |
| [`artery-sim/`](artery-sim) | Host-PC Artery/OMNeT++/SUMO simulation: 2 OP-TEE RSUs, 1 vehicle, handover on a 1 km highway (`setup_artery.sh`) |
| [`setup-vm.sh`](setup-vm.sh) | Sets up the ARM64 cross-compilation toolchain, QEMU ARMv8-A, and the VM with `optee_os` TA DevKit + `optee_client` (`libteec`) |

## Quick start

```bash
# 1. Plain protocol: ESA + RSU + vehicle (needs Docker)
make pretty

# 2. The OP-TEE gateway's self-test (bootstrap, tamper checks, Secure Marshaling 4a-4g, Secrecy Forwarding 4h-4m)
make -C rsu-optee-gateway run

# 3. Full network test with OP-TEE RSU gateway + ESA + vehicle + Cloud HTTPS
make -C rsu-optee-gateway network

# 4. Cross-compile OP-TEE RSU gateway & TA for Raspberry Pi 5 (Arm Cortex-A76)
make -C rsu-optee-gateway rpi5

# 5. The Artery simulation on the host PC (installs OMNeT++, Artery, Simu5G, SUMO)
artery-sim/setup_artery.sh
```

---

## 1. Plain bootstrap (root `Makefile`)

Requirements: `g++` (C++17), OpenSSL 3, Docker (optional, for rootless `CAP_NET_RAW`).

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
            [--cloud <certificate.pem>]                             # also start the HTTPS cloud server
            [--smartdata <size,size,...> [--smartdata-count <n>] [--smartdata-interval <ms>]]
./bootstrap esa|rsu|vehicle|cloud [--option value ...]              # a single node
```

---

## 2. OP-TEE RSU gateway (`rsu-optee-gateway/`)

The OP-TEE RSU gateway separates the RSU into:
- **Normal World (`host/`)**: Client Application (`./app`) that manages raw Ethernet sockets (`0x88b5` radio, `0x88b6` backhaul), PTP timestamps, and TLS transport to the Cloud, invoking the Trusted Application via `TeeSession` (`TEEC_InitializeContext`, `TEEC_OpenSession`, `TEEC_InvokeCommand`).
- **Secure World (`ta/`)**: Trusted Application (`9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta`) written against the **GlobalPlatform TEE Internal Core API** (`<tee_internal_api.h>`):
  - **P-256 ECDH & ECDSA**: `TEE_TYPE_ECDH_KEYPAIR`, `TEE_ALG_ECDH_P256`, `TEE_ALG_ECDSA_P256` (`TEE_GenerateKey`, `TEE_AsymmetricDeriveKey`, `TEE_AsymmetricVerify`).
  - **Authenticated Encryption**: `TEE_ALG_AES_GCM` (`TEE_AEInit`, `TEE_AEEncryptFinal`, `TEE_AEDecryptFinal`) for 128-bit (`K_g`, `KT_i`) and 256-bit (`K_dg`, `K_eg`) keys.
  - **One-Time Passwords (`OTP_dt`)**: `TEE_ALG_AES_ECB_NOPAD` + RFC 8439 Poly1305 (`poly1305Aes`).
  - **Secure Storage**: `TEE_CreatePersistentObject` / `TEE_OpenPersistentObject` (`TEE_STORAGE_PRIVATE`) to seal active vehicle sessions and `K_g` across restarts.

### Build modes (`rsu-optee-gateway/Makefile`)

- **`TEE_MODE=OPTEE` (auto-selected when `libteec` / `TA_DEV_KIT_DIR` is present)**: Links `./app` against `-lteec` (`<tee_client_api.h>`) to communicate with `/dev/tee0` and `tee-supplicant` in QEMU ARMv8-A or on the Raspberry Pi 5, and builds `ta/9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta` using `$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk`.
- **`TEE_MODE=HOST_SIM` (auto-selected on a standard x86_64 host without `/dev/tee0`)**: Links `./app` with the TA session state machine in-process so `make run`, `make network`, and `artery-sim/` work natively on any Linux PC.

| Command (inside `rsu-optee-gateway/`) | What it does |
|---|---|
| `make` / `make all` | Builds `./app` (and `ta/*.ta` when `TA_DEV_KIT_DIR` is set) |
| `make run` | Builds and runs `./app` (self-test: scenarios 1–6 including Secure Marshaling 4a–4g and Secrecy Forwarding 4h–4m between two RSU TA sessions) |
| `make network` | Runs `../bootstrap --pretty --rsu-exec ./app`: real ESA + vehicle + Cloud, with RSU = the OP-TEE gateway |
| `make bench` | Runs the Secure Marshaling benchmark (32 B to 64 KB SmartData payloads, 100 packets each) |
| `make rpi3` | Cross-compiles `./app`, `.ta`, and `./bootstrap` for **Raspberry Pi 3** (`-mcpu=cortex-a53`) |
| `make rpi5` | Cross-compiles `./app` (and `.ta`) for **Raspberry Pi 5** (`CROSS_COMPILE=aarch64-linux-gnu-`, `-mcpu=cortex-a76`) |
| `make vm` | Runs `make` inside the QEMU OP-TEE VM via `./vm-make.sh` |
| `make clean` | Removes build outputs, sealed state files (`gateway.sealed*`), and capability stamps |

### Cross-compiling and deploying to Raspberry Pi 3 (Arm Cortex-A53)

To cross-compile using the `optee-rpi3` Buildroot environment and deploy directly to the board:

```bash
# Build TA, host app, and bootstrap (auto-patches ELF OS/ABI and signs TA):
make -C rsu-optee-gateway rpi3

# Or build and automatically deploy over SSH in one command:
make -C rsu-optee-gateway rpi3 PI_IP=xxx.xxx.xxx.xxx
```

On the Raspberry Pi 3:
1. Ensure `tee-supplicant` is running (`pgrep tee-supplicant || tee-supplicant &`).
2. Run the self-tests or network node:
   ```bash
   ./app
   ```

### Cross-compiling and deploying to Raspberry Pi 5 (Arm Cortex-A76)

1. Install the ARM64 cross-compiler and OP-TEE SDK (`./setup-vm.sh` installs `aarch64-linux-gnu-g++` on the host and builds `optee_os` + `optee_client` in the VM).
2. Cross-compile targeting Cortex-A76:
   ```bash
   make -C rsu-optee-gateway rpi5 \
       TEEC_EXPORT=/opt/optee/optee_client/out/export/usr \
       TA_DEV_KIT_DIR=/opt/optee/optee_os/out/arm-plat-vexpress/export-ta_arm64
   ```
3. On the Raspberry Pi 5 running OP-TEE Linux:
   - Copy `rsu-optee-gateway/ta/9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta` to `/lib/optee_armtz/`.
   - Copy `rsu-optee-gateway/app` and `./bootstrap` to the board, ensure `tee-supplicant` is running, and execute `./app` (self-test) or `./app rsu --iface eth0 --name rsu[0]`.

---

## 3. Secrecy Forwarding (RSU-to-RSU Handover)

A vehicle activated with source RSU G<sub>i+1</sub> is handed over to target RSU G<sub>i+2</sub> ([`common/Handover.h`](common/Handover.h)):

| # | Message | From → to | What it carries / does |
|---|---|---|---|
| 1 | `Forwarding_Notice` (16) | G<sub>i+1</sub> → G<sub>i+2</sub> (HTTPS) | Y<sub>V</sub>, Auth<sub>d</sub>, τ<sub>i+2</sub> = Poly1305(K<sub>dg</sub>, t<sub>i</sub>, m): `TA_GATEWAY_CMD_TRIGGER_HANDOVER` |
| 2 | `Handover_Command` (17) | G<sub>i+2</sub> → G<sub>i+1</sub> → vehicle | Y<sub>G<sub>i+2</sub></sub>; G<sub>i+2</sub> pre-computes K<sub>dh</sub>, KT<sub>i</sub>, auth<sub>i+2</sub>: `TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE` |
| 3 | `Forwarding_Request` (18) | vehicle → G<sub>i+2</sub> | auth<sub>i+2</sub> = SHA256(τ), OTP = Poly1305(KT<sub>i</sub><sup>32</sup>, auth ⊕ t<sub>c</sub>, m) |
| 4 | `Forwarding_Granted` (19) | G<sub>i+2</sub> → vehicle | AES-128-GCM(KT<sub>i</sub>, { auth′, K<sub>G<sub>i+2</sub></sub>, OTP }): the vehicle now uses G<sub>i+2</sub>'s K<sub>g</sub> |
| – | `Secure_Data` (20) | vehicle → its RSU | SmartData OT packet, marshaled in that RSU's OP-TEE TA (`TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT`) |

---

## 4. Artery simulation on Host PC (`artery-sim/`)

[`artery-sim/`](artery-sim) runs on the host PC. [`artery-sim/setup_artery.sh`](artery-sim/setup_artery.sh) installs dependencies (Ubuntu 22.04/24.04 or Arch), builds OMNeT++, Artery, and Simu5G under `artery-sim/deps/`, registers the `tee_v2x_handover` scenario in Artery's CMake build, and compiles it against `rsu-optee-gateway/`.

| Path | Contents |
|---|---|
| `src/TeeRsuService` | RSU: one isolated `TeeSession` each, `PacketManager` over ITS-G5 (802.11p) or Simu5G (5G NR) |
| `src/VehicleTeeService` | Vehicle: bootstrap, `Secure_Data` at 10 Hz, `Forwarding_Request` at x = 500 m |
| `src/BackhaulBroker` | HTTPS backhaul (RSU ↔ ESA, RSU ↔ RSU), ESA, cloud, and 5G NR radio broker |
| `scenario/` | `HighwayHandover.ned`, `HighwayHandover5G.ned`, `omnetpp.ini` (`D250m_80211p`, `D500m_5G`), SUMO highway, `services*.xml` |

Configurations in `scenario/omnetpp.ini`:
- `D250m_80211p`: IEEE 802.11p / ITS-G5 at 5.9 GHz, 6 Mbps, 200 mW (~250 m coverage per RSU).
- `D500m_5G`: Real 5G New Radio (NR) via **Simu5G**: 3.5 GHz (FR1 n78), 20 MHz (50 Resource Blocks), numerology 1 (30 kHz subcarrier spacing), 3GPP TR 38.901 Urban Microcell pathloss, gNodeB X2 handover between gNodeB[0] (x=250m) and gNodeB[1] (x=750m), 500 m cell radius per RSU.

```bash
# Setup OMNeT++, Artery, Simu5G, and SUMO
artery-sim/setup_artery.sh

# Run IEEE 802.11p configuration (250 m per RSU)
cmake -DRUN_FLAGS="-u Cmdenv -c D250m_80211p" artery-sim/deps/artery/build
cmake --build artery-sim/deps/artery/build --target run_tee_v2x_handover

# Run Simu5G 5G New Radio configuration (500 m per RSU)
cmake -DRUN_FLAGS="-u Cmdenv -c D500m_5G" artery-sim/deps/artery/build
cmake --build artery-sim/deps/artery/build --target run_tee_v2x_handover
```
