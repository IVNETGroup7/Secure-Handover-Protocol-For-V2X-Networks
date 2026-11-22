# Secure-Handover-Protocol-For-V2X-Networks

Secure bootstrap (with IT **Human Operator** authorization, **Root CA** mutual authentication, and Theorem 2 fresh `OTP_dt`), **Secrecy Forwarding** (RSU-to-RSU handover), and **Secure Marshaling** (OT → IT Cloud encapsulation) between a **vehicle**, an **RSU** (Road-Side Unit), a **Human Operator**, and an **ESA** (External Security Agent), implemented in C++17 + OpenSSL 3 and **Arm TrustZone (OP-TEE)**.

The physical testbed uses a **Raspberry Pi 3 Model B** running **OP-TEE OS** for **all 4 Manhattan Grid RSUs (`rsu[0]`..`rsu[3]`)** in 4 isolated Trusted Application sessions (`9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta`, `rsu0.sealed`..`rsu3.sealed`) over raw Layer-2 Ethernet (`AF_PACKET`, EtherType `0x88b5` for OT radio and `0x88b6` for IT backhaul), while **Artery + OMNeT++ + SUMO** on the host PC simulates the Manhattan Grid vehicle, CTRA trajectory predictor, Root CA, Human Operator, ESA, Cloud sink, and IEEE 802.11p channel.

For development without physical RPi3 hardware, a complementary **libvirt/KVM VM (`optee-arm64-vm`)** workflow (`setup-vm.sh`, `make vm`, `make vm-hil`) provides the same 4-RSU `./app` environment over the host `virbr0` bridge.

Once bootstrapped with `rsu[0]`, the vehicle's **CTRA (Constant Turn Rate and Acceleration)** trajectory predictor (`CtraPredictor`, in Normal World on the vehicle) selects the single most likely next RSU and triggers selective **Secrecy Forwarding** token pre-fetching (`Handover_Predict` → `Forwarding_Notice`) exclusively with that target RSU, completing handovers (`rsu[0] → rsu[1] → rsu[2] → rsu[3]`) without contacting the ESA or performing a new bootstrap ([`common/Handover.h`](common/Handover.h)). For a deep reference covering every test, C++ class, cryptographic equation, wire frame, and expected output, see [TESTS.md](TESTS.md).

---

## Repository layout

| Path | Contents |
|---|---|
| [`Makefile`](Makefile) | Top-level entrypoints (`build`, `run`, `vm`, `vm-hil`, `rpi3`, `sim`, `hil-quad`, `clean`, `help`) |
| [`common/`](common) | Protocol messages, binary codecs, crypto primitives, `SimTime`, tracing, vehicle traits, `SmartData`, `Handover` equations |
| [`protocol/`](protocol) | Vehicle protocol stack (`VehicleSession`, `BootstrapClient`, `HandoverClient`, `SecureDataClient`, `VehicleAgent`), IT `HumanOperator`, and `ExternalSecurityAgent` |
| [`net/`](net) | Raw Layer-2 Ethernet sockets (`RawSocket`) and framing/demux/fragmentation (`Link`) |
| [`rsu-optee-gateway/`](rsu-optee-gateway) | OP-TEE RSU gateway: `include/gateway_ta.h`, `ta/` (Secure World TA), `host/` (Normal World `./app` self-test & `rsu` daemon, `Benchmark`, `PacketManager`, `TeeSession`), `build-rpi3.sh`, `vm-make.sh` |
| [`artery-sim/`](artery-sim) | Host-PC Artery/OMNeT++/SUMO 4-RSU Manhattan Grid simulation (`CtraPredictor`, `setup_artery.sh`, `run-hil-quad.sh`, `scenario/`, `src/`) |
| [`setup-vm.sh`](setup-vm.sh) | Sets up the complementary Ubuntu 24.04 libvirt/KVM VM (`optee-arm64-vm`) with OP-TEE DevKit & `libteec` |
| [`rsu-quad-ssh.sh`](rsu-quad-ssh.sh) | Launches 4 concurrent `rsu[0]`..`rsu[3]` OP-TEE gateway sessions on the Raspberry Pi 3 over SSH |
| [`TESTS.md`](TESTS.md) | Comprehensive reference of every test, simulation, HIL setup, class, wire format, and expected output |

---

## Quick start

```bash
# 1. Host self-test: 7-scenario OP-TEE gateway self-test (HOST_SIM mode)
make run

# 2. Pure Artery IEEE 802.11p 4-RSU Manhattan Grid simulation (bootstrap + CTRA pre-fetch + Secrecy Forwarding)
artery-sim/setup_artery.sh     # one-time dependency & CMake build
make sim

# 3. Physical 4-RSU Raspberry Pi 3 HIL (all 4 RSUs in RPi3 TrustZone; rest simulated on PC)
make rpi3 PI_IP=<pi-ip>        # cross-compile & deploy .ta + ./app
./rsu-quad-ssh.sh --pi-ip <pi-ip>
make hil-quad HIL_IFACE=<host-nic>       # add GUI=1 for sumo-gui

# 4. Complementary VM workflow (4-RSU HIL without physical RPi3 hardware)
./setup-vm.sh                  # create/start optee-arm64-vm
make vm                        # run self-test inside VM
make vm-hil                    # launch 4-RSU daemon inside VM (pair with: make hil-quad HIL_IFACE=virbr0)
```

---

## Top-level targets ([`Makefile`](Makefile))

| Command | What it does |
|---|---|
| `make build` | Builds `rsu-optee-gateway/app` (`HOST_SIM` self-test + `rsu` HIL daemon) |
| `make run` / `make test` | Builds and runs the 7-scenario OP-TEE gateway self-test |
| `make vm` | Syncs the repository into `optee-arm64-vm` and runs the self-test |
| `make vm-hil` | Starts 4 concurrent `rsu[0]`..`rsu[3]` processes inside `optee-arm64-vm` (pair with `HIL_IFACE=virbr0` on host) |
| `make rpi3 [PI_IP=<ip>]` | Cross-compiles the `.ta` and `./app` for Raspberry Pi 3 (`-mcpu=cortex-a53`) and optionally deploys via SSH |
| `make sim` | Rebuilds `tee_v2x` and runs the pure-simulation `D250m_80211p` 4-RSU Manhattan Grid + CTRA scenario |
| `make hil-quad HIL_IFACE=<nic> [GUI=1]` | Rebuilds `tee_v2x` and runs `HIL_RPi3_QuadRsu` (or `HIL_RPi3_QuadRsu_GUI` with `GUI=1`) |
| `make clean` | Removes build outputs, `*.sealed*` state files, and simulation result artifacts |

---

## 1. OP-TEE RSU Gateway (`rsu-optee-gateway/`)

The gateway separates untrusted OS networking from cryptographic state and keys:

- **Normal World (`host/`)**: `./app` manages raw Ethernet sockets (`0x88b5` radio, `0x88b6` backhaul), message fragmentation/reassembly, OT/IT queues (`PacketManager`), PTP clock synchronization, and `TeeSession` invocations. It never sees plaintext `Activation_Token` (`Auth_d`/`Auth_eg`), `Active_02` (`OTP_dt`), `Handover_Predict`, `Forwarding_Notice` (`E_{K_rsu}`), `Forwarding_Granted` (`E_{KT_i}`), `K_g`, `K_dg`, `K_rsu`, `K_esa`, `K_eg`, or `SmartData` JSON.
- **Secure World (`ta/`)**: `9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta` uses the GlobalPlatform TEE Internal Core API to generate the Gateway's P-256 identity keypair (`X_gw`/`CY_g`) strictly inside TrustZone, pin the Root CA public key and verify CA-signed Gateway/ESA/Cloud X.509 certificates, derive the mutually-authenticated Gateway ↔ ESA AES-256-GCM key (`K_esa`), decrypt `Activation_Token` anonymously, verify fresh per-step `OTP_dt`s (Theorem 2: Ascon-AEAD128 for the bootstrap, RFC 8439 Poly1305-AES for handover and SmartData), enforce `[t_0, t_f]` / compromised-`Auth_d` exclusion / active-session reboot protection, perform OT→IT Secure Marshaling (`K_eg`), handle Secrecy Forwarding handovers, and seal state in OP-TEE Secure Storage (`TEE_STORAGE_PRIVATE`).

### Build modes & CLI

- **`TEE_MODE=HOST_SIM`** (default on x86_64): Runs `GatewayTaSession` in-process with OpenSSL 3 and AES-256-GCM host-sealed files for fast debugging and Artery host simulation.
- **`TEE_MODE=OPTEE`**: Links `./app` against `libteec` (`-lteec`) to talk to `/dev/tee0` and `tee-supplicant` on the Raspberry Pi 3, and builds `ta/9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta`.

```text
Usage:
  ./rsu-optee-gateway/app [selftest] [--sealed <id>] [--fresh]
  ./rsu-optee-gateway/app rsu [--name <rsu>] [--iface <nic>] [--sealed <id>] [--fresh] [--session-timeout <sec>]
```

Running `./rsu-optee-gateway/app` (or `make run`) executes 7 scenarios (plus subtests `4a`–`4m` and `7a`–`7d`), ending with:

```text
results:
  1. normal (Operator + CA + Theorem 2)  vehicle: yes  operator Active_03: yes  ignored: 0   ok
  2. OTP changed on the air              vehicle: no   operator Active_03: no   ignored: 1   ok
  3. Auth_Request after t_f              vehicle: no   operator Active_03: no   ignored: 1   ok
  4. handover rsu[0] -> rsu[1]           Secure Marshaling (4a-4g): ok, Secrecy Forwarding (4h-4m): ok   ok
  5. CY_g of no gateway                  vehicle: no   operator Active_03: no   ignored: 1   ok
  6. before t_0 (TA enforced)            vehicle: no   operator Active_03: no   ignored: 1   ok
  7. security & HIL checks (7a-7e)       Reboot/DoS, CA PKI, Operator, HIL & SecFwd   ok
gateway OK
```

*(Other `rsu-optee-gateway/` targets include `make caps` to grant `cap_net_raw=ep` on `./app`, and `make hil-quad` to run 4 concurrent `rsu[0]`..`rsu[3]` processes locally over Ethernet.)*

---

## 2. 4-RSU Manhattan Grid Raspberry Pi 3 HIL (`HIL_RPi3_QuadRsu`)

In **4-RSU HIL**, all 4 Manhattan Grid RSUs execute in isolated OP-TEE TA sessions on the Raspberry Pi 3:

1. **Cross-compile & deploy** onto the Raspberry Pi 3:
   ```bash
   make rpi3 PI_IP=<pi-ip>
   ```
2. **Start all 4 RSUs in OP-TEE on the Raspberry Pi 3** (requires `tee-supplicant` + `/dev/tee0`):
   ```bash
   ./rsu-quad-ssh.sh --pi-ip <pi-ip>
   ```
   This launches 4 independent `./app rsu` daemons sharing `eth0`:
   - `rsu[0]` (West edge) with Secure Storage ID `rsu0.sealed` (OP-TEE TA session #1)
   - `rsu[1]` (North edge) with Secure Storage ID `rsu1.sealed` (OP-TEE TA session #2)
   - `rsu[2]` (East edge) with Secure Storage ID `rsu2.sealed` (OP-TEE TA session #3)
   - `rsu[3]` (South edge) with Secure Storage ID `rsu3.sealed` (OP-TEE TA session #4)
3. **Run Artery on the host PC** (ensure `sudo setcap cap_net_raw=ep artery-sim/deps/omnetpp-5.7.1/bin/opp_run_release` or run with privileges):
   ```bash
   make hil-quad HIL_IFACE=<host-nic>          # headless
   make hil-quad HIL_IFACE=<host-nic> GUI=1    # with sumo-gui
   ```
   *(Or invoke `./artery-sim/run-hil-quad.sh --iface <host-nic> [--gui] [--rebuild]` directly.)*

Artery drives SUMO mobility around the **400 m × 400 m Manhattan Grid** (`20 m/s` along `w_0 w_1 n_0 n_1 e_0 e_1 s_0 s_1`), ITS-G5 802.11p channel physics, vehicle `node[0]` with `CtraPredictor`, the ESA, and Cloud signature/decryption verification (`BackhaulBroker`), bridging `0x88b5` radio and `0x88b6` backhaul traffic over `<host-nic>` so `rsu[0]`..`rsu[3]` execute initial bootstrapping, SmartData marshaling, selective CTRA token pre-fetching, and TrustZone-to-TrustZone **Secrecy Forwarding** on the physical RPi3. Once `Session_Hello` / `Session_Ack` discovery completes, `RawSocket` pins each side's learned peer unicast MAC (`setPeerMac`) so LAN switches/routers do not drop concurrent 4-RSU frames under broadcast storm control.

---

## 3. Complementary VM Workflow (`setup-vm.sh`, `make vm`, `make vm-hil`)

`./setup-vm.sh` provisions an Ubuntu 24.04 x86_64 libvirt/KVM VM (`optee-arm64-vm`) with the ARM64 cross-toolchain, `qemu-system-arm`, `optee_os` `vexpress-qemu_armv8a` (`ta_dev_kit`), and `optee_client` (`libteec`) in `/opt/optee`.

- **Self-test inside the VM**: `make vm` syncs the repo via `rsu-optee-gateway/vm-make.sh` and runs the self-test.
- **4-RSU HIL against the VM**:
  1. Terminal 1: `make vm-hil` (syncs the repo, grants `cap_net_raw=ep` in the VM, and starts 4 concurrent `rsu[0]`..`rsu[3]` processes bound to the VM's libvirt NIC).
  2. Terminal 2 (host PC): `make hil-quad HIL_IFACE=virbr0` (pairs Artery `HIL_RPi3_QuadRsu` over the KVM bridge `virbr0` using the same Ethernet multiplexing path as physical RPi3 HIL).

---

## 4. CTRA Pre-Fetch & Secrecy Forwarding (`common/Handover.h`, `artery-sim/src/CtraPredictor.h`)

At startup, neighboring RSUs exchange CA-signed certificates inside their TrustZone TAs (`TA_GATEWAY_CMD_REGISTER_PEER_RSU`), deriving pairwise authenticated keys $K_{rsu}$. During bootstrap (`Auth_Granted`) and each handover (`Forwarding_Granted`), the vehicle receives the CA-verified neighbor list `nextRsus` ($\{G, Y_G\}$). Outside the Secure World (Normal World on the vehicle), the **Constant Turn Rate and Acceleration (CTRA)** predictor ($X = [x, y, v, \psi, a, \omega]^T$ over an `8.0 s` lookahead horizon) selects only the single most likely target RSU $G_{i+2}$ (`minDistance <= 80 m`) and pre-computes $\tau_{i+2}$, $K_{dh_i} = \text{ECDH}(X_V, Y_{G_{i+2}})$, $KT_i$, and $\text{auth}_{i+2}$ locally without a `Handover_Command` round-trip:

| # | Message | Direction | Transport | What it does |
|---|---|---|---|---|
| 0 | `Handover_Predict` (`21`) | $\text{Vehicle} \to G_{i+1}$ | Radio (`0x88b5`) | Vehicle sends $E_{K_{dg}}(\{\text{Auth}_d, G_{i+2}, \text{OTP}_{dt}\})$ identifying only $G_{i+2}$; verified inside TA (`TA_GATEWAY_CMD_HANDLE_HANDOVER_PREDICT`) |
| 1 | `Forwarding_Notice` (`16`) | $G_{i+1} \to G_{i+2}$ | Backhaul (`0x88b6`) | $G_{i+1}$ TA seals $E_{K_{rsu}}(\{\text{Forwarding\_Notice}, Y_V, \tau_{i+2}, \text{Auth}_d\})$ (`TA_GATEWAY_CMD_TRIGGER_HANDOVER`); $G_{i+2}$ TA pre-computes $K_{dh_i}$, $KT_i$, $\text{auth}_{i+2}$ (`TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE`) |
| 2 | `Forwarding_Request` (`18`) | $\text{Vehicle} \to G_{i+2}$ | Radio (`0x88b5`) | Sent when entering `handoverRadius = 160 m`; carries $\text{auth}_{i+2} = \text{SHA256}(\tau_{i+2})$ and $\text{OTP} = \text{Poly1305}(KT_i^{32}, \text{auth}_{i+2} \oplus t_c, \text{type} \parallel \text{auth}_{i+2})$ (`TA_GATEWAY_CMD_HANDLE_FORWARDING_REQUEST`) |
| 3 | `Forwarding_Granted` (`19`) | $G_{i+2} \to \text{Vehicle}$ | Radio (`0x88b5`) | Sends $E_{KT_i}(\{\text{nextRsus}, \text{auth}'_{i+2}, K_{G_{i+2}}, \text{OTP}'\})$ with $\text{auth}'_{i+2} = \text{SHA256}(KT_i \parallel \text{auth}_{i+2})$ and fresh $\text{OTP}'$; vehicle switches to target key $K_{G_{i+2}}$ |
| – | `Secure_Data` (`20`) | $\text{Vehicle} \to \text{RSU}$ | Radio (`0x88b5`) | SmartData OT packet marshaled in TA (`TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT`) → IT Cloud backhaul (`0x88b6`) |

---

## 5. Artery Simulation Scenarios (`artery-sim/scenario/omnetpp.ini`)

| Config | Mode | What it runs |
|---|---|---|
| `D250m_80211p` / `D250m_80211p_GUI` | Pure host simulation (`HOST_SIM`) | IEEE 802.11p (5.9 GHz ch 180, 10 MHz, 6 Mbps, 200 mW); **400 m × 400 m 3×3 Manhattan Grid** (`85 s`, `20 m/s`), 4 RSUs on the 4 perimeter edges (`rsu[0]` West `(10, 200)`, `rsu[1]` North `(200, 10)`, `rsu[2]` East `(390, 200)`, `rsu[3]` South `(200, 390)`), CTRA trajectory prediction (`predictRadius = 80 m`, `handoverRadius = 160 m`), 3 handovers (`rsu[0] → rsu[1] → rsu[2] → rsu[3]`). |
| `HIL_RPi3_QuadRsu` (+ `HIL_RPi3_QuadRsu_GUI`) | Hardware-in-the-Loop (`cRealTimeScheduler`) | All 4 RSUs (`rsu[0]`..`rsu[3]`) have `enableHil = true`, bridging `0x88b5`/`0x88b6` frames over `HIL_IFACE` to the 4 isolated RPi3 (or `virbr0` VM) OP-TEE TA sessions. |
