# Secure-Handover-Protocol-For-V2X-Networks

Secure bootstrap (with IT **Human Operator** authorization, **Root CA** mutual authentication, and Theorem 2 fresh `OTP_dt`), **Secrecy Forwarding** (RSU-to-RSU handover), and **Secure Marshaling** (OT → IT Cloud encapsulation) between a **vehicle**, an **RSU** (Road-Side Unit), a **Human Operator**, and an **ESA** (External Security Agent), implemented in C++17 + OpenSSL 3 and **Arm TrustZone (OP-TEE)**.

The physical testbed uses a **Raspberry Pi 3 Model B** running **OP-TEE OS** for **all 4 Manhattan Grid RSUs (`rsu[0]`..`rsu[3]`)** in 4 isolated Trusted Application sessions (`9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta`, `rsu0.sealed`..`rsu3.sealed`) over raw Layer-2 Ethernet (`AF_PACKET`, EtherType `0x88b5` for OT radio and `0x88b6` for IT backhaul), while **CrowNet (OMNeT++ 6.3.0 + INET 4 + Veins + Artery + Simu5G) + SUMO** on the host PC simulates the **5G NR** RAN/Core (`4` gNodeBs with full-mesh X2 handover, UPF, edge router), the Manhattan Grid vehicle UE (`ApplicationLayerVehicle`), purely kinematic CTRA trajectory predictor, Root CA, Human Operator, ESA, and Cloud sink.

For development without physical RPi3 hardware, a complementary **libvirt/KVM VM (`optee-arm64-vm`)** workflow (`setup-vm.sh`, `make vm`, `make vm-hil`) provides the same 4-RSU `./app` environment over the host `virbr0` bridge.

Once bootstrapped with `rsu[0]`, the vehicle's purely kinematic **CTRA (Constant Turn Rate and Acceleration)** trajectory predictor (`CtraPredictor`, in Normal World on the vehicle) selects the single most likely next RSU and triggers selective **Secrecy Forwarding** token pre-fetching (`Handover_Predict` → `Forwarding_Notice`) exclusively with that target RSU, completing handovers (`rsu[0] → rsu[1] → rsu[2] → rsu[3]`) over **5G NR** without contacting the ESA or performing a new bootstrap ([`common/Handover.h`](common/Handover.h)). For a deep reference covering every test, C++ class, cryptographic equation, wire frame, and expected output, see [TESTS.md](TESTS.md).

---

## Repository layout

| Path | Contents |
|---|---|
| [`Makefile`](Makefile) | Top-level entrypoints (`build`, `run`, `vm`, `vm-hil`, `rpi3`, `sim`, `hil-quad`, `clean`, `help`) |
| [`common/`](common) | Protocol messages, binary codecs, crypto primitives, unified OTP (`Ascon` / `Poly1305`), `SimTime`, tracing, vehicle traits, `SmartData`, `Handover` equations |
| [`protocol/`](protocol) | Vehicle protocol stack (`VehicleSession`, `BootstrapClient`, `HandoverClient`, `SecureDataClient`, `VehicleAgent`), IT `HumanOperator`, and `ExternalSecurityAgent` |
| [`net/`](net) | Raw Layer-2 Ethernet sockets (`RawSocket`) and framing/demux/fragmentation (`Link`) |
| [`rsu-optee-gateway/`](rsu-optee-gateway) | OP-TEE RSU gateway: `include/gateway_ta.h`, `ta/` (Secure World TA), `host/` (Normal World `./app` self-test & `rsu` daemon, `Benchmark`, `PacketManager`, `TeeSession`), `build-rpi3.sh`, `vm-make.sh` |
| [`artery-sim/`](artery-sim) | Host-PC CrowNet 5G NR (OMNeT++ 6.3 + INET 4 + Artery + Simu5G + SUMO) 4-RSU Manhattan Grid simulation (`Dockerfile.crownet`, `Makefile`, `setup_artery.sh`, `run-sim.sh`, `run-hil-quad.sh`, `CtraPredictor`, `scenario/`, `src/`) |
| [`setup-vm.sh`](setup-vm.sh) | Sets up the complementary Ubuntu 24.04 libvirt/KVM VM (`optee-arm64-vm`) with OP-TEE DevKit & `libteec` |
| [`rsu-quad-ssh.sh`](rsu-quad-ssh.sh) | Launches 4 concurrent `rsu[0]`..`rsu[3]` OP-TEE gateway sessions on the Raspberry Pi 3 over SSH |
| [`TESTS.md`](TESTS.md) | Comprehensive reference of every test, simulation, HIL setup, class, wire format, and expected output |

---

## Quick start

All test, simulation, and HIL commands accept `OTP=ascon|poly1305` (or `--otp ascon|poly1305`, default: `ascon`) to run every OTP/MAC in the session under a single algorithm — never mixed.

```bash
# 1. Host self-test: 7-scenario OP-TEE gateway self-test (HOST_SIM mode)
make run                       # or: make run OTP=poly1305

# 2. Pure CrowNet 5G NR (Artery + Simu5G) 4-RSU Manhattan Grid simulation
artery-sim/setup_artery.sh --clean-objs  # one-time Docker image + CrowNet 5G build
make sim                       # or: make sim OTP=poly1305 GUI=1

# 3. Physical 4-RSU Raspberry Pi 3 5G NR HIL (all 4 RSUs in RPi3 TrustZone; 5G NR RAN/Core on PC)
make rpi3 PI_IP=<pi-ip>        # cross-compile & deploy .ta + ./app
./rsu-quad-ssh.sh --pi-ip <pi-ip> [--otp ascon|poly1305]
make hil-quad HIL_IFACE=<host-nic> [OTP=ascon|poly1305] [GUI=1]

# 4. Complementary VM workflow (4-RSU 5G NR HIL without physical RPi3 hardware)
./setup-vm.sh                  # create/start optee-arm64-vm (add --recreate to rebuild)
make vm [OTP=ascon|poly1305]   # run self-test inside VM
make vm-hil [OTP=ascon|poly1305] # launch 4-RSU daemon inside VM (pair with: make hil-quad HIL_IFACE=virbr0)
```

---

## Top-level targets ([`Makefile`](Makefile))

| Command | Flags / Variables | What it does |
|---|---|---|
| `make build` | — | Builds `rsu-optee-gateway/app` (`HOST_SIM` self-test + `rsu` HIL daemon) |
| `make run` / `make test` | `OTP=ascon\|poly1305` *(default `ascon`)* | Builds and runs the 7-scenario OP-TEE gateway self-test |
| `make vm` | `OTP=ascon\|poly1305` *(default `ascon`)* | Syncs the repository into `optee-arm64-vm` and runs the self-test |
| `make vm-hil` | `OTP=ascon\|poly1305` *(default `ascon`)* | Starts 4 concurrent `rsu[0]`..`rsu[3]` processes inside `optee-arm64-vm` (pair with `HIL_IFACE=virbr0` on host) |
| `make rpi3` | `PI_IP=<ip>` *(optional)* | Cross-compiles the `.ta` and `./app` for Raspberry Pi 3 (`-mcpu=cortex-a53`) and deploys via SSH when `PI_IP` is set |
| `make sim` | `OTP=ascon\|poly1305` *(default `ascon`)*, `GUI=1`, `QUIET=1`, `CSV_PREFIX=<path>` | Rebuilds `libtee_v2x.so`, runs CrowNet 5G NR `NR_5G` (or `NR_5G_GUI`), prints the V2X Evaluation Report, and exports 3 CSV files |
| `make hil-quad` | `HIL_IFACE=<nic>` *(required)*, `OTP=ascon\|poly1305`, `GUI=1`, `VERBOSE=1`, `CSV_PREFIX=<path>` | Rebuilds `libtee_v2x.so`, runs 5G NR `HIL_RPi3_QuadRsu` (focused output by default; pass `VERBOSE=1` for full crypto trace), and exports 3 CSV files |
| `make clean` | — | Removes build outputs, `*.sealed*` state files, and simulation result artifacts |

---

## 1. OP-TEE RSU Gateway (`rsu-optee-gateway/`)

The gateway separates untrusted OS networking from cryptographic state and keys:

- **Normal World (`host/`)**: `./app` manages raw Ethernet sockets (`0x88b5` radio, `0x88b6` backhaul), message fragmentation/reassembly, OT/IT queues (`PacketManager`), PTP clock synchronization, and `TeeSession` invocations. It never sees plaintext `Activation_Token` (`Auth_d`/`Auth_eg`), `Active_02` (`OTP_dt`), `Handover_Predict`, `Forwarding_Notice` (`E_{K_rsu}`), `Forwarding_Granted` (`E_{KT_i}`), `K_g`, `K_dg`, `K_rsu`, `K_esa`, `K_eg`, or `SmartData` JSON.
- **Secure World (`ta/`)**: `9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta` uses the GlobalPlatform TEE Internal Core API to generate the Gateway's P-256 identity keypair (`X_gw`/`CY_g`) strictly inside TrustZone, pin the Root CA public key and verify CA-signed Gateway/ESA/Cloud X.509 certificates, derive the mutually-authenticated Gateway ↔ ESA AES-256-GCM key (`K_esa`), decrypt `Activation_Token` anonymously, verify fresh per-step `OTP_dt`s (Theorem 2: all OTPs/MACs in a run use either **Ascon-AEAD128** or **Poly1305-AES**, selected via `--otp ascon|poly1305`, never mixed), enforce `[t_0, t_f]` / compromised-`Auth_d` exclusion / active-session reboot protection, perform OT→IT Secure Marshaling (`K_eg`), handle Secrecy Forwarding handovers, and seal state in OP-TEE Secure Storage (`TEE_STORAGE_PRIVATE`).

### Build modes & CLI

- **`TEE_MODE=HOST_SIM`** (default on x86_64): Runs `GatewayTaSession` in-process with OpenSSL 3 and AES-256-GCM host-sealed files for fast debugging and Artery host simulation.
- **`TEE_MODE=OPTEE`**: Links `./app` against `libteec` (`-lteec`) to talk to `/dev/tee0` and `tee-supplicant` on the Raspberry Pi 3, and builds `ta/9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta`.

```text
Usage:
  ./rsu-optee-gateway/app [selftest] [--otp ascon|poly1305] [--sealed <id>] [--fresh]
  ./rsu-optee-gateway/app rsu [--otp ascon|poly1305] [--name <rsu>] [--iface <nic>] [--sealed <id>] [--fresh] [--session-timeout <sec>]
```

| Flag (`./app`) | Modes | Default | Description |
|---|---|---|---|
| `--otp ascon\|poly1305` | `selftest`, `rsu` | `ascon` (`selftest`); auto-adopt from `Session_Ack` (`rsu`) | Selects the single OTP/MAC algorithm for the whole run. In `rsu` mode, passing `--otp` explicitly enforces a match against Artery's `Session_Ack`. |
| `--sealed <id>` | `selftest`, `rsu` | `gateway.sealed` (`OPTEE`) or `<app-dir>/gateway.sealed` (`HOST_SIM`) | OP-TEE Secure Storage object ID (or host-sealed file path in `HOST_SIM`). |
| `--fresh` | `selftest`, `rsu` | off (`0`) | Purges any existing sealed state for `--sealed <id>` on startup (`--fresh`, `--fresh 1`, or `--fresh true`). |
| `--name <rsu>` | `rsu` | `rsu[0]` | Logical RSU identifier on shared Ethernet (`rsu[0]`..`rsu[3]`). |
| `--iface <nic>` | `rsu` | `eth0` | Network interface for raw Ethernet sockets (`0x88b5` radio, `0x88b6` backhaul). |
| `--session-timeout <sec>` | `rsu` | `120` | Seconds to wait for initial `Session_Ack` from Artery/ESA before exiting. |
| `-h`, `--help` | both | — | Prints CLI usage and exits. |

*(In `rsu-optee-gateway/Makefile`, you can also pass `TEE_MODE=HOST_SIM|OPTEE`, `OTP=ascon|poly1305`, `IFACE=<nic>`, `SESSION_TIMEOUT=<sec>`, `PLATFORM=<name>`, `PI_IP=<ip>`, and `VM_ARGS=<targets>`.)*

Running `./rsu-optee-gateway/app --otp ascon` or `--otp poly1305` (or `make run OTP=ascon` / `make run OTP=poly1305`, `make sim OTP=...`, `make hil-quad HIL_IFACE=<nic> OTP=...`) runs all 7 scenarios (plus subtests `4a`–`4m` and `7a`–`7e`) under the single selected OTP/MAC algorithm, ending with:

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
   ./rsu-quad-ssh.sh --pi-ip <pi-ip> [--rsu-iface eth0] [--otp ascon|poly1305] [--session-timeout 120] [--keep-state] [--remote-app /root/app]
   ```
   - `--pi-ip <ip>` (or `PI_IP=<ip>`): Raspberry Pi IP *(required)*.
   - `--rsu-iface <iface>` (or `RSU_IFACE=<iface>`): Pi Ethernet NIC *(default `eth0`)*.
   - `--otp ascon|poly1305` (or `OTP=...`): Pin OTP algorithm on the Pi; if omitted, each RSU adopts the algorithm sent by Artery in `Session_Ack`.
   - `--session-timeout <sec>` (or `SESSION_TIMEOUT=<sec>`): Handshake timeout *(default `120`)*.
   - `--keep-state`: Reuse existing `rsu0.sealed`..`rsu3.sealed` instead of passing `--fresh`.
   - `--remote-app <path>`: Remote binary path on the Pi *(default `/root/app`)*.

   This launches 4 independent `./app rsu` daemons sharing `eth0`:
   - `rsu[0]` (West edge) with Secure Storage ID `rsu0.sealed` (OP-TEE TA session #1)
   - `rsu[1]` (North edge) with Secure Storage ID `rsu1.sealed` (OP-TEE TA session #2)
   - `rsu[2]` (East edge) with Secure Storage ID `rsu2.sealed` (OP-TEE TA session #3)
   - `rsu[3]` (South edge) with Secure Storage ID `rsu3.sealed` (OP-TEE TA session #4)
3. **Run CrowNet 5G NR on the host PC** (`v2x-crownet:6.3.0` already sets `cap_net_raw+ep` on `opp_run_release` and launches with `--network=host --cap-add=NET_RAW`, while host SUMO 1.26.0 runs natively):
   ```bash
   make hil-quad HIL_IFACE=<host-nic> [OTP=ascon|poly1305] [GUI=1] [CSV_PREFIX=<path>] [VERBOSE=1]
   # Or invoke run-hil-quad.sh / run-sim.sh directly:
   ./artery-sim/run-hil-quad.sh --iface <host-nic> [--otp ascon|poly1305] [--csv-prefix <path>] [--verbose] [--gui] [--rebuild] [-- <extra opp_run flags>]
   ./artery-sim/run-sim.sh [--config NR_5G|NR_5G_GUI|HIL_RPi3_QuadRsu|HIL_RPi3_QuadRsu_GUI] [--otp ascon|poly1305] [--iface <nic>] [--csv-prefix <path>] [--quiet|--verbose] [--gui] [--rebuild] [-- <extra opp_run flags>]
   ```
   - `--config <name>` (`run-sim.sh`): OMNeT++ config *(default `NR_5G`, or `NR_5G_GUI` with `--gui`)*.
   - `--iface <nic>` (or `HIL_IFACE=<nic>`): Host NIC wired to the RPi3 *(required for HIL configs)*.
   - `--otp ascon|poly1305` (or `OTP` / `OTP_ALGO`): OTP/MAC algorithm for the whole run *(default `ascon`)*.
   - `--csv-prefix <path>` (or `CSV_PREFIX=<path>`): Custom output prefix for the 3 evaluation CSV files *(default `artery-sim/scenario/results/<config>-<otp>`)*.
   - `--quiet` / `--verbose` (`QUIET=1` / `VERBOSE=1`): `HIL_RPi3_QuadRsu` uses focused evaluation output (`[EVAL t=...]` milestones + summary report) by default; pass `--verbose` (`V2X_VERBOSE=1`) to re-enable per-step crypto hex dumps.
   - `--gui`: Launches host `sumo-gui --start` (`NR_5G_GUI` / `HIL_RPi3_QuadRsu_GUI`) instead of headless `sumo`.
   - `--rebuild`: Rebuilds `artery-sim/build/libtee_v2x.so` before starting CrowNet.
   - `-- <extra opp_run flags>`: Forwards additional flags directly to `opp_run_release` (e.g. `--*.rsu[*].app[0].hilHandshakeTimeout=25s`).

CrowNet drives SUMO mobility around the **400 m × 400 m Manhattan Grid** (`20 m/s` along `w_0 w_1 n_0 n_1 e_0 e_1 s_0 s_1`), **Simu5G 5G NR** (`3.5 GHz` n78, numerology μ=1 / `30 kHz` SCS, `25 RBs`, 4 `gNodeB`s with full-mesh X2 handover + `UPF` + `Router`), vehicle `node[0]` (`ApplicationLayerVehicle` with Artery `VehicleMiddleware` + purely kinematic `CtraPredictor`), the ESA, and Cloud verification (`BackhaulBroker`), bridging `0x88b5` radio and `0x88b6` backhaul traffic over `<host-nic>` so `rsu[0]`..`rsu[3]` execute initial bootstrapping, SmartData marshaling, selective CTRA token pre-fetching, and TrustZone-to-TrustZone **Secrecy Forwarding** on the physical RPi3. Once `Session_Hello` / `Session_Ack` discovery completes, `RawSocket` pins each side's learned peer unicast MAC (`setPeerMac`) so LAN switches/routers do not drop concurrent 4-RSU frames under broadcast storm control.

---

## 3. Complementary VM Workflow (`setup-vm.sh`, `make vm`, `make vm-hil`)

`./setup-vm.sh` provisions an Ubuntu 24.04 x86_64 libvirt/KVM VM (`optee-arm64-vm`) with the ARM64 cross-toolchain, `qemu-system-arm`, `optee_os` `vexpress-qemu_armv8a` (`ta_dev_kit`), and `optee_client` (`libteec`) in `/opt/optee`.

- **Self-test inside the VM**: `make vm [OTP=ascon|poly1305]` syncs the repo via `rsu-optee-gateway/vm-make.sh` (`VM_NAME`, `VM_DIR`, `VM_USER`, `VM_HOST` env overrides) and runs the self-test.
- **4-RSU HIL against the VM**:
  1. Terminal 1: `make vm-hil [OTP=ascon|poly1305]` (syncs the repo, grants `cap_net_raw=ep` in the VM, and starts 4 concurrent `rsu[0]`..`rsu[3]` processes bound to the VM's libvirt NIC).
  2. Terminal 2 (host PC): `make hil-quad HIL_IFACE=virbr0 [OTP=ascon|poly1305] [GUI=1]` (pairs Artery `HIL_RPi3_QuadRsu` over the KVM bridge `virbr0` using the same Ethernet multiplexing path as physical RPi3 HIL).

---

## 4. CTRA Pre-Fetch & Secrecy Forwarding (`common/Handover.h`, `artery-sim/src/CtraPredictor.h`)

At startup, neighboring RSUs exchange CA-signed certificates inside their TrustZone TAs (`TA_GATEWAY_CMD_REGISTER_PEER_RSU`), deriving pairwise authenticated keys $K_{rsu}$. During bootstrap (`Auth_Granted`) and each handover (`Forwarding_Granted`), the vehicle receives the CA-verified neighbor list `nextRsus` ($\{G, Y_G\}$). Outside the Secure World (Normal World on the vehicle), the **Constant Turn Rate and Acceleration (CTRA)** predictor ($X = [x, y, v, \psi, a, \omega]^T$ over an `8.0 s` lookahead horizon) selects only the single most likely target RSU $G_{i+2}$ (`minDistance <= 80 m`) and pre-computes $\tau_{i+2}$, $K_{dh_i} = \text{ECDH}(X_V, Y_{G_{i+2}})$, $KT_i$, and $\text{auth}_{i+2}$ locally without a `Handover_Command` round-trip:

| # | Message | Direction | Transport | What it does |
|---|---|---|---|---|
| 0 | `Handover_Predict` (`21`) | $\text{Vehicle} \to G_{i+1}$ | Radio (`0x88b5`) | Vehicle sends $E_{K_{dg}}(\{\text{Auth}_d, G_{i+2}, \text{OTP}_{dt}\})$ identifying only $G_{i+2}$; verified inside TA (`TA_GATEWAY_CMD_HANDLE_HANDOVER_PREDICT`) |
| 1 | `Forwarding_Notice` (`16`) | $G_{i+1} \to G_{i+2}$ | Backhaul (`0x88b6`) | $G_{i+1}$ TA seals $E_{K_{rsu}}(\{\text{Forwarding\_Notice}, Y_V, \tau_{i+2}, \text{Auth}_d\})$ (`TA_GATEWAY_CMD_TRIGGER_HANDOVER`); $G_{i+2}$ TA pre-computes $K_{dh_i}$, $KT_i$, $\text{auth}_{i+2}$ (`TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE`) |
| 2 | `Forwarding_Request` (`18`) | $\text{Vehicle} \to G_{i+2}$ | Radio (`0x88b5`) | Sent when entering `handoverRadius = 160 m`; carries $\text{auth}_{i+2} = \text{SHA256}(\tau_{i+2})$ and $\text{OTP} = \text{MAC}(KT_i^{32}, \text{auth}_{i+2} \oplus t_c, \text{type} \parallel \text{auth}_{i+2})$ (`TA_GATEWAY_CMD_HANDLE_FORWARDING_REQUEST`) |
| 3 | `Forwarding_Granted` (`19`) | $G_{i+2} \to \text{Vehicle}$ | Radio (`0x88b5`) | Sends $E_{KT_i}(\{\text{nextRsus}, \text{auth}'_{i+2}, K_{G_{i+2}}, \text{OTP}'\})$ with $\text{auth}'_{i+2} = \text{SHA256}(KT_i \parallel \text{auth}_{i+2})$ and fresh $\text{OTP}'$; vehicle switches to target key $K_{G_{i+2}}$ |
| – | `Secure_Data` (`20`) | $\text{Vehicle} \to \text{RSU}$ | Radio (`0x88b5`) | SmartData OT packet marshaled in TA (`TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT`) → IT Cloud backhaul (`0x88b6`) |

---

## 5. CrowNet 5G NR Simulation Scenarios (`artery-sim/scenario/omnetpp.ini`)

| Config | Mode | What it runs |
|---|---|---|
| `NR_5G` / `NR_5G_GUI` | Pure host simulation (`HOST_SIM`) | **5G NR via CrowNet (OMNeT++ 6.3.0 + INET 4 + Artery + Simu5G)** — `3.5 GHz` n78 NR carrier, numerology $\mu=1$ (`30 kHz` SCS), `25 RBs`, `ueTxPower = 26 dBm`, `eNodeBTxPower = 30 dBm`; **400 m × 400 m 3×3 Manhattan Grid** (`85 s`, `20 m/s`), 4 `gNodeB`s (`gNB[0..3]`) with full-mesh X2 handover + `UPF` + `Router` + 4 co-located OP-TEE RSUs (`rsu[0]` West `(10, 200)`, `rsu[1]` North `(200, 10)`, `rsu[2]` East `(390, 200)`, `rsu[3]` South `(200, 390)`), purely kinematic CTRA prediction (`predictRadius = 80 m`, `handoverRadius = 160 m`), 3 live 5G NR X2 radio handovers (`gNB[0] → gNB[1] → gNB[2] → gNB[3]`), and 3 Secrecy Forwarding handovers (`rsu[0] → rsu[1] → rsu[2] → rsu[3]`). |
| `HIL_RPi3_QuadRsu` (+ `HIL_RPi3_QuadRsu_GUI`) | 5G NR Hardware-in-the-Loop (`cRealTimeScheduler`) | Extends `NR_5G` with `*.rsu[*].app[0].enableHil = true` and `*.backhaulBroker.quietTrace = true` (focused evaluation milestones + report + CSV exports), bridging `0x88b5`/`0x88b6` frames over `HIL_IFACE` to the 4 isolated RPi3 (or `virbr0` VM) OP-TEE TA sessions while the 5G NR RAN/Core, vehicle UE, CTRA predictor, ESA, and Cloud run in CrowNet. |

### Academic V2X Evaluation Metrics & CSV Exports

Every `NR_5G` and `HIL_RPi3_QuadRsu` run prints a structured **V2X 5G NR + OP-TEE Evaluation Report** at completion and exports 3 CSV files into `artery-sim/scenario/results/` (default prefix `<config>-<otp>`, overridable via `CSV_PREFIX=<path>` / `--csv-prefix <path>`):

- **`<prefix>-summary.csv`** (`category,metric,value,unit,description`): Aggregated academic V2X & TEE metrics — OT/E2E PDR & PLR, TA acceptance rate, OT/Cloud goodput (`kbps`), security control overhead (`%`), E2E OT→Cloud latency (`mean/std/min/p50/p95/p99/max`), 5G NR uplink latency, RSU OP-TEE TA turnaround latency, RFC 3550 latency jitter (IPDV), bootstrap & Operator E2E delay, Secrecy Forwarding handover delay & success rate, Handover Interruption Time (HIT), CTRA prediction accuracy, pre-fetch lead time, backhaul signaling reduction (`%`), 5G NR X2 radio handovers, and Simu5G 5G NR DL/UL SINR & CQI.
- **`<prefix>-handovers.csv`**: Per-handover event log (`from_rsu`, `to_rsu`, CTRA predict & pre-fetch timestamps/accuracy, 5G NR X2 gNB switch, `Forwarding_Request`/`Granted` timestamps, pre-fetch lead time, handover E2E delay, HIT, distance).
- **`<prefix>-packets.csv`**: Per-packet time-series (`seq`, `tx_time_s`, `rsu_rx_time_s`, `cloud_rx_time_s`, `rsu`, `serving_gnb`, `ot_bytes`, `it_json_bytes`, `nr_uplink_ms`, `rsu_ta_ms`, `e2e_latency_ms`, `jitter_ms`) ready for plotting CDFs, latency timelines, and jitter distributions.
