# Comprehensive Guide to Tests, Hardware Testbench, VM, and Simulations

This document is a technical reference for every test, benchmark, hardware-in-the-loop (HIL) setup, VM workflow, and V2X network simulation in **Secure-Handover-Protocol-For-V2X-Networks**, covering the **OP-TEE RSU Gateway**, **4-RSU Manhattan Grid Raspberry Pi 3 HIL** (`HIL_RPi3_QuadRsu`), and **CTRA trajectory prediction + Secrecy Forwarding** handover.

For a concise overview and quick-start commands, see [README.md](README.md).

---

## Table of Contents

1. [Test & Simulation Matrix](#1-test--simulation-matrix)
2. [Architecture & Protocol Foundations](#2-architecture--protocol-foundations)
   - [2.1 Actors & Trust Boundaries](#21-actors--trust-boundaries)
   - [2.2 Cryptographic Key Hierarchy & Equations](#22-cryptographic-key-hierarchy--equations)
   - [2.3 IEEE 1588 PTP Synchronization & Slotted OTPs](#23-ieee-1588-ptp-synchronization--slotted-otps)
   - [2.4 Wire Protocols, Raw Ethernet Framing & 4-RSU Multiplexing](#24-wire-protocols-raw-ethernet-framing--4-rsu-multiplexing)
3. [OP-TEE RSU Gateway Architecture (`rsu-optee-gateway/`)](#3-op-tee-rsu-gateway-architecture-rsu-optee-gateway)
   - [3.1 Normal World (`host/`) vs. Secure World (`ta/`)](#31-normal-world-host-vs-secure-world-ta)
   - [3.2 `HOST_SIM` Mode vs. `OPTEE` Hardware Mode](#32-host_sim-mode-vs-optee-hardware-mode)
   - [3.3 Secure Storage & State Persistence](#33-secure-storage--state-persistence)
4. [Suite 1: OP-TEE Gateway Security Self-Test (`make run` / `./app`)](#4-suite-1-op-tee-gateway-security-self-test-make-run--app)
   - [4.1 Purpose & Requirements](#41-purpose--requirements)
   - [4.2 Scenario-by-Scenario Deep Dive (`1`–`7` & `4a`–`4m`)](#42-scenario-by-scenario-deep-dive-17--4a4m)
   - [4.3 Observed Terminal Output](#43-observed-terminal-output)
5. [Suite 2: Raspberry Pi 3 TrustZone & 4-RSU HIL Daemon (`./app rsu`)](#5-suite-2-raspberry-pi-3-trustzone--4-rsu-hil-daemon-app-rsu)
   - [5.1 Cross-Compilation & Deployment (`build-rpi3.sh`)](#51-cross-compilation--deployment-build-rpi3sh)
   - [5.2 4-RSU Hardware Launcher (`rsu-quad-ssh.sh`)](#52-4-rsu-hardware-launcher-rsu-quad-sshsh)
   - [5.3 Embedded Gateway Latency Reporting (`Benchmark`)](#53-embedded-gateway-latency-reporting-benchmark)
6. [Suite 3: Complementary VM Workflow (`setup-vm.sh`, `make vm`, `make vm-hil`)](#6-suite-3-complementary-vm-workflow-setup-vmsh-make-vm-make-vm-hil)
   - [6.1 VM Provisioning (`setup-vm.sh`)](#61-vm-provisioning-setup-vmsh)
   - [6.2 Self-Test & Bridged 4-RSU HIL (`vm-make.sh`, `make vm-hil`)](#62-self-test--bridged-4-rsu-hil-vm-makesh-make-vm-hil)
7. [Suite 4: Artery / OMNeT++ / SUMO V2X Simulations (`artery-sim/`)](#7-suite-4-artery--omnet--sumo-v2x-simulations-artery-sim)
   - [7.1 Build Setup (`setup_artery.sh`)](#71-build-setup-setup_arterysh)
   - [7.2 Road Topology, SUMO Mobility & Custom Modules](#72-road-topology-sumo-mobility--custom-modules)
   - [7.3 Simulation Configurations (`omnetpp.ini`)](#73-simulation-configurations-omnetppini)
   - [7.4 Observed `D250m_80211p` Trace & Scalar Results](#74-observed-d250m_80211p-trace--scalar-results)

---

## 1. Test & Simulation Matrix

| Test / Configuration | Command | Primary Files | Frameworks & Tech | Key Requirements | TEE Role | What It Verifies |
|---|---|---|---|---|---|---|
| **OP-TEE Gateway Self-Test** | `make run` (or `make test`, or `./rsu-optee-gateway/app`) | [`rsu-optee-gateway/host/selftest.cpp`](rsu-optee-gateway/host/selftest.cpp), [`rsu-optee-gateway/ta/`](rsu-optee-gateway/ta) | C++17, OpenSSL 3 (`HOST_SIM`) or `libteec` + `.ta` (`OPTEE`) | C++17 + OpenSSL 3 on Linux (`HOST_SIM`); `/dev/tee0` + `tee-supplicant` + signed `.ta` (`OPTEE`). Takes ~0.5 s | Full TA isolation (`GatewayTaSession`, `ta_crypto`, CA verification, `K_esa`, Secure Storage) | Scenarios `1`–`7` + subtests `4a`–`4m` & `7a`–`7d`: Operator-initiated IT bootstrap (zero OT leak of `UUID_d`/`SHA256(fw_d)`), CA-authenticated `K_esa` sealing, fresh per-step `OTP_dt` (Theorem 2), tampered OTP, expired window `[t_0, t_f]` + compromised `Auth_d` exclusion, early arrival `< t_0` enforced in TA, rogue `CY_g`, OT→IT Secure Marshaling, Cloud session rotation, Secrecy Forwarding handover + replay/cross-RSU rejection, post-`t_f` DoS & reboot protection, CA PKI rejection, and HIL shared-link helpers. |
| **Artery Pure 802.11p Simulation** | `make sim` (or `opp_run_release ... -c D250m_80211p` / `_GUI`) | [`artery-sim/scenario/omnetpp.ini`](artery-sim/scenario/omnetpp.ini), [`HighwayHandover.ned`](artery-sim/scenario/HighwayHandover.ned), [`CtraPredictor.cc`](artery-sim/src/CtraPredictor.cc), [`artery-sim/src/`](artery-sim/src) | OMNeT++ 5.7.1, Artery, INET, Veins, Vanetza (BTP/GeoNetworking), SUMO, TA (`HOST_SIM`) | Built `tee_v2x` (`libartery_tee_v2x.so`) & SUMO binary (`artery-sim/setup_artery.sh`) | Each of the 4 simulated RSUs (`rsu[0]`..`rsu[3]`) owns an isolated host `TeeSession` | **400 m × 400 m 3×3 Manhattan Grid** (`85 s`, `20 m/s`), ITS-G5 ch 180 physics, vehicle bootstrapping (`rsu[0]`), 10 Hz SmartData, **CTRA** trajectory prediction + selective single-RSU pre-fetch (`Handover_Predict`), and 3 Secrecy Forwarding handovers (`rsu[0] → rsu[1] → rsu[2] → rsu[3]`). |
| **4-RSU Raspberry Pi 3 HIL** | `make rpi3 PI_IP=<ip>` + `./rsu-quad-ssh.sh --pi-ip <ip>` + `make hil-quad HIL_IFACE=<nic>` | [`rsu-optee-gateway/build-rpi3.sh`](rsu-optee-gateway/build-rpi3.sh), [`rsu-quad-ssh.sh`](rsu-quad-ssh.sh), [`artery-sim/run-hil-quad.sh`](artery-sim/run-hil-quad.sh), [`rsu_node.cpp`](rsu-optee-gateway/host/rsu_node.cpp), [`TeeRsuService.cc`](artery-sim/src/TeeRsuService.cc) | AArch64 RPi3 OP-TEE OS + `tee-supplicant` + `/dev/tee0` (`TA_FLAG_MULTI_SESSION`), OMNeT++ `cRealTimeScheduler`, Artery, SUMO, `AF_PACKET` (`0x88b5`/`0x88b6`) | RPi3 wired via Ethernet to `<nic>`, `cap_net_raw=ep` on `opp_run_release` (plus RPi3 `.ta` + `./app`) | All 4 RSUs (`rsu[0]`..`rsu[3]`, `rsu0.sealed`..`rsu3.sealed`) run concurrently inside OP-TEE on RPi3 | Real-time simulated Manhattan Grid vehicle with CTRA predictor, ESA, and Cloud (`BackhaulBroker`) exchanging bootstrap, 10 Hz SmartData marshaling, selective pre-fetch, and TrustZone-to-TrustZone Secrecy Forwarding over physical Ethernet. |
| **VM Self-Test (`optee-arm64-vm`)** | `./setup-vm.sh` + `make vm` | [`setup-vm.sh`](setup-vm.sh), [`rsu-optee-gateway/vm-make.sh`](rsu-optee-gateway/vm-make.sh) | libvirt/KVM Ubuntu 24.04 VM, `optee_os` `vexpress-qemu_armv8a` DevKit, `optee_client` | KVM/libvirt on host PC, `rsync`, `ssh`, internet during provisioning | Same `./app` build/self-test flow inside `optee-arm64-vm` | Reproducible VM sandbox with ARM64 cross-compilers, OP-TEE DevKit, and `libteec` in `/opt/optee`. |
| **VM Bridged 4-RSU HIL** | `make vm-hil` + `make hil-quad HIL_IFACE=virbr0` | [`Makefile`](Makefile), [`rsu-optee-gateway/vm-make.sh`](rsu-optee-gateway/vm-make.sh), [`rsu-optee-gateway/Makefile`](rsu-optee-gateway/Makefile), [`rsu_node.cpp`](rsu-optee-gateway/host/rsu_node.cpp) | libvirt `virbr0` bridge, 4 `./app rsu` daemons inside VM, Artery `HIL_RPi3_QuadRsu` on host | Provisioned `optee-arm64-vm`, `cap_net_raw=ep` on `opp_run_release`, `virbr0` active | 4 concurrent `rsu[0]`..`rsu[3]` daemon processes inside VM | Mirrors the 4-RSU Manhattan Grid RPi3 HIL setup over the KVM bridge (`virbr0`) without physical RPi3 hardware. |

---

## 2. Architecture & Protocol Foundations

Understanding what each test checks requires tracking **where trust stops** and **which keys move across Normal World vs. Secure World boundaries**.

### 2.1 Actors & Trust Boundaries

1. **Certificate Authority (CA)** (`CertificateAuthority` in [`common/Crypto.h`](common/Crypto.h)):
   - Root P-256 trust anchor (`iiot-root-ca`) issuing X.509 v3 certificates for each RSU Gateway's TEE-generated key (`CY_g`), the ESA (`CY_e`), and the Cloud sink (`CY_cloud`). Both the ESA and every RSU's OP-TEE TA verify peer certificates against the pinned Root CA public key—self-signed or rogue-CA certificates are rejected.

2. **Human Operator (IT Domain)** ([`protocol/HumanOperator.h`](protocol/HumanOperator.h), [`protocol/HumanOperator.cpp`](protocol/HumanOperator.cpp)):
   - Operates strictly in the IT domain with out-of-band knowledge of each vehicle's `(UUID_d, SHA256(fw_d))` and target gateway public key `CY_g`.
   - Initiates Step 1 (`Activation_Request`) directly to the ESA over IT/HTTPS (never over OT radio) with an operator-chosen activation window `[t_0, t_f]`, and receives/validates Step 12 (`Active_03(UUID_d, SHA256(fw_d))`) upon activation completion.

3. **Vehicle / On-Board Unit (OBU)** ([`protocol/VehicleAgent.cpp`](protocol/VehicleAgent.cpp), [`BootstrapClient.cpp`](protocol/BootstrapClient.cpp), [`HandoverClient.cpp`](protocol/HandoverClient.cpp), [`SecureDataClient.cpp`](protocol/SecureDataClient.cpp)):
   - Manufactured via `manufactureVehicle()` ([`common/Traits.cpp`](common/Traits.cpp)) with a random `UUID`, firmware digest `SHA256(f_w)` (derived from `kFirmwareImage = "gateway-firmware v1.0"`), identity $Id_d$, and authenticator $Auth_d$. Never transmits `UUID`, `SHA256(f_w)`, or `Activation_Request` over OT radio, and does not trust the RSU until `Auth_eg == AES(Id_d, CY_e)` verifies in Step 9.
   - Authenticates to its initial RSU over V2X radio (PTP → ECDH → `Auth_Request(OTP_dt)` → `Auth_Granted` → `Active_01`) and transmits encrypted telemetry (`SmartData` JSON, [`common/SmartData.cpp`](common/SmartData.cpp)) authenticated with a sliding-slot Poly1305 One-Time Password (`OTP_dt`).
   - Holds ephemeral ECDH key $(X_V, Y_V)$ across its session so future RSU-to-RSU handovers (**Secrecy Forwarding**, [`common/Handover.cpp`](common/Handover.cpp)) require only symmetric tokens and fresh RSU ephemeral ECDH keys—never re-contacting the ESA.

4. **Roadside Unit (RSU) Gateway** ([`rsu-optee-gateway/`](rsu-optee-gateway)):
   - **Normal World (`host/`)**: [`PacketManager`](rsu-optee-gateway/host/packet_manager.cpp), [`runRsuNode`](rsu-optee-gateway/host/rsu_node.cpp), [`TeeSession`](rsu-optee-gateway/host/tee_session.cpp), [`RawSocket`](net/RawSocket.cpp). Handles Ethernet frames (`0x88b5`/`0x88b6`), fragmentation/reassembly, message queues (`PacketQueue`), and PTP air timestamps. **Assumed untrusted**: never accesses $X_{gw}$, $K_{esa}$, $K_g$, $K_{dg}$, $K_{eg}$, plaintext `Activation_Token` (`Auth_d`/`Auth_eg`), plaintext `Active_02` (`OTP_dt`), or plaintext `SmartData` JSON.
   - **Secure World (`ta/`)**: Arm TrustZone Trusted Application ([`GatewayTaSession`](rsu-optee-gateway/ta/gateway_session.cpp)) running inside OP-TEE (`OPTEE`) or in-process (`HOST_SIM`). Generates Gateway identity keypair $(X_{gw}, CY_g)$ strictly inside Secure World, pins the Root CA, verifies CA-signed Gateway/ESA/Cloud certificates, derives $K_{esa}$, decrypts anonymous `Activation_Token`s, enforces `[t_0, t_f]` + compromised-`Auth_d` exclusion + active-session reboot protection, validates and re-encrypts `Active_01` → `E_{K_{esa}}(Active_02)`, executes OT→IT **Secure Marshaling**, **Secrecy Forwarding**, and sealed persistent storage.

5. **External Security Agent (ESA)** ([`protocol/ExternalSecurityAgent.cpp`](protocol/ExternalSecurityAgent.cpp)):
   - Trusted IT backend holding its CA-signed P-256 certificate ($CY_e$) and CA-authenticated RSU registrations ($CY_g$, mutually-authenticated $K_{esa}$).
   - Accepts `Activation_Request` strictly from `"operator"` (drops any RSU-relayed attempt), seals anonymous `Activation_Token(t_0, t_f, Auth_d, Auth_eg)` under $K_{esa}$, and completes bootstrapping (`Active_02` → `Active_03`) by decrypting under $K_{esa}$, validating $Auth_d$ and $Auth_{de}$, deriving $K_{de}$, and acknowledging `(UUID_d, SHA256(fw_d))` to `HumanOperator`.

6. **Cloud Verification Sink** (`CloudIdentity` in [`common/SmartData.h`](common/SmartData.h), [`BackhaulBroker`](artery-sim/src/BackhaulBroker.cc), [`selftest.cpp`](rsu-optee-gateway/host/selftest.cpp)):
   - Holds a **CA-signed** P-256 X.509 certificate (`CY_cloud`) on address `kCloudAddress = "127.0.0.1"`.
   - The RSU TA verifies the Cloud certificate against the pinned Root CA inside Secure World (`initCloudSession`), generates an ephemeral P-256 session key $(X_s, Y_s)$ every `kMessagesPerSession = 100` packets, attaches base64($Y_s$) as the HTTP `X-Session-Key` header, and encrypts the SmartData JSON under $K_{eg}$ inside the TA. In Artery simulation and HIL, `BackhaulBroker::postToCloud` verifies that the Cloud keypair decrypts every received `ItPacket` cleanly.

7. **Backhaul Transport (`0x88B6` / `BackhaulBroker`)**:
   - Carries IT traffic (`HumanOperator` ↔ `ESA`, encrypted `RSU` ↔ `ESA` `Activation_Token` / `Active_02`, Cloud provisioning & marshaled `ItPacket` delivery) and RSU ↔ RSU handover control (`Forwarding_Notice`, `Handover_Command`, plus HIL `Handover_Trigger` / `Clock_Anchor`). Implemented with `20 ms` simulated latency in `BackhaulBroker`, or Layer-2 Ethernet frames (`kBackhaulEtherType = 0x88B6`) over physical/virtual NICs in HIL.

---

### 2.2 Cryptographic Key Hierarchy & Equations

All elliptic-curve keys use **NIST P-256** (`prime256v1`, `kEcdhCurve = "P-256"`). Symmetric operations ([`common/Crypto.cpp`](common/Crypto.cpp), [`rsu-optee-gateway/ta/crypto_tee.cpp`](rsu-optee-gateway/ta/crypto_tee.cpp)) use **AES-256-GCM** (12 B nonce + ciphertext + 16 B tag for `K_esa`, `K_dg`, `K_eg`), **AES-128-GCM** (`K_g` is `16` bytes, `kGroupKeySize = 16`), **AES-256-ECB + PKCS7** (`aes256Encrypt`), **SHA-256**, and **Poly1305-AES** (`poly1305Aes`: 32-byte key split into a 16-byte AES-128 nonce cipher key `k` and 16-byte Poly1305 key `r`).

#### Manufacturing & Activation Phase
- **Device Identity**:
  $$Id_d = \text{SHA256}(\text{UUID} \parallel \text{SHA256}(f_w))$$
- **Authenticators** (`computeAuthD`, `computeAuthDe`, `computeKDe` in [`common/Traits.cpp`](common/Traits.cpp)):
  $$Auth_d = \text{AES}_{Id_d}(Id_d)$$
  $$Auth_{de} = \text{AES}_{Id_d}(\text{SHA256}(\text{UUID} \parallel \text{SHA256}(f_w) \parallel CY_e))$$
  $$Auth_{eg} = \text{AES}_{Id_d}(CY_e)$$
  - $K_{de} = \text{SHA256}(Id_d \parallel Auth_d \parallel Auth_{de} \parallel OTP_{\text{active}})$: shared vehicle–ESA key bound to the fresh `Active_01` `OTP_dt` (Theorem 2).

#### Secure Bootstrap Phase (Operator ↔ ESA ↔ RSU ↔ Vehicle)
1. **Gateway CA Bootstrapping (Step 2)**: Each RSU TA generates its P-256 identity keypair $(X_{gw}, CY_g)$ strictly inside Secure World (`TA_GATEWAY_CMD_INIT_IDENTITY`). The CA signs the Gateway, ESA, and Cloud certificates. Inside `TA_GATEWAY_CMD_INIT_GATEWAY`, the TA pins the Root CA public key, verifies both Gateway and ESA certificates against the CA, and derives the mutually-authenticated Gateway ↔ ESA channel key inside Secure World:
   $$K_{esa} = \text{SHA256}(\text{ECDH}(X_{gw}, CY_e) \parallel CY_g \parallel CY_e)$$
2. **IT Pre-Activation via Human Operator (Steps 1 & 3)**: `HumanOperator` sends `Activation_Request(CY_g, t_0, t_f, UUID_d, SHA256(fw_d))` directly to the ESA over IT/HTTPS (never over OT radio). ESA verifies `CY_g` is CA-registered, computes `Id_d`, `Auth_d`, `Auth_eg`, and sends `E_{K_{esa}}(Activation_Token(t_0, t_f, Auth_d, Auth_eg))` to the RSU. Normal World passes the opaque ciphertext straight into `TA_GATEWAY_CMD_ADD_ACTIVATION_TOKEN`; the TA decrypts it under $K_{esa}$ and stores the token anonymously (rejecting already-active or previously expired/compromised `Auth_d`).
3. **PTP Time Synchronization (Phase B Prerequisite)**: Vehicle initiates `PTP` to the RSU; RSU replies `PTP_Sync(t_1)`, Vehicle sends `PTP_Delay_Request` ($t_3$), RSU responds `PTP_Delay_Response(t_4)`. Vehicle runs `correctClock` before proceeding.
4. **ECDH Key Agreement (Steps 4 & 5)**: Vehicle sends ephemeral public key $Y_V$ in `ECDH_Request`. RSU TA generates ephemeral $(X_g, Y_g)$, derives $K_{dg} = \text{ECDH}(X_g, Y_V)$ (32 B, kept strictly inside TA; $X_g$ immediately destroyed), and inserts $K_{dg}$ into its unauthenticated pending ECDH pool without touching active sessions.
5. **Mutual Authentication & Group Key (Steps 6–9)**:
   - Vehicle quantizes time into `kOtpTimeStep = 0.1 s` slots ($t_{\text{slot}} = \lfloor t / 0.1 \rfloor$) and sends `Auth_Request(OTP_req)` (strictly omitting `Auth_d`):
     $$OTP_{\text{req}} = \text{Poly1305}(K_{dg}, Auth_d \oplus t_{\text{slot}}, \text{"secure-bootstrap OTP\_dt"})$$
   - RSU TA purges expired pending tokens ($t > t_f \implies Auth_d$ added to compromised blocklist), discards any `Auth_Request` matching an already-active device (preserving the active session), sweeps `(pending K_dg) × (in-window pending Auth_d with t_0 <= t <= t_f) × {t-1, t, t+1}`, activates the device keyed by `Auth_d`, seals Secure Storage (version 3), and computes a **fresh** `Auth_Granted` `OTP_dt` over `{Auth_Granted, K_g, CY_e, Auth_eg}`:
     $$\text{Auth\_Granted} = E_{K_{dg}}(\{OTP_{\text{granted}}, K_g, CY_e, Auth_{eg}\})$$
   - Vehicle decrypts `Auth_Granted`, performs **Level 1** verification (validating fresh $OTP_{\text{granted}}$ under $K_{dg}, Auth_d$ across $t \pm 1$) and **Level 2** verification ($Auth_{eg} == \text{AES}(Id_d, CY_e)$), stores $K_g$ and slot $t_i$, computes $Auth_{de}$, generates a **fresh** `Active_01` `OTP_dt` over `{Active_01, Auth_d, Auth_de}` (distinct from Step 6's plaintext $OTP_{\text{req}}$), derives $K_{de}$, and sends `Active_01` $= E_{K_{dg}}(\{Auth_d, OTP_{\text{active}}, Auth_{de}\})$.
6. **Activation Confirmation (Steps 10–12)**: RSU TA decrypts `Active_01`, verifies `Auth_d` and fresh `OTP_active` inside Secure World (rejecting duplicates and never deleting active sessions on spoofed input), and re-encrypts `Active_02` under $K_{esa}$ before handing it to Normal World. ESA decrypts `E_{K_{esa}}(Active_02)`, verifies `Auth_d`, authorized gateway, and `Auth_de`, derives the matching $K_{de}$, and sends `Active_03(UUID_d, SHA256(fw_d))` to `HumanOperator`.

#### Secure Marshaling (OT → IT)
- Vehicle seals `DataMessage` (`SmartData` payload up to `kMaxSmartDataValue = 65535` B) with AES-128-GCM under $K_g$, authenticates the ciphertext with $OTP_{dt} = \text{Poly1305}(K_{dg}, Auth_d \oplus t_{\text{slot}}, \text{AES}(K_g, \text{Data}))$, and transmits it (optionally wrapped in `Secure_Data`, type `20`).
- Inside `GatewayTaSession::marshal`, the TA:
  1. Verifies $Auth_d$ matches an active session;
  2. Verifies `AES(K_g, Data)` GCM authentication tag;
  3. Verifies `OTP_dt` across the 3-slot tolerance window;
  4. Serializes JSON and encrypts it under Cloud session key $K_{eg} = \text{SHA256}(\text{ECDH}(X_s, Y_e))$;
  5. Emits an HTTP/1.1 `POST /smartdata` buffer with `X-Session-Key: <base64(Y_s)>`, rotating $(X_s, Y_s)$ every `kMessagesPerSession = 100` packets.

#### CTRA Pre-Fetch & Secrecy Forwarding ($G_{i+1} \to G_{i+2}$)
Handover transfers vehicle authentication without exposing $K_{dg}$ to Normal World or subsequent RSU traffic to $G_{i+1}$ ([`common/Handover.cpp`](common/Handover.cpp), [`artery-sim/src/CtraPredictor.cc`](artery-sim/src/CtraPredictor.cc)):
0. *(CTRA Trajectory Prediction — Artery)* Vehicle integrates $X = [x, y, v, \psi, a, \omega]^T$ over `predictionHorizon = 8.0 s` (`predictionStep = 0.1 s`) against all candidate RSUs, identifies the single most likely target RSU $G_{i+2}$ (`minDistance <= 80 m`), and sends `Handover_Predict` `{ targetRsu }` only to its current RSU $G_{i+1}$ (other candidate RSUs are not notified).
1. Source RSU TA ($G_{i+1}$) computes a one-time forwarding token using activation slot $t_i$ and transmits `Forwarding_Notice` `{ Y_V, tau_{i+2}, Auth_d }` exclusively to $G_{i+2}$:
   $$\tau_{i+2} = \text{Poly1305}(K_{dg}, t_i, m)$$
2. Target RSU TA ($G_{i+2}$) generates ephemeral P-256 keypair $(X_G, Y_{G_{i+2}})$ and derives:
   $$K_{dh_i} = \text{ECDH}(X_G, Y_V), \qquad KT_i = \text{Poly1305}(K_{dh_i}, K_{dh_i} \oplus \tau_{i+2}, m)$$
   $$KT_i^{32} = \text{SHA256}(KT_i \parallel K_{dh_i}), \qquad \text{auth}_{i+2} = \text{SHA256}(\tau_{i+2})$$
   Target TA stores $(KT_i^{32}, \text{auth}_{i+2}, K_{dh_i}, Auth_d)$ as a pending handover and replies via $G_{i+1}$ with `Handover_Command` `{ G_{i+2}, Y_{G_{i+2}} }`. With `deferHandover = true`, the vehicle pre-computes and holds $(K_{dh_i}, KT_i^{32}, \text{auth}_{i+2})$ until entering the target handover zone (`handoverRadius = 160 m`).
3. Vehicle computes at current slot $t_c$:
   $$\text{OTP} = \text{Poly1305}(KT_i^{32}, \text{auth}_{i+2} \oplus t_c, m)$$
   and transmits `Forwarding_Request` `{ auth_{i+2}, OTP }` to $G_{i+2}$.
4. $G_{i+2}$ TA (`TA_GATEWAY_CMD_HANDLE_FORWARDING_REQUEST`) validates $\text{auth}_{i+2}$ and `OTP` within the 3-slot window, promotes $K_{dh_i}$ as the vehicle's active $K_{dg}$ paired with $G_{i+2}$'s group key $K_g$, consumes the pending handover (preventing replay), seals Secure Storage, and replies:
   $$\text{Forwarding\_Granted} = E_{KT_i}(\{ Y_{G_{i+3}}, \text{auth}'_{i+2}, K_{G_{i+2}}, \text{OTP} \})$$
   where $\text{auth}'_{i+2} = \text{SHA256}(\text{auth}_{i+2})$. Vehicle verifies `OTP` and $\text{auth}'_{i+2}$ and transitions to $G_{i+2}$'s keys.

---

### 2.3 IEEE 1588 PTP Synchronization & Slotted OTPs

Because `[t_0, t_f]` is only `5.0 s` wide and `OTP_dt` slots step every `0.1 s`, unsynchronized vehicle clocks cause authentication mismatches:
- Vehicle sends `PTP` to initiate sync; RSU replies `PTP_Sync` ($t_1$), vehicle stamps local $t_2$, transmits `PTP_Delay_Request` ($t_3$ stamped on air), and receives `PTP_Delay_Response` ($t_4$).
- `correctClock` computes link delay and clock offset:
  $$\text{delay} = \frac{(t_2 - t_1) + (t_4 - t_3)}{2}, \qquad \text{offset} = \frac{(t_2 - t_1) - (t_4 - t_3)}{2}$$
- Scenario 1 in `selftest.cpp` injects a `+0.25 s` clock skew to verify PTP correction before `ECDH_Request`, and Scenario 6 sets an operator window `[now + 10 s, now + 15 s]` to verify the Gateway TA rejects `Auth_Request` arriving before `t_0`.

---

### 2.4 Wire Protocols, Raw Ethernet Framing & 4-RSU Multiplexing

When bridging physical hardware (RPi3) or the VM (`virbr0`) with Artery ([`net/RawSocket.h`](net/RawSocket.h), [`net/Link.h`](net/Link.h), [`common/ProtocolMsg.h`](common/ProtocolMsg.h)):
- **EtherTypes**:
  - `kRadioEtherType = 0x88B5`: OT radio plane (`Vehicle` ↔ `RSU`)
  - `kBackhaulEtherType = 0x88B6`: IT/Backhaul plane (`RSU` ↔ `ESA` / `RSU` ↔ `RSU` / `Cloud`)
- **Frame Capacity & Fragmentation**:
  - `RawSocket` opens Linux `AF_PACKET` / `SOCK_RAW` (dropping `PACKET_OUTGOING` loopback echoes) with `kMaxFrameData = 1498` bytes payload per Ethernet frame.
  - Payloads larger than `1498` B (such as 65 KB `SmartData` or X.509 PEM certificates) split into `FrameKind::Data_Fragment` chunks reassembled with `kReassemblyTimeout = 2 s`.
- **Control & HIL Multiplexing (`FrameKind`)**:
  - `Protocol`, `Data_Fragment`, `Session_Hello` (`{ rsuName, Y_gw }` generated inside OP-TEE TA), and `Session_Ack` (`{ rsuName, caPublicKey, gatewayCert, esaCert }`) for CA-authenticated startup provisioning.
  - `Handover_Trigger` (`packHandoverTrigger` / `parseHandoverTrigger`): Artery backhaul trigger instructing physical/VM `rsu[0]` to initiate `Forwarding_Notice` toward `rsu[1]`.
  - `Clock_Anchor` (`packClockAnchor` / `parseClockAnchor`): Artery periodically pushes simulation time $t_{\text{sim}}$ so remote RPi3/VM `./app rsu` processes anchor their `steady_clock` (`PacketManager::setClock`) to OMNeT++ `simTime()`, keeping 0.1 s OTP slots and `[t_0, t_f]` windows aligned despite Unix-epoch vs. simulator-time offsets.
  - `Cloud_Ready` / `Cloud_Refused`: Signals when each RSU TA verifies and pins the CA-signed Cloud cert or if Cloud verification rejects an IT packet.

---

## 3. OP-TEE RSU Gateway Architecture (`rsu-optee-gateway/`)

### 3.1 Normal World (`host/`) vs. Secure World (`ta/`)

- **Normal World (`host/`)**:
  - [`host/main.cpp`](rsu-optee-gateway/host/main.cpp) & [`host/modes.h`](rsu-optee-gateway/host/modes.h): Dispatches `[selftest]` or `rsu` daemon mode (`runRsuNode`).
  - [`host/tee_session.h`](rsu-optee-gateway/host/tee_session.h) / [`host/tee_session.cpp`](rsu-optee-gateway/host/tee_session.cpp): `TeeSession` wraps every TA call (`initIdentity`, `initGateway`, `initCloudSession`, `addActivationToken`, `startHandover`, bootstrap/handover handlers, `marshal`).
  - [`host/packet_manager.h`](rsu-optee-gateway/host/packet_manager.h) / [`host/packet_manager.cpp`](rsu-optee-gateway/host/packet_manager.cpp) & [`host/packet_queue.h`](rsu-optee-gateway/host/packet_queue.h): Buffers OT frames into `PacketQueue<OtPacket>`, handles vehicle-initiated `PTP` sync, passes opaque `E_{K_{esa}}(Activation_Token)` into the TA, invokes TA Secure Marshaling, outputs encrypted HTTP POST blobs into `PacketQueue<ItPacket>`, and accepts simulated/anchored clocks (`setClock`).
  - [`host/rsu_node.cpp`](rsu-optee-gateway/host/rsu_node.cpp): Runs `./app rsu`, generating `(X_gw, CY_g)` inside the OP-TEE TA via `initIdentity`, binding `RawSocket` on `0x88b5` and `0x88b6`, completing `Session_Hello` / `Session_Ack` CA provisioning, verifying and pinning the CA-signed Cloud PEM pushed over `0x88b6`, publishing marshaled `ItPacket` blobs back over `0x88b6`, reacting to `Handover_Trigger` / `Clock_Anchor`, and printing `Benchmark` statistics upon exit (`--session-timeout` defaults to `120` s).
  - [`host/benchmark.h`](rsu-optee-gateway/host/benchmark.h) / [`host/benchmark.cpp`](rsu-optee-gateway/host/benchmark.cpp): Collects per-payload-size microsecond timings.
- **Secure World (`ta/`)**:
  - UUID: `TA_GATEWAY_UUID = 9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718` ([`include/gateway_ta.h`](rsu-optee-gateway/include/gateway_ta.h)), built with `TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION` so a single OP-TEE TA instance serves concurrent isolated `GatewayTaSession` contexts (`rsu[0]`..`rsu[3]`).
  - Return codes: `GW_OK = 0`, `GW_IGNORED = 1`, `GW_ERR_ARGS = -1` (plus negative error codes).
  - [`ta/ta_entry.cpp`](rsu-optee-gateway/ta/ta_entry.cpp): GlobalPlatform TA entrypoints and minimal C++17 runtime stubs without `libstdc++`.
  - [`ta/gateway_session.h`](rsu-optee-gateway/ta/gateway_session.h) / [`ta/gateway_session.cpp`](rsu-optee-gateway/ta/gateway_session.cpp): Full TA protocol state machine (TEE-resident `X_gw`, CA-verified `K_esa`, anonymous `Activation_Token` decryption, expired/compromised `Auth_d` blocklist, active-session reboot/DoS protection, 3-slot OTP sweep, fresh `Auth_Granted` & `Active_01` OTPs, `E_{K_{esa}}(Active_02)` re-encryption, `marshal`, Secrecy Forwarding).
  - [`ta/crypto_tee.h`](rsu-optee-gateway/ta/crypto_tee.h) / [`ta/crypto_tee.cpp`](rsu-optee-gateway/ta/crypto_tee.cpp): Uses GP TEE Internal Core API in `OPTEE` mode (`TEE_ALG_ECDH_P256`, `TEE_ALG_ECDSA_P256`, `TEE_ALG_AES_GCM`), RAII `EcdhKeyPair` keeping `X_gw` as an opaque `TEE_ObjectHandle`, RFC 8439 Poly1305, and a freestanding DER/PEM X.509 certificate verifier against the pinned Root CA public key (`verifyCertDerSignedByCa` / `verifyCertPemSignedByCa`).
  - [`ta/codec.h`](rsu-optee-gateway/ta/codec.h) / [`ta/codec.cpp`](rsu-optee-gateway/ta/codec.cpp): Binary codec across Normal/Secure World buffers.

### 3.2 `HOST_SIM` Mode vs. `OPTEE` Hardware Mode

- **`TEE_MODE=HOST_SIM`** (default on x86_64 host and inside Artery): Compiles `ta/*.cpp` into `./app` or `libtee_v2x_protocol.a` with OpenSSL 3 crypto and host-encrypted disk sealing (`gateway.sealed`), preserving exact `TaGatewayCommand` wire boundaries.
- **`TEE_MODE=OPTEE`** (`-DUSE_OPTEE`): Compiles `ta/*.cpp` into `9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta` and links `./app` against `-lteec` (`<tee_client_api.h>`) to talk to real TrustZone `/dev/tee0` and `tee-supplicant`.

### 3.3 Secure Storage & State Persistence

Whenever `Auth_Granted`, `Active_01`, or `Forwarding_Granted` updates active vehicle state, the TA seals its 16-byte group key $K_g$ and `Auth_d`-keyed active session table (format version `3`) into persistent storage (`TEE_STORAGE_PRIVATE` on RPi3; `--sealed <id>` file such as `gateway.sealed` in `HOST_SIM`). Pass `--fresh` to wipe prior sealed state on startup.

---

## 4. Suite 1: OP-TEE Gateway Security Self-Test (`make run` / `./app`)

### 4.1 Purpose & Requirements

- **Command**: `make run` (or `make test`, or directly `./rsu-optee-gateway/app [selftest] [--sealed <id>] [--fresh]`)
- **Primary File**: [`rsu-optee-gateway/host/selftest.cpp`](rsu-optee-gateway/host/selftest.cpp)
- **Requirements**: `g++` (C++17) + OpenSSL 3 (`HOST_SIM`), or `/dev/tee0` + `tee-supplicant` + `.ta` (`OPTEE` on RPi3). Takes ~**0.5 seconds** (Scenario 3 uses a `0.3 s` operator window and sleeps `0.4 s`).

### 4.2 Scenario-by-Scenario Deep Dive (`1`–`7`, `4a`–`4m`, `7a`–`7d`)

Upon startup, `selftest` creates a Root CA (`iiot-root-ca`), an `ExternalSecurityAgent(ca)`, a `HumanOperator("operator")`, and a CA-signed `CloudIdentity(ca)` (`/CN=127.0.0.1`), opens TA session 1 (`rsu[0]`), generates `rsu[0]`'s identity keypair inside the TA (`initIdentity`), certifies it via the CA, registers it with the ESA, and runs `initGateway` + `initCloudSession`:

1. **`1. normal (Operator + CA + Theorem 2)`** (`node[0]`, `seed=1`, `+0.25 s` clock skew): Runs Phase A via `HumanOperator` in IT and Phase B/C over OT radio (correcting `+0.25 s` skew via PTP). Asserts: `vehicleReady`, `HumanOperator` verified `Active_03`, **zero** OT radio transmission of `Activation_Request`/`UUID_d`/`SHA256(fw_d)`, **zero** plaintext `Auth_d`/`OTP_active` in `Activation_Token`/`Active_02` backhaul frames, `OTP_active != OTP_auth_req` (Theorem 2), and `Vehicle K_de == ESA K_de`.
2. **`2. OTP changed on the air (rejected by OP-TEE TA)`** (`node[1]`, `seed=7`): Flips a bit inside `Auth_Request` in flight; TA sweeps all pending combinations across 3 slots and rejects (`ignored: 1`).
3. **`3. Auth_Request after t_f (expired & marked compromised by OP-TEE TA)`** (`node[2]`, `seed=11`): Operator sets a `0.3 s` window and `Auth_Request` is delayed `0.4 s`; TA detects `t > t_f`, purges the pending record, adds `node[2]`'s `Auth_d` to its compromised exclusion blocklist, and ignores the request (`ignored: 1`).
4. **`4. Secure Marshaling (OT -> IT) + Secrecy Forwarding handover (node[5]: rsu[0] -> rsu[1])`**:
   - **Part A — Secure Marshaling (`4a`–`4g`)**: Runs on active `node[0]` (`rsu[0]`), verifying 32 B and 64 KB−1 marshaling, tampered `OTP_dt`, tampered `AES(K_G, Data)` caught by GCM tag, unknown `Auth_d`, out-of-window `t`, and Cloud `K_eg` rotation at packet 100.
   - **Part B — Secrecy Forwarding (`4h`–`4m`)**: Opens a **second isolated TA session** (`gateway.sealed.rsu1`) provisioned via CA for `rsu[1]`, bootstraps a distinct vehicle `node[5]` (`seed=5`) via `HumanOperator` on `rsu[0]` (preserving `node[0]`'s active session on `rsu[0]`), marshals SmartData to `rsu[0]`, hands over to `rsu[1]` via Secrecy Forwarding, marshals SmartData to `rsu[1]`, rejects replayed `Forwarding_Request`, and rejects `rsu[0]`-sealed packets at `rsu[1]`.
5. **`5. CY_g of no CA-registered gateway (node[3])`** (`seed=13`): Operator names an unregistered rogue `CY_g`; ESA drops it, no token is issued, and `rsu[0]` TA ignores `node[3]`'s `Auth_Request` (`ignored: 1`).
6. **`6. before t_0: Operator window opens 10 s later (node[4])`** (`seed=17`): Operator sets `[now + 10 s, now + 15 s]`; `node[4]` syncs via PTP and sends `Auth_Request` before `t_0` → **Gateway TA** enforces `t_0 <= now <= t_f` and ignores it (`ignored: 1`).
7. **`7. Reboot/DoS protection, CA PKI & HIL 4-RSU checks (`7a`–`7d`)`**:
   - `7a. post-t_f DoS & reboot protection`: Injects spoofed `ECDH_Request`, `Auth_Request`, and `Active_01` naming active `node[0]` 100 s in the future plus a valid reboot `Auth_Request` signed with `node[0]`'s keys; verifies TA discards them (`GW_IGNORED`) **without evicting `node[0]`**, confirmed by marshaling fresh `SmartData` from `node[0]` (`GW_OK`).
   - `7b. active & expired Auth_d excluded`: Re-submitting `Activation_Token` for already-active `node[0]` or expired/compromised `node[2]` is rejected (`GW_IGNORED`).
   - `7c. CA PKI & operator-only Step 1`: Verifies ESA rejects self-signed Gateway certs and drops `Activation_Request` sent by an RSU instead of `"operator"`; verifies TA rejects self-signed ESA certs and self-signed Cloud certs (`GW_ERR_CRYPTO`).
   - `7d. HIL wire helpers & 4 TA sessions`: Verifies `Session_Hello`/`Session_Ack`, `HandoverTrigger`, `ClockAnchor`, `RsuTag`, `PTP` with `PacketManager::setClock`, and concurrent CA provisioning of `rsu[2]` and `rsu[3]`.

### 4.3 Observed Terminal Output

Running `make clean && make run` exited with code `0` and ended with:

```text
  7a. post-t_f DoS & reboot protection   spoofed/reboot Auth_Request discarded; node[0] stayed active   ok
  7b. active & expired Auth_d excluded   both active and expired/compromised Auth_d rejected (GW_IGNORED)   ok
  7c. CA PKI & operator-only Step 1      self-signed GW/ESA/Cloud certs & RSU-relayed Activation_Request rejected   ok
  7d. HIL wire helpers & 4 TA sessions   Session_Hello/Ack, HandoverTrigger, ClockAnchor, PTP & 4 RSUs OK   ok

results:
  1. normal (Operator + CA + Theorem 2)  vehicle: yes  operator Active_03: yes  ignored: 0   ok
  2. OTP changed on the air              vehicle: no   operator Active_03: no   ignored: 1   ok
  3. Auth_Request after t_f              vehicle: no   operator Active_03: no   ignored: 1   ok
  4. handover rsu[0] -> rsu[1]           Secure Marshaling (4a-4g): ok, Secrecy Forwarding (4h-4m): ok   ok
  5. CY_g of no gateway                  vehicle: no   operator Active_03: no   ignored: 1   ok
  6. before t_0 (TA enforced)            vehicle: no   operator Active_03: no   ignored: 1   ok
  7. security & HIL checks (7a-7d)       Reboot/DoS, CA PKI, Operator-only & HIL helpers   ok
gateway OK
```

---

## 5. Suite 2: Raspberry Pi 3 TrustZone & 4-RSU HIL Daemon (`./app rsu`)

### 5.1 Cross-Compilation & Deployment (`build-rpi3.sh`)

- **Command**: `make rpi3 [PI_IP=<ip>]` (invokes [`rsu-optee-gateway/build-rpi3.sh`](rsu-optee-gateway/build-rpi3.sh))
- **Pipeline**:
  1. Builds `ta/9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta` for Cortex-A53 (`-mcpu=cortex-a53`).
  2. Patches ELF header `EI_OSABI` to `0x00` and signs/encrypts the `.ta` with OP-TEE `sign_encrypt.py` (`default_ta.pem`).
  3. Cross-compiles `./app` linked with `-lteec` (`TEE_MODE=OPTEE`).
  4. If `PI_IP` is set, uploads the signed `.ta` into OP-TEE's TA store and `/root/app` via `scp`/`ssh`.

### 5.2 4-RSU Hardware Launcher (`rsu-quad-ssh.sh`)

```bash
./rsu-quad-ssh.sh --pi-ip <ip> [--rsu-iface <iface>] [--session-timeout <sec>] [--keep-state] [--remote-app <path>]
```

- Launches **4 concurrent `/root/app rsu` daemons** over SSH on the Raspberry Pi 3 (one per Manhattan Grid edge):
  1. `rsu[0]` (West edge) → OP-TEE TA session #1, Secure Storage ID `rsu0.sealed`
  2. `rsu[1]` (North edge) → OP-TEE TA session #2, Secure Storage ID `rsu1.sealed`
  3. `rsu[2]` (East edge) → OP-TEE TA session #3, Secure Storage ID `rsu2.sealed`
  4. `rsu[3]` (South edge) → OP-TEE TA session #4, Secure Storage ID `rsu3.sealed`
- All 4 bind to `--rsu-iface` (default `eth0`), sharing one NIC via EtherTypes `0x88b5` (radio) and `0x88b6` (backhaul).

### 5.3 Embedded Gateway Latency Reporting (`Benchmark`)

When each `./app rsu` instance exits cleanly (timeout or signal), [`Benchmark::print`](rsu-optee-gateway/host/benchmark.cpp) prints per-payload-size statistics (`average (min-max)` in microseconds):
1. **`TA Invoke`**: Secure-World `GatewayTaSession::marshal` execution time (AES-128-GCM decrypt + 3-slot `OTP_dt` check + JSON format + AES-256-GCM encrypt + HTTP assembly, including ARM TrustZone SMC overhead on RPi3).
2. **`OT -> IT queue`**: End-to-end OT queue through TA marshaling to IT queue placement.
3. **`radio -> cloud`**: Full Normal-World frame reassembly through TA marshaling and backhaul enqueue.

---

## 6. Suite 3: Complementary VM Workflow (`setup-vm.sh`, `make vm`, `make vm-hil`)

### 6.1 VM Provisioning (`setup-vm.sh`)

- Creates or reuses an Ubuntu 24.04 x86_64 libvirt/KVM domain named **`optee-arm64-vm`** (`setup-vm.sh [--recreate]`), attached to the libvirt `default` bridge (`virbr0`).
- Installs ARM64 cross-compilers and `qemu-system-arm`, and builds `optee_os` (`PLATFORM=vexpress-qemu_armv8a`, `ta_dev_kit`) and `optee_client` (`libteec`) in `/opt/optee` (`/etc/profile.d/optee.sh`).

### 6.2 Self-Test & Bridged 4-RSU HIL (`vm-make.sh`, `make vm-hil`)

- **`make vm`**: Starts `optee-arm64-vm`, `rsync`s the repository into the VM via [`rsu-optee-gateway/vm-make.sh`](rsu-optee-gateway/vm-make.sh), sources `/etc/profile.d/optee.sh`, and runs `make -C rsu-optee-gateway run` (or custom `VM_ARGS`).
- **`make vm-hil`**: Syncs the repo, grants `cap_net_raw=ep` (`make caps`), and runs `make hil-quad` inside `optee-arm64-vm` (launching 4 concurrent `rsu[0]`..`rsu[3]` processes bound to the VM's libvirt NIC). Pair with `make hil-quad HIL_IFACE=virbr0` on the host PC to execute the exact same 4-RSU Artery HIL Layer-2 flow without physical RPi3 hardware.

---

## 7. Suite 4: Artery / OMNeT++ / SUMO V2X Simulations (`artery-sim/`)

### 7.1 Build Setup (`setup_artery.sh`)

[`artery-sim/setup_artery.sh`](artery-sim/setup_artery.sh) automates 5 setup steps inside `artery-sim/deps/`:
1. Downloads and builds **OMNeT++ 5.7.1**.
2. Clones and registers `scenarios/tee_v2x_handover` inside **Artery** (`riebl/artery` with INET, Veins/TraCI, and Vanetza).
3. Verifies **SUMO** installation.
4. Configures CMake and builds `tee_v2x` (`libartery_tee_v2x.so`).
5. Summarizes available run commands (`D250m_80211p` and `HIL_RPi3_QuadRsu`).

### 7.2 Road Topology, SUMO Mobility & Custom Modules

- **SUMO Mobility** ([`highway.sumocfg`](artery-sim/scenario/highway.sumocfg), [`highway.net.xml`](artery-sim/scenario/highway.net.xml), [`highway.rou.xml`](artery-sim/scenario/highway.rou.xml)): **400 m × 400 m 3×3 Manhattan Grid**; vehicle `v0` (`node[0]`) enters on `w_0` moving at **`20 m/s`** along route `manhattan_loop` (`w_0 w_1 n_0 n_1 e_0 e_1 s_0 s_1`) and traverses all 4 perimeter edges within `sim-time-limit = 85 s`.
- **Network** ([`HighwayHandover.ned`](artery-sim/scenario/HighwayHandover.ned), `numRoadSideUnits = 4`):
  - `rsu[0]` (West edge) at `(10 m, 200 m, 10 m)` → OP-TEE TA session #1 (`rsu0.sealed`)
  - `rsu[1]` (North edge) at `(200 m, 10 m, 10 m)` → OP-TEE TA session #2 (`rsu1.sealed`)
  - `rsu[2]` (East edge) at `(390 m, 200 m, 10 m)` → OP-TEE TA session #3 (`rsu2.sealed`)
  - `rsu[3]` (South edge) at `(200 m, 390 m, 10 m)` → OP-TEE TA session #4 (`rsu3.sealed`)
  - `backhaulBroker` ([`BackhaulBroker`](artery-sim/src/BackhaulBroker.cc), `latency = 20 ms`) hosting the Root CA (`CertificateAuthority`), `HumanOperator`, ESA (`ExternalSecurityAgent`), and Cloud verification (`cloudStored`, `cloudRefused`, `operatorConfirmations`, `cloudJsonBytes`).
- **Artery Services** ([`artery-sim/src/`](artery-sim/src)):
  - [`CtraPredictor.h`](artery-sim/src/CtraPredictor.h) / [`CtraPredictor.cc`](artery-sim/src/CtraPredictor.cc): Constant Turn Rate and Acceleration (CTRA) trajectory predictor ($X = [x, y, v, \psi, a, \omega]^T$) evaluating future vehicle positions (`predictionHorizon = 8.0 s`, `predictionStep = 0.1 s`) against all candidate RSUs to select the single most likely next RSU (`predictRadius = 80 m`) and trigger `Forwarding_Request` once within `handoverRadius = 160 m`.
  - [`V2xFrame.h`](artery-sim/src/V2xFrame.h): Wraps `ProtocolMsg` packets in Vanetza BTP (`port 2025`; `DP0` for pre-ECDH `PTP`/`PTP_Delay_Request`/`ECDH_Request`, `DP2` for `Auth_Request`, 10 Hz `Secure_Data`, `Handover_Predict`, and `Forwarding_Request`).
  - [`VehicleTeeService.cc`](artery-sim/src/VehicleTeeService.cc): Runs `VehicleAgent` (`BootstrapClient`, `HandoverClient`, `SecureDataClient`) with `CtraPredictor` (`firstRsu = "rsu[0]"`, `startDelay = 0.5 s` triggers Phase A `HumanOperator` IT pre-activation followed `+100 ms` later by Phase B OT bootstrap, `dataInterval = 100 ms`, `dataSize = 200 B`).
  - [`TeeRsuService.cc`](artery-sim/src/TeeRsuService.cc):
    - When `enableHil = false` (`D250m_80211p`), creates an isolated host `TeeSession` + `PacketManager` per RSU, generating `(X_gw, CY_g)` inside the TA and provisioning CA-signed certs via `BackhaulBroker`.
    - When `enableHil = true` (`HIL_RPi3_QuadRsu`), `initHil()` does not instantiate local `TeeSession` or `PacketManager` objects; Artery acts solely as an `AF_PACKET` bridge (`0x88b5` / `0x88b6`) polled every `1 ms`.

### 7.3 Simulation Configurations (`omnetpp.ini`)

1. **`D250m_80211p` & `D250m_80211p_GUI`**:
   - Pure IEEE 802.11p ITS-G5 (5.9 GHz ch 180, 10 MHz bandwidth, 6 Mbps bitrate, 200 mW TX power) over the 4-RSU Manhattan Grid with CTRA trajectory prediction (`nextRsu = ""`, no broadcast pre-fetch). Run via `make sim` (`D250m_80211p`).
2. **`HIL_RPi3_QuadRsu` (+ `HIL_RPi3_QuadRsu_GUI`)**:
   - Sets **`*.rsu[*].middleware.TeeRsuService.enableHil = true`** so **all 4 RSUs (`rsu[0]`..`rsu[3]`)** reside in 4 isolated OP-TEE TA sessions on the physical Raspberry Pi 3 (or `virbr0` VM), launched under **`--scheduler-class=omnetpp::cRealTimeScheduler`**.
   - Run via `make hil-quad HIL_IFACE=<nic> [GUI=1]` or `./artery-sim/run-hil-quad.sh --iface <nic> [--gui] [--rebuild]`.
   - Fails fast with an explicit error if `HIL_IFACE` / `hilIface` is omitted (`rsu[0]: HIL enabled but no host interface specified...`).

### 7.4 Observed `D250m_80211p` Trace & Scalar Results

Running `D250m_80211p` with `opp_run_release` reached `t = 85 s` (`Event #43987`, elapsed `1.067 s`, exit code `0`) and wrote [`D250m_80211p-0.sca`](artery-sim/scenario/results/D250m_80211p-0.sca) with:
- **Vehicle (`HighwayHandover.node[0].middleware.VehicleTeeService`)**:
  - `bootstrapped`: `1` (`bootstrapDelay:last = 0.062043418192 s`)
  - `ctraPredictionsSent`: `3`, `prefetchesCompleted`: `3` (`prefetchLeadTimeMs:last = 3659.430674597 ms`)
  - `handovers`: `3` (`rsu[0] → rsu[1] → rsu[2] → rsu[3]`, `handoverE2EDelayMs:last = 0.823067718 ms`)
  - `secureDataSent`: `842` (`220` to `rsu[0]`, `239` to `rsu[1]`, `239` to `rsu[2]`, `144` to `rsu[3]`)
- **RSUs (`TeeRsuService`)**:
  - `rsu[0]`: `marshaledPackets = 220`, `marshalRefused = 0`, `teeIgnored = 0`, `handoversTriggered = 1`, `handoversGranted = 0`
  - `rsu[1]`: `marshaledPackets = 239`, `marshalRefused = 0`, `teeIgnored = 0`, `handoversTriggered = 1`, `handoversGranted = 1`
  - `rsu[2]`: `marshaledPackets = 239`, `marshalRefused = 0`, `teeIgnored = 0`, `handoversTriggered = 1`, `handoversGranted = 1`
  - `rsu[3]`: `marshaledPackets = 144`, `marshalRefused = 0`, `teeIgnored = 0`, `handoversTriggered = 0`, `handoversGranted = 1`
- **Backhaul, Operator & Cloud (`HighwayHandover.backhaulBroker`)**:
  - `backhaulDelivered`: `10` (4 initial bootstrap IT messages: `Activation_Request` Operator→ESA, `E_{K_{esa}}(Activation_Token)` ESA→RSU, `E_{K_{esa}}(Active_02)` RSU→ESA, `Active_03` ESA→Operator + 3 × `Forwarding_Notice` / `Handover_Command` pairs), `backhaulUndeliverable`: `0`, `operatorConfirmations`: `1`
  - `cloudStored`: `842` (`cloudRefused = 0`, `cloudJsonBytes:sum = 366561`)
