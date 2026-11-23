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
   - [4.1 Purpose, Requirements & Flags](#41-purpose-requirements--flags)
   - [4.2 Scenario-by-Scenario Deep Dive (`1`–`7`, `4a`–`4m`, `7a`–`7e`)](#42-scenario-by-scenario-deep-dive-17-4a4m-7a7e)
   - [4.3 Observed Terminal Output](#43-observed-terminal-output)
5. [Suite 2: Raspberry Pi 3 TrustZone & 4-RSU HIL Daemon (`./app rsu`)](#5-suite-2-raspberry-pi-3-trustzone--4-rsu-hil-daemon-app-rsu)
   - [5.1 Cross-Compilation & Deployment (`build-rpi3.sh`)](#51-cross-compilation--deployment-build-rpi3sh)
   - [5.2 4-RSU Hardware Launcher (`rsu-quad-ssh.sh` & `./app rsu`)](#52-4-rsu-hardware-launcher-rsu-quad-sshsh--app-rsu)
   - [5.3 Embedded Gateway Latency Reporting (`Benchmark`)](#53-embedded-gateway-latency-reporting-benchmark)
6. [Suite 3: Complementary VM Workflow (`setup-vm.sh`, `make vm`, `make vm-hil`)](#6-suite-3-complementary-vm-workflow-setup-vmsh-make-vm-make-vm-hil)
   - [6.1 VM Provisioning (`setup-vm.sh`)](#61-vm-provisioning-setup-vmsh)
   - [6.2 Self-Test & Bridged 4-RSU HIL (`vm-make.sh`, `make vm-hil`)](#62-self-test--bridged-4-rsu-hil-vm-makesh-make-vm-hil)
7. [Suite 4: CrowNet 5G NR (OMNeT++ 6.3 + Artery + Simu5G + SUMO) V2X Simulations (`artery-sim/`)](#7-suite-4-crownet-5g-nr-omnet-63--artery--simu5g--sumo-v2x-simulations-artery-sim)
   - [7.1 Build Setup (`setup_artery.sh`)](#71-build-setup-setup_arterysh)
   - [7.2 5G NR Topology, SUMO Mobility & Custom Modules](#72-5g-nr-topology-sumo-mobility--custom-modules)
   - [7.3 Simulation Configurations (`omnetpp.ini`) & Run Flags](#73-simulation-configurations-omnetppini--run-flags)
   - [7.4 Observed `NR_5G` Trace & Scalar Results](#74-observed-nr_5g-trace--scalar-results)
   - [7.5 Observed Physical RPi3 5G NR `HIL_RPi3_QuadRsu` Results](#75-observed-physical-rpi3-5g-nr-hil_rpi3_quadrsu-results)
   - [7.6 Academic V2X Evaluation Metrics & CSV Exports](#76-academic-v2x-evaluation-metrics--csv-exports)

---

## 1. Test & Simulation Matrix

| Test / Configuration | Command | Primary Files | Frameworks & Tech | Key Requirements | TEE Role | What It Verifies |
|---|---|---|---|---|---|---|
| **OP-TEE Gateway Self-Test** | `make run [OTP=ascon\|poly1305]` (or `./rsu-optee-gateway/app [--otp ascon\|poly1305] [--sealed <id>] [--fresh]`) | [`rsu-optee-gateway/host/selftest.cpp`](rsu-optee-gateway/host/selftest.cpp), [`rsu-optee-gateway/ta/`](rsu-optee-gateway/ta) | C++17, OpenSSL 3 (`HOST_SIM`) or `libteec` + `.ta` (`OPTEE`) | C++17 + OpenSSL 3 on Linux (`HOST_SIM`); `/dev/tee0` + `tee-supplicant` + signed `.ta` (`OPTEE`). Takes ~0.5 s | Full TA isolation (`GatewayTaSession`, `ta_crypto`, CA verification, `K_esa`, `K_rsu`, Secure Storage) | Scenarios `1`–`7` + subtests `4a`–`4m` & `7a`–`7e`: Operator-initiated IT bootstrap (zero OT leak of `UUID_d`/`SHA256(fw_d)`), CA-authenticated `K_esa` & pairwise peer `K_rsu` sealing, fresh per-step `OTP_dt` (Theorem 2), tampered OTP, expired window `[t_0, t_f]` + compromised `Auth_d` exclusion, early arrival `< t_0` enforced in TA, rogue `CY_g`, OT→IT Secure Marshaling, Cloud session rotation, CTRA + encrypted `Handover_Predict` / `K_rsu`-sealed `Forwarding_Notice` handover + replay/fan-out/rate-limit/cross-RSU rejection, post-`t_f` DoS & reboot protection, CA PKI rejection, and HIL shared-link helpers. |
| **CrowNet 5G NR Simulation** | `make sim [OTP=ascon\|poly1305] [GUI=1]` (or `./artery-sim/run-sim.sh [--config NR_5G\|NR_5G_GUI] [--otp ...] [--gui] [--rebuild]`) | [`artery-sim/scenario/omnetpp.ini`](artery-sim/scenario/omnetpp.ini), [`HighwayHandover.ned`](artery-sim/scenario/HighwayHandover.ned), [`CtraPredictor.cc`](artery-sim/src/CtraPredictor.cc), [`artery-sim/src/`](artery-sim/src) | CrowNet (OMNeT++ 6.3.0, INET 4, Veins, Artery, Simu5G 5G NR), host SUMO 1.26.0, TA (`HOST_SIM`) | Docker image `v2x-crownet:6.3.0`, CrowNet `.so` libs & `libtee_v2x.so` (`artery-sim/setup_artery.sh`), host `sumo` | Each of the 4 simulated RSUs (`rsu[0]`..`rsu[3]`) owns an isolated host `TeeSession` | **400 m × 400 m 3×3 Manhattan Grid** (`85 s`, `20 m/s`), **5G NR** (`3.5 GHz` n78, $\mu=1$, `25 RBs`, 4 `gNodeB`s + X2 handover + `UPF` + `Router`), vehicle bootstrapping (`rsu[0]`), 10 Hz SmartData over 5G NR UDP/IP, purely kinematic **CTRA** trajectory prediction + selective single-RSU pre-fetch (`Handover_Predict`), 3 live 5G NR X2 radio handovers (`gNB[0] → gNB[1] → gNB[2] → gNB[3]`), and 3 Secrecy Forwarding handovers (`rsu[0] → rsu[1] → rsu[2] → rsu[3]`). |
| **4-RSU Raspberry Pi 3 5G NR HIL** | `make rpi3 PI_IP=<ip>` + `./rsu-quad-ssh.sh --pi-ip <ip> [--otp ...]` + `make hil-quad HIL_IFACE=<nic> [OTP=...] [GUI=1]` | [`rsu-optee-gateway/build-rpi3.sh`](rsu-optee-gateway/build-rpi3.sh), [`rsu-quad-ssh.sh`](rsu-quad-ssh.sh), [`artery-sim/run-hil-quad.sh`](artery-sim/run-hil-quad.sh), [`artery-sim/run-sim.sh`](artery-sim/run-sim.sh), [`rsu_node.cpp`](rsu-optee-gateway/host/rsu_node.cpp), [`TeeRsuService.cc`](artery-sim/src/TeeRsuService.cc) | AArch64 RPi3 OP-TEE OS + `tee-supplicant` + `/dev/tee0` (`TA_FLAG_MULTI_SESSION`), CrowNet (OMNeT++ 6.3 `cRealTimeScheduler`, Artery, Simu5G 5G NR), host SUMO 1.26.0, `AF_PACKET` (`0x88b5`/`0x88b6`) | RPi3 wired via Ethernet to `<nic>`, Docker (`--network=host --cap-add=NET_RAW`), `v2x-crownet:6.3.0` (`cap_net_raw+ep` on `opp_run_release`), RPi3 `.ta` + `./app` | All 4 RSUs (`rsu[0]`..`rsu[3]`, `rsu0.sealed`..`rsu3.sealed`) run concurrently inside OP-TEE on RPi3 | Real-time simulated 5G NR Manhattan Grid vehicle (`ApplicationLayerVehicle`) with purely kinematic CTRA predictor, 4 gNodeBs + UPF + Router, ESA, and Cloud (`BackhaulBroker`) exchanging bootstrap, 10 Hz SmartData marshaling, selective pre-fetch, and TrustZone-to-TrustZone Secrecy Forwarding over physical Ethernet. |
| **VM Self-Test (`optee-arm64-vm`)** | `./setup-vm.sh [--recreate]` + `make vm [OTP=ascon\|poly1305]` | [`setup-vm.sh`](setup-vm.sh), [`rsu-optee-gateway/vm-make.sh`](rsu-optee-gateway/vm-make.sh) | libvirt/KVM Ubuntu 24.04 VM, `optee_os` `vexpress-qemu_armv8a` DevKit, `optee_client` | KVM/libvirt on host PC, `rsync`, `ssh`, internet during provisioning | Same `./app` build/self-test flow inside `optee-arm64-vm` | Reproducible VM sandbox with ARM64 cross-compilers, OP-TEE DevKit, and `libteec` in `/opt/optee`. |
| **VM Bridged 4-RSU HIL** | `make vm-hil [OTP=ascon\|poly1305]` + `make hil-quad HIL_IFACE=virbr0 [OTP=...] [GUI=1]` | [`Makefile`](Makefile), [`rsu-optee-gateway/vm-make.sh`](rsu-optee-gateway/vm-make.sh), [`rsu-optee-gateway/Makefile`](rsu-optee-gateway/Makefile), [`rsu_node.cpp`](rsu-optee-gateway/host/rsu_node.cpp) | libvirt `virbr0` bridge, 4 `./app rsu` daemons inside VM, Artery `HIL_RPi3_QuadRsu` on host | Provisioned `optee-arm64-vm`, `cap_net_raw=ep` on `opp_run_release`, `virbr0` active | 4 concurrent `rsu[0]`..`rsu[3]` daemon processes inside VM | Mirrors the 4-RSU Manhattan Grid RPi3 HIL setup over the KVM bridge (`virbr0`) without physical RPi3 hardware. |

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
   - Carries IT traffic (`HumanOperator` ↔ `ESA`, encrypted `RSU` ↔ `ESA` `Activation_Token` / `Active_02`, Cloud provisioning & marshaled `ItPacket` delivery), CA-signed RSU peer certificate exchange (`Peer_Cert` / `Peer_Cert_Ack` in HIL; `BackhaulBroker::PeerCertCallback` in Artery), and RSU ↔ RSU handover control ($K_{rsu}$-sealed `Forwarding_Notice`, plus HIL `Clock_Anchor`). Implemented with `20 ms` simulated latency in `BackhaulBroker`, or Layer-2 Ethernet frames (`kBackhaulEtherType = 0x88B6`) over physical/virtual NICs in HIL.

---

### 2.2 Cryptographic Key Hierarchy & Equations

All elliptic-curve keys use **NIST P-256** (`prime256v1`, `kEcdhCurve = "P-256"`). Symmetric operations ([`common/Crypto.cpp`](common/Crypto.cpp), [`rsu-optee-gateway/ta/crypto_tee.cpp`](rsu-optee-gateway/ta/crypto_tee.cpp)) use **AES-256-GCM** (12 B nonce + ciphertext + 16 B tag for `K_esa`, `K_dg`, `K_eg`), **AES-128-GCM** (`K_g` is `16` bytes, `kGroupKeySize = 16`), **AES-256-ECB + PKCS7** (`aes256Encrypt`), **SHA-256**, and a **single run-wide OTP/MAC algorithm** ([`common/Otp.h`](common/Otp.h), selected via `--otp ascon|poly1305` or `OTP=ascon|poly1305`, never mixed):
- **`ascon`** *(default)*: **Ascon-AEAD128 / Ascon-Hash256** (NIST SP 800-232, portable [`common/Ascon.cpp`](common/Ascon.cpp) + [`common/Otp.cpp`](common/Otp.cpp), identical code on host and inside OP-TEE TA) with domain-separated per-purpose 16-byte keys $K_{otp} = \text{Ascon-Hash256}(\text{label}(\text{purpose}) \parallel 0\text{x}00 \parallel K)[0..16]$ for all 9 OTP/MAC steps (`Auth_Request`, `Auth_Granted`, `Active_01`, `Secure_Data`, `Handover_Predict`, $\tau_{i+2}$, $KT_i$, `Forwarding_Request`, `Forwarding_Granted`).
- **`poly1305`**: **Poly1305-AES** (`poly1305Aes`: 32-byte key split into a 16-byte AES-128 nonce cipher key `k` and 16-byte Poly1305 key `r`) for all 9 OTP/MAC steps.

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
   - Vehicle quantizes time into `kOtpTimeStep = 0.5 s` slots ($t_{\text{slot}} = \lfloor t / 0.5 \rfloor$) and sends `Auth_Request(OTP_req)` (strictly omitting `Auth_d`):
     $$OTP_{\text{req}} = \text{MAC}(K_{dg}, Auth_d \oplus t_{\text{slot}}, \text{"secure-bootstrap OTP\_dt"})$$
     Every OTP/MAC across bootstrap, SmartData marshaling, and Secrecy Forwarding uses the single algorithm chosen via `--otp ascon` (Ascon-AEAD128 with per-purpose $K_{otp}$ via [`common/Otp.cpp`](common/Otp.cpp)) or `--otp poly1305` (Poly1305-AES), propagated to both host and OP-TEE TA (`TA_GATEWAY_CMD_SET_STORAGE_ID` and HIL `Session_Ack`).
   - RSU TA purges expired pending tokens ($t > t_f \implies Auth_d$ added to compromised blocklist), discards any `Auth_Request` matching an already-active device (preserving the active session), sweeps `(pending K_dg) × (in-window pending Auth_d with t_0 <= t <= t_f) × {t-1, t, t+1}`, activates the device keyed by `Auth_d` (keeping activation slot $t_i$ strictly volatile in TA RAM), seals Secure Storage (version 3, writing `0` for `authTime`), advances the clock across `saveState()` via `ta_crypto::monotonicTimeMs()` (`TEE_GetSystemTime` in OP-TEE), and computes a **fresh** `Auth_Granted` `OTP_dt` at the actual send-time slot over `{Auth_Granted, nextRsus, K_g, CY_e, Auth_eg}` (where `nextRsus` pre-loads up to `kMaxNeighborRsus = 4` CA-verified peer `{G, CY_G}` keys):
     $$\text{Auth\_Granted} = E_{K_{dg}}(\{OTP_{\text{granted}}, \text{nextRsus}, K_g, CY_e, Auth_{eg}\})$$
   - Vehicle decrypts `Auth_Granted`, performs **Level 1** verification (validating fresh $OTP_{\text{granted}}$ under $K_{dg}, Auth_d$ across $t \pm 1$) and **Level 2** verification ($Auth_{eg} == \text{AES}(Id_d, CY_e)$), caches `nextRsus`, stores $K_g$ and slot $t_i$, computes $Auth_{de}$, generates a **fresh** `Active_01` `OTP_dt` over `{Active_01, Auth_d, Auth_de}` (distinct from Step 6's plaintext $OTP_{\text{req}}$), derives $K_{de}$, and sends `Active_01` $= E_{K_{dg}}(\{Auth_d, OTP_{\text{active}}, Auth_{de}\})$.
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
Handover transfers vehicle authentication without exposing $K_{dg}$, `Forwarding_Notice`, or subsequent RSU traffic to Normal World or $G_{i+1}$ ([`common/Handover.cpp`](common/Handover.cpp), [`artery-sim/src/CtraPredictor.cc`](artery-sim/src/CtraPredictor.cc)):
- **Peer RSU CA Registration (`TA_GATEWAY_CMD_REGISTER_PEER_RSU`)**: At startup, RSUs exchange CA-signed certificates inside Secure World, deriving pairwise symmetric keys $K_{rsu} = \text{SHA256}(\text{"rsu-peer"} \parallel \text{ECDH}(X_{gw}, CY_{g,\text{peer}}) \parallel \min \parallel \max)$ used to seal inter-RSU notices and populate `nextRsus`.
0. *(CTRA Trajectory Prediction — Normal World on Vehicle)* Outside the Secure World, `CtraPredictor` integrates $X = [x, y, v, \psi, a, \omega]^T$ over `predictionHorizon = 8.0 s` (`predictionStep = 0.1 s`) against candidate RSUs and selects only the single most likely target RSU $G_{i+2}$ (`minDistance <= 80 m`). The vehicle looks up $G_{i+2}$'s CA-verified key $Y_{G_{i+2}}$ pre-loaded in `nextRsus`, pre-computes $\tau_{i+2} = \text{Poly1305}(K_{dg}, t_i, m)$, $K_{dh_i} = \text{ECDH}(X_V, Y_{G_{i+2}})$, $KT_i$, and $\text{auth}_{i+2}$ locally (held until `handoverRadius = 160 m` with no `Handover_Command` message), and transmits encrypted & authenticated `Handover_Predict` $= E_{K_{dg}}(\{\text{Handover\_Predict}, Auth_d, G_{i+2}, \text{OTP}_{dt}\})$ strictly to $G_{i+1}$. Other candidate RSUs are never notified.
1. Source RSU TA ($G_{i+1}$, `TA_GATEWAY_CMD_HANDLE_HANDOVER_PREDICT` / `TA_GATEWAY_CMD_TRIGGER_HANDOVER`) decrypts `Handover_Predict`, verifies $Auth_d$ and $\text{OTP}_{dt}$ in $t \pm 1$, computes $\tau_{i+2} = \text{Poly1305}(K_{dg}, t_i, m)$ using volatile activation slot $t_i$ (enforcing `kMaxForwardingNoticesPerVehicle = 4` fan-out limit), and seals `Forwarding_Notice` inside the TA under $K_{rsu}$ for delivery exclusively to $G_{i+2}$:
   $$\text{Forwarding\_Notice} = E_{K_{rsu}}(\{\text{Forwarding\_Notice}, Y_V, \tau_{i+2}, Auth_d, \text{vehicleLabel}\})$$
2. Target RSU TA ($G_{i+2}$, `TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE`) decrypts `Forwarding_Notice` under $K_{rsu}$ and derives session handover keys using its CA-certified gateway keypair $(X_{gw}, CY_{g_{i+2}})$ (zero slow per-handover keygen):
   $$K_{dh_i} = \text{ECDH}(X_{gw}, Y_V), \qquad KT_i = \text{Poly1305}(K_{dh_i}, K_{dh_i} \oplus \tau_{i+2}, m)$$
   $$KT_i^{32} = \text{SHA256}(KT_i \parallel K_{dh_i}), \qquad \text{auth}_{i+2} = \text{SHA256}(\tau_{i+2}), \qquad \text{auth}'_{i+2} = \text{SHA256}(KT_i \parallel \text{auth}_{i+2})$$
   Target TA stores pending handovers keyed by $\text{auth}_{i+2}$ (`kMaxPendingHandovers = 64`, `kHandoverPendingTtlNs = 30 s`).
3. Entering the handover zone (`handoverRadius = 160 m`), vehicle computes at current slot $t_c$:
   $$\text{OTP} = \text{Poly1305}(KT_i^{32}, \text{auth}_{i+2} \oplus t_c, \text{Forwarding\_Request} \parallel \text{auth}_{i+2})$$
   and transmits `Forwarding_Request` `{ auth_{i+2}, OTP }` to $G_{i+2}$.
4. $G_{i+2}$ TA (`TA_GATEWAY_CMD_HANDLE_FORWARDING_REQUEST`) enforces a per-sender DoS rate limit (`<= 5/s`), validates $\text{auth}_{i+2}$ in constant time and `OTP` across $t_c \pm 1$, promotes $K_{dh_i}$ as the vehicle's active $K_{dg}$ paired with $G_{i+2}$'s group key $K_g$, consumes the pending handover (preventing replay), seals Secure Storage (`saveState()`), computes a **fresh** post-`saveState()` $\text{OTP}'$ over `{Forwarding_Granted, nextRsus, auth'_{i+2}, K_{G_{i+2}}}`, and replies:
   $$\text{Forwarding\_Granted} = E_{KT_i}(\{ \text{nextRsus}, \text{auth}'_{i+2}, K_{G_{i+2}}, \text{OTP}' \})$$
   Vehicle verifies keyed $\text{auth}'_{i+2} == \text{SHA256}(KT_i \parallel \text{auth}_{i+2})$ and fresh $\text{OTP}'$ across $t \pm 1$, and transitions to $G_{i+2}$'s $K_{G_{i+2}}$ and updated `nextRsus`.

---

### 2.3 IEEE 1588 PTP Synchronization & Slotted OTPs

Because `[t_0, t_f]` is only `5.0 s` wide and `OTP_dt` slots step every `0.5 s`, unsynchronized vehicle clocks cause authentication mismatches:
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
- **Frame Capacity, Unicast Pinning & Fragmentation**:
  - `RawSocket` opens Linux `AF_PACKET` / `SOCK_RAW` (enabling `PACKET_IGNORE_OUTGOING` where supported and dropping `PACKET_OUTGOING` loopback echoes) with `kMaxFrameData = 1498` bytes payload per Ethernet frame. Discovery retries broadcast `Session_Hello` every `kSessionRetry = 500 ms`; once `Session_Hello`/`Session_Ack` completes, both sides pin the learned peer unicast MAC (`setPeerMac`, while loopback `lo` stays broadcast), preventing switch/router broadcast rate-limiting across 4 concurrent RSUs.
  - Payloads larger than `1498` B (such as 65 KB `SmartData` or X.509 PEM certificates) split into `FrameKind::Data_Fragment` chunks reassembled with `kReassemblyTimeout = 2 s`.
- **Control & HIL Multiplexing (`FrameKind`)**:
  - `Protocol`, `Data_Fragment`, `Session_Hello` (`{ rsuName, Y_gw }` generated inside OP-TEE TA), and `Session_Ack` (`{ rsuName, caPublicKey, gatewayCert, esaCert }`) for CA-authenticated startup provisioning.
  - `Peer_Cert` (`8`) / `Peer_Cert_Ack` (`9`): Exchanges CA-signed peer RSU certificates among `rsu[0]`..`rsu[3]` over `0x88B6` so each RSU TA runs `TA_GATEWAY_CMD_REGISTER_PEER_RSU` (`10`) and derives $K_{rsu}$.
  - `Clock_Anchor` (`packClockAnchor` / `parseClockAnchor`): Artery periodically pushes simulation time $t_{\text{sim}}$ so remote RPi3/VM `./app rsu` processes anchor their `steady_clock` (`PacketManager::setClock`) to OMNeT++ `simTime()`, keeping 0.5 s OTP slots and `[t_0, t_f]` windows aligned despite Unix-epoch vs. simulator-time offsets.
  - `Cloud_Ready` / `Cloud_Refused`: Signals when each RSU TA verifies and pins the CA-signed Cloud cert or if Cloud verification rejects an IT packet.

---

## 3. OP-TEE RSU Gateway Architecture (`rsu-optee-gateway/`)

### 3.1 Normal World (`host/`) vs. Secure World (`ta/`)

- **Normal World (`host/`)**:
  - [`host/main.cpp`](rsu-optee-gateway/host/main.cpp) & [`host/modes.h`](rsu-optee-gateway/host/modes.h): Dispatches `[selftest]` or `rsu` daemon mode (`runRsuNode`).
  - [`host/tee_session.h`](rsu-optee-gateway/host/tee_session.h) / [`host/tee_session.cpp`](rsu-optee-gateway/host/tee_session.cpp): `TeeSession` wraps every TA call (`initIdentity`, `initGateway`, `registerPeerRsu`, `initCloudSession`, `addActivationToken`, `handleHandoverPredict`, `startHandover`, bootstrap/handover handlers, `marshal`).
  - [`host/packet_manager.h`](rsu-optee-gateway/host/packet_manager.h) / [`host/packet_manager.cpp`](rsu-optee-gateway/host/packet_manager.cpp) & [`host/packet_queue.h`](rsu-optee-gateway/host/packet_queue.h): Buffers OT frames into `PacketQueue<OtPacket>`, handles vehicle-initiated `PTP` sync, passes opaque `E_{K_{esa}}(Activation_Token)` into the TA, invokes TA Secure Marshaling, outputs encrypted HTTP POST blobs into `PacketQueue<ItPacket>`, and accepts simulated/anchored clocks (`setClock`).
  - [`host/rsu_node.cpp`](rsu-optee-gateway/host/rsu_node.cpp): Runs `./app rsu`, generating `(X_gw, CY_g)` inside the OP-TEE TA via `initIdentity`, binding `RawSocket` on `0x88b5` and `0x88b6`, completing `Session_Hello` / `Session_Ack` CA provisioning and `Peer_Cert` / `Peer_Cert_Ack` exchange, verifying and pinning the CA-signed Cloud PEM pushed over `0x88b6`, publishing marshaled `ItPacket` blobs back over `0x88b6`, reacting to `Clock_Anchor`, and printing `Benchmark` statistics upon exit (`--session-timeout` defaults to `120` s).
  - [`host/benchmark.h`](rsu-optee-gateway/host/benchmark.h) / [`host/benchmark.cpp`](rsu-optee-gateway/host/benchmark.cpp): Collects per-payload-size microsecond timings.
- **Secure World (`ta/`)**:
  - UUID: `TA_GATEWAY_UUID = 9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718` ([`include/gateway_ta.h`](rsu-optee-gateway/include/gateway_ta.h)), built with `TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION` so a single OP-TEE TA instance serves concurrent isolated `GatewayTaSession` contexts (`rsu[0]`..`rsu[3]`). Commands include `TA_GATEWAY_CMD_REGISTER_PEER_RSU = 10` and `TA_GATEWAY_CMD_HANDLE_HANDOVER_PREDICT = 11`.
  - Return codes: `GW_OK = 0`, `GW_IGNORED = 1`, `GW_ERR_ARGS = -1` (plus negative error codes).
  - [`ta/ta_entry.cpp`](rsu-optee-gateway/ta/ta_entry.cpp): GlobalPlatform TA entrypoints and minimal C++17 runtime stubs without `libstdc++`.
  - [`ta/gateway_session.h`](rsu-optee-gateway/ta/gateway_session.h) / [`ta/gateway_session.cpp`](rsu-optee-gateway/ta/gateway_session.cpp): Full TA protocol state machine (TEE-resident `X_gw`, CA-verified `K_esa` & peer `K_rsu`, anonymous `Activation_Token` decryption, expired/compromised `Auth_d` blocklist, active-session reboot/DoS protection, 3-slot OTP sweep, fresh `Auth_Granted` & `Active_01` OTPs, `E_{K_{esa}}(Active_02)` re-encryption, `marshal`, Secrecy Forwarding with encrypted `Handover_Predict` & `K_rsu`-sealed `Forwarding_Notice`).
  - [`ta/crypto_tee.h`](rsu-optee-gateway/ta/crypto_tee.h) / [`ta/crypto_tee.cpp`](rsu-optee-gateway/ta/crypto_tee.cpp): Uses GP TEE Internal Core API in `OPTEE` mode (`TEE_ALG_ECDH_P256`, `TEE_ALG_ECDSA_P256`, `TEE_ALG_AES_GCM`), RAII `EcdhKeyPair` keeping `X_gw` as an opaque `TEE_ObjectHandle`, RFC 8439 Poly1305, `monotonicTimeMs()` via `TEE_GetSystemTime` (so `Auth_Granted` / `Forwarding_Granted` `OTP_dt` reflects elapsed `saveState()` latency), and a freestanding DER/PEM X.509 certificate verifier against the pinned Root CA public key (`verifyCertDerSignedByCa` / `verifyCertPemSignedByCa`).
  - [`ta/codec.h`](rsu-optee-gateway/ta/codec.h) / [`ta/codec.cpp`](rsu-optee-gateway/ta/codec.cpp): Binary codec across Normal/Secure World buffers.

### 3.2 `HOST_SIM` Mode vs. `OPTEE` Hardware Mode

- **`TEE_MODE=HOST_SIM`** (default on x86_64 host and inside Artery): Compiles `ta/*.cpp` into `./app` or `libtee_v2x_protocol.a` with OpenSSL 3 crypto and host-encrypted disk sealing (`gateway.sealed`), preserving exact `TaGatewayCommand` wire boundaries.
- **`TEE_MODE=OPTEE`** (`-DUSE_OPTEE`): Compiles `ta/*.cpp` into `9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta` and links `./app` against `-lteec` (`<tee_client_api.h>`) to talk to real TrustZone `/dev/tee0` and `tee-supplicant`.

### 3.3 Secure Storage & State Persistence

Whenever `Auth_Granted`, `Active_01`, or `Forwarding_Granted` updates active vehicle state, the TA seals its 16-byte group key $K_g$ and `Auth_d`-keyed active session table (format version `3`; `authTime` $t_i$ stays volatile in TA RAM and is persisted as `0` on flash) into persistent storage (`TEE_STORAGE_PRIVATE` on RPi3; `--sealed <id>` file such as `gateway.sealed` in `HOST_SIM`). Pass `--fresh` to wipe prior sealed state on startup.

---

## 4. Suite 1: OP-TEE Gateway Security Self-Test (`make run` / `./app`)

### 4.1 Purpose, Requirements & Flags

- **Commands**:
  - `make run [OTP=ascon|poly1305]` (or `make test [OTP=ascon|poly1305]`)
  - `./rsu-optee-gateway/app [selftest] [--otp ascon|poly1305] [--sealed <id>] [--fresh] [-h|--help]`
- **Primary File**: [`rsu-optee-gateway/host/selftest.cpp`](rsu-optee-gateway/host/selftest.cpp)
- **Requirements**: `g++` (C++17) + OpenSSL 3 (`HOST_SIM`), or `/dev/tee0` + `tee-supplicant` + `.ta` (`OPTEE` on RPi3). Takes ~**0.5 seconds** (Scenario 3 uses a `0.3 s` operator window and sleeps `0.4 s`).
- **Flags & Make Variables**:

| Flag / Variable | Default | Description |
|---|---|---|
| `--otp ascon\|poly1305` (Make: `OTP=...`) | `ascon` | Runs all 9 OTP/MAC steps in both host and TA strictly under `ascon` or `poly1305` (invalid values exit `1`). |
| `--sealed <id>` | `<app-dir>/gateway.sealed` (`HOST_SIM`) / `gateway.sealed` (`OPTEE`) | Secure Storage ID prefix (`<id>`, `<id>.rsu1`, `<id>.rsu2`, `<id>.rsu3`). |
| `--fresh` | off (`0`) | Deletes prior sealed state for `<id>` before opening (`--fresh`, `--fresh 1`, or `--fresh true`). |
| `TEE_MODE=HOST_SIM\|OPTEE` | `HOST_SIM` | Build backend in `rsu-optee-gateway/Makefile` (`OPTEE` links `-lteec` and builds `.ta`). |
| `PLATFORM=<name>` | `native` | Build directory suffix `build_<TEE_MODE>_<PLATFORM>`. |
| `-h`, `--help` | — | Prints CLI usage and exits `0`. |

### 4.2 Scenario-by-Scenario Deep Dive (`1`–`7`, `4a`–`4m`, `7a`–`7e`)

Upon startup, `selftest` creates a Root CA (`iiot-root-ca`), an `ExternalSecurityAgent(ca)`, a `HumanOperator("operator")`, and a CA-signed `CloudIdentity(ca)` (`/CN=127.0.0.1`), opens TA session 1 (`rsu[0]`), generates `rsu[0]`'s identity keypair inside the TA (`initIdentity`), certifies it via the CA, registers it with the ESA, and runs `initGateway` + `initCloudSession`:

1. **`1. normal (Operator + CA + Theorem 2)`** (`node[0]`, `seed=1`, `+0.25 s` clock skew): Runs Phase A via `HumanOperator` in IT and Phase B/C over OT radio (correcting `+0.25 s` skew via PTP). Asserts: `vehicleReady`, `HumanOperator` verified `Active_03`, **zero** OT radio transmission of `Activation_Request`/`UUID_d`/`SHA256(fw_d)`, **zero** plaintext `Auth_d`/`OTP_active` in `Activation_Token`/`Active_02` backhaul frames, `OTP_active != OTP_auth_req` (Theorem 2), and `Vehicle K_de == ESA K_de`.
2. **`2. OTP changed on the air (rejected by OP-TEE TA)`** (`node[1]`, `seed=7`): Flips a bit inside `Auth_Request` in flight; TA sweeps all pending combinations across 3 slots and rejects (`ignored: 1`).
3. **`3. Auth_Request after t_f (expired & marked compromised by OP-TEE TA)`** (`node[2]`, `seed=11`): Operator sets a `0.3 s` window and `Auth_Request` is delayed `0.4 s`; TA detects `t > t_f`, purges the pending record, adds `node[2]`'s `Auth_d` to its compromised exclusion blocklist, and ignores the request (`ignored: 1`).
4. **`4. Secure Marshaling (OT -> IT) + Secrecy Forwarding handover (node[5]: rsu[0] -> rsu[1])`**:
   - **Part A — Secure Marshaling (`4a`–`4g`)**: Runs on active `node[0]` (`rsu[0]`), verifying 32 B and 64 KB−1 marshaling, tampered `OTP_dt`, tampered `AES(K_G, Data)` caught by GCM tag, unknown `Auth_d`, out-of-window `t`, and Cloud `K_eg` rotation at packet 100.
   - **Part B — Secrecy Forwarding (`4h`–`4m`)**: Opens a **second isolated TA session** (`gateway.sealed.rsu1`) provisioned via CA for `rsu[1]`, exchanges peer RSU certificates (`registerPeerRsu`) so both TAs share `K_rsu`, bootstraps a distinct vehicle `node[5]` (`seed=5`) via `HumanOperator` on `rsu[0]` (pre-loading `rsu[1]`'s key in `Auth_Granted` while preserving `node[0]`'s active session on `rsu[0]`), marshals SmartData to `rsu[0]`, executes vehicle-initiated `requestPrediction("rsu[1]")` → `E_{K_{dg}}(Handover_Predict)` → `E_{K_{rsu}}(Forwarding_Notice)` → `Forwarding_Request` → `Forwarding_Granted` (asserting no plaintext `Auth_d`/`targetRsu` leaks on wire), marshals SmartData to `rsu[1]`, rejects replayed `Forwarding_Request`, and rejects `rsu[0]`-sealed packets at `rsu[1]`.
5. **`5. CY_g of no CA-registered gateway (node[3])`** (`seed=13`): Operator names an unregistered rogue `CY_g`; ESA drops it, no token is issued, and `rsu[0]` TA ignores `node[3]`'s `Auth_Request` (`ignored: 1`).
6. **`6. before t_0: Operator window opens 10 s later (node[4])`** (`seed=17`): Operator sets `[now + 10 s, now + 15 s]`; `node[4]` syncs via PTP and sends `Auth_Request` before `t_0` → **Gateway TA** enforces `t_0 <= now <= t_f` and ignores it (`ignored: 1`).
7. **`7. Reboot/DoS protection, CA PKI, HIL 4-RSU & Secrecy Forwarding checks (`7a`–`7e`)`**:
   - `7a. post-t_f DoS & reboot protection`: Injects spoofed `ECDH_Request`, `Auth_Request`, and `Active_01` naming active `node[0]` 100 s in the future plus a valid reboot `Auth_Request` signed with `node[0]`'s keys; verifies TA discards them (`GW_IGNORED`) **without evicting `node[0]`**, confirmed by marshaling fresh `SmartData` from `node[0]` (`GW_OK`).
   - `7b. active & expired Auth_d excluded`: Re-submitting `Activation_Token` for already-active `node[0]` or expired/compromised `node[2]` is rejected (`GW_IGNORED`).
   - `7c. CA PKI & operator-only Step 1`: Verifies ESA rejects self-signed Gateway certs and drops `Activation_Request` sent by an RSU instead of `"operator"`; verifies TA rejects self-signed ESA certs and self-signed Cloud certs (`GW_ERR_CRYPTO`).
   - `7d. HIL wire helpers & 4 TA sessions`: Verifies `Session_Hello`/`Session_Ack`, `PeerCert`/`PeerCertAck`, `ClockAnchor`, `RsuTag`, `PTP` with `PacketManager::setClock`, and concurrent CA provisioning of `rsu[2]` and `rsu[3]`.
   - `7e. Secrecy Forwarding security/DoS`: Verifies rogue-CA peer RSU certificates fail (`GW_ERR_CRYPTO`), spoofed `Handover_Predict` and forged/tampered `Forwarding_Notice` are ignored (`GW_IGNORED`), the 4-notice per-vehicle fan-out cap blocks the 5th `Handover_Predict` (`GW_IGNORED`), and the 5/s `Forwarding_Request` rate limit throttles excess requests (`GW_IGNORED`).

### 4.3 Observed Terminal Output

Running `make -C rsu-optee-gateway run` (and re-running `./rsu-optee-gateway/app`) exited with code `0` and ended with:

```text
  7a. post-t_f DoS & reboot protection   spoofed/reboot Auth_Request discarded; node[0] stayed active   ok
  7b. active & expired Auth_d excluded   both active and expired/compromised Auth_d rejected (GW_IGNORED)   ok
  7c. CA PKI & operator-only Step 1      self-signed GW/ESA/Cloud certs & RSU-relayed Activation_Request rejected   ok
  7d. HIL wire helpers & 4 TA sessions   Session_Hello/Ack, PeerCert/Ack, ClockAnchor, PTP & 4 RSUs OK   ok
  7e. Secrecy Forwarding security/DoS    rogue peer, spoofed predict/notice, fan-out <= 4 & req rate limit OK   ok

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

---

## 5. Suite 2: Raspberry Pi 3 TrustZone & 4-RSU HIL Daemon (`./app rsu`)

### 5.1 Cross-Compilation & Deployment (`build-rpi3.sh`)

- **Command**: `make rpi3 [PI_IP=<ip>]` (invokes [`rsu-optee-gateway/build-rpi3.sh`](rsu-optee-gateway/build-rpi3.sh) `[<pi-ip>]`)
- **Environment Overrides**:
  - `PI_IP` (or positional arg `$1`): If set, uploads `.ta` and `/root/app` to `root@<ip>` via `scp`/`ssh`.
  - `RPI3_SDK_DIR` *(default `rsu-optee-gateway/rpi3-sdk`)*, `OPTEE_RPI3_DIR` *(optional full Buildroot tree)*, `TA_DEV_KIT_DIR`, `SYSROOT`, `CROSS_COMPILE_TA` *(default `aarch64-linux-gnu-`)*, `CROSS_COMPILE_HOST`, `SIGN_SCRIPT`, `SIGN_KEY`.
- **Pipeline**:
  1. Builds `ta/9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718.ta` for Cortex-A53 (`-mcpu=cortex-a53`).
  2. Patches ELF header `EI_OSABI` to `0x00` and signs/encrypts the `.ta` with OP-TEE `sign_encrypt.py` (`default_ta.pem`).
  3. Cross-compiles `./app` linked with `-lteec` (`TEE_MODE=OPTEE`).
  4. If `PI_IP` is set, uploads the signed `.ta` into OP-TEE's TA store and `/root/app` via `scp`/`ssh`.

### 5.2 4-RSU Hardware Launcher (`rsu-quad-ssh.sh` & `./app rsu`)

```bash
./rsu-quad-ssh.sh --pi-ip <ip> [--rsu-iface <iface>] [--otp ascon|poly1305] [--session-timeout <sec>] [--keep-state] [--remote-app <path>]
# Individual daemon on RPi3 / local NIC:
./app rsu [--name <rsu>] [--iface <nic>] [--otp ascon|poly1305] [--sealed <id>] [--fresh] [--session-timeout <sec>]
```

| Flag | Env Var Equivalent | Default | Description |
|---|---|---|---|
| `--pi-ip <ip>` (`rsu-quad-ssh.sh`) | `PI_IP` | *(required)* | Target Raspberry Pi 3 IP address over SSH. |
| `--rsu-iface <iface>` (`rsu-quad-ssh.sh`) / `--iface <nic>` (`./app rsu`) | `RSU_IFACE` / `IFACE` | `eth0` | Raw Ethernet NIC (`0x88b5` radio + `0x88b6` backhaul). |
| `--otp ascon\|poly1305` | `OTP` | auto-adopt from `Session_Ack` | If omitted on RPi3, adopts Artery's `Session_Ack` OTP algorithm; if set explicitly, fails fast on mismatch. |
| `--session-timeout <sec>` | `SESSION_TIMEOUT` | `120` | Seconds to wait for `Session_Ack` from Artery/ESA. |
| `--keep-state` (`rsu-quad-ssh.sh`) / `--fresh` (`./app rsu`) | — | fresh state (`--fresh`) | `rsu-quad-ssh.sh` passes `--fresh` unless `--keep-state` is given. |
| `--remote-app <path>` (`rsu-quad-ssh.sh`) | — | `/root/app` | Path to `./app` binary on the Raspberry Pi 3. |
| `--name <rsu>` (`./app rsu`) | — | `rsu[0]` | Logical RSU identifier (`rsu[0]`..`rsu[3]`). |
| `--sealed <id>` (`./app rsu`) | — | `gateway.sealed` | OP-TEE Secure Storage object ID (`rsu0.sealed`..`rsu3.sealed`). |
| `-h`, `--help` | — | — | Prints usage and exits `0`. |

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

- **`make vm [OTP=ascon|poly1305]`**: Starts `optee-arm64-vm`, `rsync`s the repository into the VM via [`rsu-optee-gateway/vm-make.sh`](rsu-optee-gateway/vm-make.sh), sources `/etc/profile.d/optee.sh`, and runs `make -C rsu-optee-gateway run OTP=<algo>` (or custom `VM_ARGS` when invoked via `make -C rsu-optee-gateway vm VM_ARGS=...`).
- **`make vm-hil [OTP=ascon|poly1305]`**: Syncs the repo, grants `cap_net_raw=ep` (`make caps`), and runs `make hil-quad OTP=<algo>` inside `optee-arm64-vm` (launching 4 concurrent `rsu[0]`..`rsu[3]` processes bound to the VM's libvirt NIC; `IFACE` and `SESSION_TIMEOUT` can be overridden via `VM_ARGS`). Pair with `make hil-quad HIL_IFACE=virbr0 [OTP=ascon|poly1305] [GUI=1]` on the host PC.
- **`vm-make.sh` environment overrides**: `VM_NAME` *(default `optee-arm64-vm`)*, `VM_DIR` *(default `v2x`)*, `VM_USER` *(default `optee`)*, `VM_HOST` *(optional `<user>@<ip>` to bypass `virsh domifaddr`)*.

---

## 7. Suite 4: CrowNet 5G NR (OMNeT++ 6.3 + Artery + Simu5G + SUMO) V2X Simulations (`artery-sim/`)

### 7.1 Build Setup (`setup_artery.sh`)

[`artery-sim/setup_artery.sh`](artery-sim/setup_artery.sh) automates the CrowNet 5G NR build inside `artery-sim/deps/crownet/`:
1. Builds the [`v2x-crownet:6.3.0`](artery-sim/Dockerfile.crownet) Docker image (`ghcr.io/omnetpp/omnetpp:u24.04-6.3.0` + `osgEarth 3.7.2` + Boost + Crypto++ + GeographicLib + OpenSSL 3 + `python3-packaging` + `cap_net_raw+ep` on `opp_run_release`).
2. Clones **`roVer-HM/crownet`** (`master`) and initializes its C++ submodules (`inet4`, `veins`, `artery` + `vanetza`/`pybind11`, `simu5g`).
3. Compiles all 6 frameworks in Release mode (`MODE=release`): `inet4` → `veins` → `veins_inet` → `artery` → `simu5g` → `crownet` (`libCROWNET.so`).
4. Builds [`artery-sim/build/libtee_v2x.so`](artery-sim/Makefile) linking `common/`, `protocol/`, `net/`, `rsu-optee-gateway/{host,ta}`, and `artery-sim/src/`.
5. Flags: `--rebuild-image` (force Docker image rebuild), `--clean-objs` (delete intermediate `.o`/`.d` files after linking each framework to keep disk usage compact).

### 7.2 5G NR Topology, SUMO Mobility & Custom Modules

- **SUMO Mobility** ([`highway.sumocfg`](artery-sim/scenario/highway.sumocfg), [`highway.net.xml`](artery-sim/scenario/highway.net.xml), [`highway.rou.xml`](artery-sim/scenario/highway.rou.xml)): **400 m × 400 m 3×3 Manhattan Grid**; host SUMO 1.26.0 runs natively and connects to CrowNet via `traci.ConnectLauncher` on a dynamically allocated localhost TraCI port. Vehicle `v0` (`node[0]`, `crownet.nodes.ApplicationLayerVehicle`) enters on `w_0` moving at **`20 m/s`** along route `manhattan_loop` (`w_0 w_1 n_0 n_1 e_0 e_1 s_0 s_1`) and traverses all 4 perimeter edges within `sim-time-limit = 85 s`.
- **5G NR Core, RAN & Edge RSU Network** ([`HighwayHandover.ned`](artery-sim/scenario/HighwayHandover.ned), [`demo.xml`](artery-sim/scenario/demo.xml)):
  - **5G NR Carrier (`CarrierAggregation` + `Binder` + `LteChannelControl`)**: `3.5 GHz` (n78), numerology $\mu=1$ (`30 kHz` SCS), `25 RBs`, `NrAmc`, `NrChannelModel`, `ueTxPower = 26 dBm`, `eNodeBTxPower = 30 dBm`, `dynamicCellAssociation = true`, `enableHandover = true`, `handoverLatency = 50 ms`, `broadcastMessageInterval = 0.2 s`.
  - **4 5G NR gNodeBs (`gNB[0..3]`, full-mesh X2/Xn SCTP links) + 4 co-located OP-TEE Edge RSU Gateways (`rsu[0..3]: StandardHost`)** connected via `upf` (`simu5g.nodes.Upf`) and `router` (`Eth10G`):
    - `gNB[0]` (`macNodeId=1`) & `rsu[0]` (West edge) at `(10 m, 200 m, 10 m)` → OP-TEE TA session #1 (`rsu0.sealed`)
    - `gNB[1]` (`macNodeId=2`) & `rsu[1]` (North edge) at `(200 m, 10 m, 10 m)` → OP-TEE TA session #2 (`rsu1.sealed`)
    - `gNB[2]` (`macNodeId=3`) & `rsu[2]` (East edge) at `(390 m, 200 m, 10 m)` → OP-TEE TA session #3 (`rsu2.sealed`)
    - `gNB[3]` (`macNodeId=4`) & `rsu[3]` (South edge) at `(200 m, 390 m, 10 m)` → OP-TEE TA session #4 (`rsu3.sealed`)
  - `backhaulBroker` ([`BackhaulBroker`](artery-sim/src/BackhaulBroker.cc), `latency = 20 ms`) hosting the Root CA (`CertificateAuthority`), `HumanOperator`, ESA (`ExternalSecurityAgent`), and Cloud verification (`cloudStored`, `cloudRefused`, `operatorConfirmations`, `cloudJsonBytes`).
- **Custom 5G NR V2X Modules** ([`artery-sim/src/`](artery-sim/src)):
  - [`CtraPredictor.h`](artery-sim/src/CtraPredictor.h) / [`CtraPredictor.cc`](artery-sim/src/CtraPredictor.cc): Purely kinematic Constant Turn Rate and Acceleration (CTRA) trajectory predictor ($X = [x, y, v, \psi, a, \omega]^T$, zero map-matching or road-geometry heuristics) evaluating future vehicle positions (`predictionHorizon = 8.0 s`, `predictionStep = 0.1 s`) against all candidate RSUs to select the single most likely next RSU (`predictRadius = 80 m`) and trigger `Forwarding_Request` once within `handoverRadius = 160 m`.
  - [`V2xFrame.h`](artery-sim/src/V2xFrame.h): Wraps serialized `ProtocolMsg` bytes for delayed backhaul scheduling in `BackhaulBroker`.
  - [`VehicleTeeService.cc`](artery-sim/src/VehicleTeeService.cc): INET 4 `IApp` (`node[0].app[0]`) running `VehicleAgent` (`BootstrapClient`, `HandoverClient`, `SecureDataClient`) and `CtraPredictor` over **5G NR IPv4/UDP port 2025** (`NrNicUe` → `gNB[*]` → `UPF` → `Router` → `rsu[*]`), reading live SUMO kinematics via Artery's `VehicleMiddleware` (`traci::VehicleController`) and subscribing to Simu5G `nrPhy`'s `servingCell` signal to record `nrRadioHandovers` and `nrServingCellId`.
  - [`TeeRsuService.cc`](artery-sim/src/TeeRsuService.cc): INET 4 `IApp` (`rsu[i].app[0]`) serving 5G NR UDP port 2025:
    - When `enableHil = false` (`NR_5G`), creates an isolated host `TeeSession` + `PacketManager` per RSU, generating `(X_gw, CY_g)` inside the TA and provisioning CA-signed certs via `BackhaulBroker`.
    - When `enableHil = true` (`HIL_RPi3_QuadRsu`), `initHil()` does not instantiate local `TeeSession` or `PacketManager` objects; CrowNet acts solely as an `AF_PACKET` bridge (`0x88b5` / `0x88b6`) polled every `1 ms`.

### 7.3 Simulation Configurations (`omnetpp.ini`) & Run Flags

1. **`NR_5G` & `NR_5G_GUI`**:
   - Pure CrowNet 5G NR (`3.5 GHz` n78, $\mu=1$, `25 RBs`, 4 `gNodeB`s with full-mesh X2 handover + `UPF` + `Router` + 4 OP-TEE RSUs) over the 400 m × 400 m Manhattan Grid with purely kinematic CTRA trajectory prediction.
   - Run via `make sim [OTP=ascon|poly1305] [GUI=1]` or `./artery-sim/run-sim.sh [--config NR_5G|NR_5G_GUI] [--otp ascon|poly1305] [--gui] [--rebuild] [-- <extra opp_run flags>]`.
2. **`HIL_RPi3_QuadRsu` (+ `HIL_RPi3_QuadRsu_GUI`)**:
   - Extends `NR_5G` and sets **`*.rsu[*].app[0].enableHil = true`** so **all 4 RSUs (`rsu[0]`..`rsu[3]`)** reside in 4 isolated OP-TEE TA sessions on the physical Raspberry Pi 3 (or `virbr0` VM), launched under **`--scheduler-class=omnetpp::cRealTimeScheduler`** with `--network=host --cap-add=NET_RAW`.
   - Run via `make hil-quad HIL_IFACE=<nic> [OTP=ascon|poly1305] [GUI=1]` or `./artery-sim/run-hil-quad.sh --iface <nic> [--otp ascon|poly1305] [--gui] [--rebuild] [-- <extra opp_run flags>]`.
   - Fails fast with an explicit error if `HIL_IFACE` / `--iface` is omitted.

| Flag / Variable / Override | Applies To | Default | Description |
|---|---|---|---|
| `--config <name>` | `run-sim.sh` | `NR_5G` (`NR_5G_GUI` with `--gui`) | OMNeT++ configuration name (`NR_5G`, `NR_5G_GUI`, `HIL_RPi3_QuadRsu`, `HIL_RPi3_QuadRsu_GUI`). |
| `OTP=ascon\|poly1305` (Make) / `--otp ascon\|poly1305` / `OTP_ALGO` env | `make sim`, `make hil-quad`, `run-sim.sh`, `run-hil-quad.sh` | `ascon` | Selects the single OTP/MAC algorithm for vehicle, local TAs, and `Session_Ack` sent to physical RPi3 RSUs. |
| `HIL_IFACE=<nic>` / `--iface <nic>` | `make hil-quad`, `run-hil-quad.sh`, `run-sim.sh` (HIL configs) | *(required for HIL)* | Host Ethernet interface wired to RPi3 (e.g. `<host-nic>`) or VM bridge (`virbr0`). |
| `CSV_PREFIX=<path>` / `--csv-prefix <path>` | `make sim`, `make hil-quad`, `run-sim.sh`, `run-hil-quad.sh` | `results/<config>-<otp>-<YYYYMMDD-HHMMSS>` | Output stem for `.sca`/`.vec`/`.vci` and `<prefix>-{summary,handovers,packets}.csv` (unique per OTP algorithm and run timestamp by default). |
| `QUIET=1` / `--quiet` & `VERBOSE=1` / `--verbose` (`V2X_VERBOSE=1`) | `make sim`, `make hil-quad`, `run-sim.sh`, `run-hil-quad.sh` | `quietTrace=true` in HIL, `false` in `NR_5G` | Controls focused evaluation output (`[EVAL t=...]` milestones + report) vs. full per-step cryptographic hex traces. |
| `GUI=1` (Make) / `--gui` | `make sim`, `make hil-quad`, `run-sim.sh`, `run-hil-quad.sh` | headless | Launches host `sumo-gui --start --quit-on-end` (`NR_5G_GUI` / `HIL_RPi3_QuadRsu_GUI`). |
| `--rebuild` | `run-sim.sh`, `run-hil-quad.sh` | off (`make` passes it) | Rebuilds `artery-sim/build/libtee_v2x.so` inside `v2x-crownet:6.3.0` before running. |
| `-- <extra opp_run flags>` | `run-sim.sh`, `run-hil-quad.sh` | — | Appends arbitrary OMNeT++ flags to `opp_run_release`, e.g. `--*.rsu[*].app[0].hilHandshakeTimeout=25s` or `--*.backhaulBroker.otpAlgo=\"poly1305\"`. |
| `-h`, `--help` | `run-sim.sh`, `run-hil-quad.sh`, `setup_artery.sh` | — | Prints usage and exits `0`. |

### 7.4 Observed `NR_5G` Trace & Scalar Results

Running `make sim OTP=ascon` and `make sim OTP=poly1305` reached `t = 85 s` (`Event #1696279`, elapsed `~3.0 s`, exit code `0`) and wrote [`NR_5G-0.sca`](artery-sim/scenario/results/NR_5G-0.sca) with identical delivery counts under both OTP modes:
- **Vehicle (`HighwayHandover.node[0].app[0]`)**:
  - `bootstrapped`: `1` (`bootstrapDelay:last = 0.0395 s`)
  - **5G NR Radio Handovers**: `nrRadioHandovers = 3`, `nrServingCellId = 4` (`gNB[0] → gNB[1]` at `t = 21.85 s`, `gNB[1] → gNB[2]` at `t = 46.05 s`, `gNB[2] → gNB[3]` at `t = 70.25 s`)
  - `ctraPredictionsSent`: `3`, `prefetchesCompleted`: `3` (`prefetchLeadTimeMs`: `count = 3`, `min/mean/max = 2900 ms`)
  - `handovers`: `3` (`rsu[0] → rsu[1] → rsu[2] → rsu[3]`, `handoverE2EDelayMs`: `count = 3`, `min/mean/max = 12 ms`)
  - `secureDataSent`: `842` (`220` to `rsu[0]`, `239` to `rsu[1]`, `239` to `rsu[2]`, `144` to `rsu[3]`)
- **RSUs (`rsu[*].app[0]`, `TeeRsuService`)**:
  - `rsu[0]`: `marshaledPackets = 220`, `marshalRefused = 0`, `teeIgnored = 0`, `handoversTriggered = 1`, `handoversGranted = 0`
  - `rsu[1]`: `marshaledPackets = 239`, `marshalRefused = 0`, `teeIgnored = 0`, `handoversTriggered = 1`, `handoversGranted = 1`
  - `rsu[2]`: `marshaledPackets = 239`, `marshalRefused = 0`, `teeIgnored = 0`, `handoversTriggered = 1`, `handoversGranted = 1`
  - `rsu[3]`: `marshaledPackets = 144`, `marshalRefused = 0`, `teeIgnored = 0`, `handoversTriggered = 0`, `handoversGranted = 1`
- **Backhaul, Operator & Cloud (`HighwayHandover.backhaulBroker`)**:
  - `backhaulDelivered`: `7` (4 initial bootstrap IT messages: `Activation_Request` Operator→ESA, `E_{K_{esa}}(Activation_Token)` ESA→RSU, `E_{K_{esa}}(Active_02)` RSU→ESA, `Active_03` ESA→Operator + 3 × $K_{rsu}$-sealed `Forwarding_Notice`), `backhaulUndeliverable`: `0`, `operatorConfirmations`: `1`
  - `cloudStored`: `842` (`cloudRefused = 0`, `cloudJsonBytes:sum = 366561`)

### 7.5 Observed Physical RPi3 5G NR `HIL_RPi3_QuadRsu` Results

Running the full 85 s 5G NR `HIL_RPi3_QuadRsu` scenario (`OTP=ascon`) with all 4 RSU instances executing in Raspberry Pi 3 OP-TEE TrustZone (`<pi-ip>`, bridged over `<host-nic>` under `cRealTimeScheduler`) initialized all 4 RSUs (`Session_Ack` + `Cloud_Ready` + `peer RSU certificates verified in TrustZone (K_rsu ready)`), reached `t = 85 s` (exit code `0`), and wrote [`HIL_RPi3_QuadRsu-0.sca`](artery-sim/scenario/results/HIL_RPi3_QuadRsu-0.sca) with:
- **Vehicle (`HighwayHandover.node[0].app[0]`)**:
  - `bootstrapped`: `1` (`bootstrapDelay:last = 1.8155 s`)
  - **5G NR Radio Handovers**: `nrRadioHandovers = 3`, `nrServingCellId = 4` (`gNB[0] → gNB[1] → gNB[2] → gNB[3]`)
  - `ctraPredictionsSent`: `3`, `prefetchesCompleted`: `3` (`prefetchLeadTimeMs`: `count = 3`, `min/mean/max = 2900 ms`)
  - `handovers`: `3` (`rsu[0] → rsu[1] → rsu[2] → rsu[3]`, `handoverE2EDelayMs`: `mean = 273.33 ms`, `min = 221 ms`, `max = 375 ms`)
  - `secureDataSent`: `824` (`204` to `rsu[0]`, `239` to `rsu[1]`, `240` to `rsu[2]`, `141` to `rsu[3]`)
- **RSUs (`rsu[*].app[0]`, `TeeRsuService`)**:
  - `rsu[0]`: `marshaledPackets = 196`, `marshalRefused = 8`, `teeIgnored = 0`, `handoversTriggered = 1`, `handoversGranted = 0`
  - `rsu[1]`: `marshaledPackets = 215`, `marshalRefused = 24`, `teeIgnored = 0`, `handoversTriggered = 1`, `handoversGranted = 1`
  - `rsu[2]`: `marshaledPackets = 215`, `marshalRefused = 25`, `teeIgnored = 0`, `handoversTriggered = 1`, `handoversGranted = 1`
  - `rsu[3]`: `marshaledPackets = 136`, `marshalRefused = 5`, `teeIgnored = 0`, `handoversTriggered = 0`, `handoversGranted = 1`
  - *(Note: `marshalRefused` bursts occur briefly while 10 Hz packets queue behind ~1.58 s P-256 Cloud session key rotation `newCloudSession()` inside RPi3 TrustZone and legitimately expire outside the `t ± 1` OTP freshness window.)*
- **Backhaul, Operator & Cloud (`HighwayHandover.backhaulBroker`)**:
  - `backhaulDelivered`: `7`, `backhaulUndeliverable`: `0`, `operatorConfirmations`: `1`
  - `cloudStored`: `762` (`cloudRefused = 0`, `cloudJsonBytes:sum = 331753`)

### 7.6 Academic V2X Evaluation Metrics & CSV Exports

To produce publication-ready evaluation data without verbose cryptographic hex traces cluttering HIL output, `HIL_RPi3_QuadRsu` enables `*.backhaulBroker.quietTrace = true` by default (override with `VERBOSE=1` / `--verbose`, or enable on `NR_5G` with `QUIET=1` / `--quiet`). During the run, only concise `[EVAL t=...]` milestones (bootstrap, CTRA predictions, 5G NR X2 handovers, Secrecy Forwarding handovers) are printed, followed by a formatted **V2X 5G NR + OP-TEE Evaluation Report** and 3 CSV files in `artery-sim/scenario/results/` (`<prefix>-summary.csv`, `<prefix>-handovers.csv`, `<prefix>-packets.csv`, where `<prefix>` defaults to `results/<configname>-<otp>` and can be overridden via `CSV_PREFIX=<path>` / `--csv-prefix <path>`):

| CSV File | Schema & Academic Metrics Captured |
|---|---|
| **`<prefix>-summary.csv`** | `category,metric,value,unit,description` covering **Reliability** (`ot_pdr_pct`, `e2e_cloud_pdr_pct`, `e2e_plr_pct`, `ta_acceptance_rate_pct`, `marshal_refused`, `cloud_refused`), **Throughput & Overhead** (`ot_tx_goodput_kbps`, `cloud_it_goodput_kbps`, `protocol_control_overhead_pct`, `control_bytes_sent`, `data_bytes_sent`, `backhaul_messages_delivered`), **Latency & Jitter** (`e2e_latency_{mean,std,min,p50,p95,p99,max}_ms`, RFC 3550 `jitter_{mean,p95,max}_ms`, `nr_uplink_latency_{mean,p95}_ms`, `rsu_ta_turnaround_{mean,p95,max}_ms`, `host_ta_invoke_{mean,p95}_us`), **Bootstrap & Handover** (`bootstrap_delay_ms`, `operator_e2e_confirmation_ms`, `handover_success_rate_pct`, `handover_latency_{mean,std,min,max}_ms`, `handover_interruption_time_{mean,max}_ms`), **CTRA** (`ctra_prediction_accuracy_pct`, `prefetch_lead_time_{mean,min,max}_ms`, `backhaul_signaling_reduction_pct`), and **5G NR PHY** (`nr_radio_handovers`, `nr_sinr_{dl,ul}_mean_db`, `nr_cqi_{dl,ul}_mean`). |
| **`<prefix>-handovers.csv`** | Per-handover breakdown: `handover_id,from_rsu,to_rsu,ctra_predict_time_s,ctra_accurate,prefetch_ready_time_s,nr_x2_handover_time_s,nr_from_gnb,nr_to_gnb,fwd_req_time_s,fwd_granted_time_s,prefetch_lead_time_ms,handover_e2e_delay_ms,handover_interruption_time_ms,handover_dist_m`. |
| **`<prefix>-packets.csv`** | Per-packet time-series extracted directly from each Cloud-decrypted `SmartData` JSON `"Timing"` field (zero wire-protocol overhead in both `NR_5G` and physical RPi3 `HIL_RPi3_QuadRsu`): `seq,tx_time_s,rsu_rx_time_s,cloud_rx_time_s,rsu,serving_gnb,ot_bytes,it_json_bytes,nr_uplink_ms,rsu_ta_ms,e2e_latency_ms,jitter_ms`. |

Verified `NR_5G` (`OTP=ascon` and `OTP=poly1305`) summary highlights (`results/NR_5G-{ascon,poly1305}-summary.csv`):
- **Reliability**: OT PDR `100.00%` (`842/842`), E2E Cloud PDR `100.00%` (`PLR = 0.00%`), TA acceptance `100.00%`.
- **Throughput & Overhead**: `33.00 kbps` OT goodput, `34.87 kbps` Cloud JSON goodput, `0.328%` protocol control overhead (`1143 B` control / `346904 B` data).
- **Latency & Jitter**: E2E latency `mean = 5.31 ms` (`std = 2.49`, `p50 = 4.50`, `p95 = 10.50`, `p99 = 15.27`, `max = 28.00 ms`), RFC 3550 jitter `mean = 0.87 ms` (`p95 = 6.00 ms`), `HOST_SIM` TA wall-clock `mean = 32.23 us` (`p95 = 37.92 us`).
- **Bootstrap, CTRA & Handover**: OT bootstrap `39.50 ms`, Operator E2E `187.00 ms`, CTRA accuracy `100.0%` (`3/3`), pre-fetch lead time `2900 ms`, backhaul signaling reduction `66.67%`, Secrecy Forwarding delay `12.00 ms`, Handover Interruption Time (HIT) `100.00 ms` (exact 10 Hz packet period, zero dropped packets across all 3 RSU switches).
- **5G NR PHY (Simu5G)**: `3` X2 gNodeB handovers, mean DL SINR `42.01 dB` (CQI `14.00`), mean UL SINR `39.71 dB` (CQI `14.26`).
