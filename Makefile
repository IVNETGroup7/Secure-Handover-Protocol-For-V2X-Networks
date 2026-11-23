# Secure-Handover-Protocol-For-V2X-Networks
#
# Primary focus:
#   1. In-memory OP-TEE gateway self-test (bootstrap + tampering + Secure Marshaling + Secrecy Forwarding)
#   2. Quad-RSU (4-RSU) Raspberry Pi 3 Hardware-in-the-Loop (rsu[0]..rsu[3] on RPi3 TrustZone; Artery on PC)
#   3. Virtualized OP-TEE VM workflow (self-test and virbr0 Quad-RSU HIL mirroring the RPi3 setup)
#   4. Pure Artery IEEE 802.11p highway handover simulation (D250m_80211p)

ARTERY_BUILD := artery-sim/deps/artery/build
OTP ?= ascon

.PHONY: all build run test vm vm-hil rpi3 sim hil-quad clean help

all: build

build:
	$(MAKE) -C rsu-optee-gateway all

run test:
	$(MAKE) -C rsu-optee-gateway run OTP=$(OTP)

vm:
	$(MAKE) -C rsu-optee-gateway vm VM_ARGS="run OTP=$(OTP)"

vm-hil:
	$(MAKE) -C rsu-optee-gateway vm VM_ARGS="hil-quad OTP=$(OTP)"

rpi3:
	$(MAKE) -C rsu-optee-gateway rpi3 PI_IP=$(PI_IP)

sim:
	cmake --build $(ARTERY_BUILD) --target tee_v2x -j$$(nproc)
	cmake -DRUN_FLAGS="-u Cmdenv -c D250m_80211p" $(ARTERY_BUILD)
	OTP_ALGO=$(OTP) cmake --build $(ARTERY_BUILD) --target run_tee_v2x_handover

hil-quad:
	@test -n "$(HIL_IFACE)" || { echo "error: pass HIL_IFACE=<host_nic> (e.g. make hil-quad HIL_IFACE=enp3s0)" >&2; exit 2; }
	./artery-sim/run-hil-quad.sh --rebuild --iface "$(HIL_IFACE)" --otp "$(OTP)" $(if $(GUI),--gui)

clean:
	$(MAKE) -C rsu-optee-gateway clean
	rm -rf build artery-sim/scenario/results artery-sim/scenario/*.sealed \
		artery-sim/scenario/.cmdenv-log .cmdenv-log

help:
	@echo "Targets (pass OTP=ascon or OTP=poly1305, default: ascon):"
	@echo "  make build                                Build rsu-optee-gateway ./app (HOST_SIM self-test + HIL daemon)"
	@echo "  make run [OTP=ascon|poly1305]             Run the 7-scenario OP-TEE gateway self-test"
	@echo "  make vm [OTP=ascon|poly1305]              Sync repo & run self-test in optee-arm64-vm"
	@echo "  make vm-hil [OTP=ascon|poly1305]          Run quad-RSU (rsu[0]..rsu[3]) in optee-arm64-vm (pair with HIL_IFACE=virbr0)"
	@echo "  make rpi3 [PI_IP=<ip>]                    Cross-compile & deploy .ta + ./app for Raspberry Pi 3"
	@echo "  make sim [OTP=ascon|poly1305]             Build tee_v2x and run Artery simulation (D250m_80211p)"
	@echo "  make hil-quad HIL_IFACE=<nic> [OTP=...]   Rebuild tee_v2x and run Artery HIL_RPi3_QuadRsu (add GUI=1 for sumo-gui)"
	@echo "  make clean                                Clean build artifacts, sealed state files, and simulation results"
