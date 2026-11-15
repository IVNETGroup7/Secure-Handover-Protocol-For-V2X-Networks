# Secure-Handover-Protocol-For-V2X-Networks
#
# Primary focus:
#   1. In-memory OP-TEE gateway self-test (bootstrap + tampering + Secure Marshaling + Secrecy Forwarding)
#   2. Dual-RSU Raspberry Pi 3 Hardware-in-the-Loop (both rsu[0] and rsu[1] on RPi3 TrustZone; Artery on PC)
#   3. Virtualized OP-TEE VM workflow (self-test and virbr0 Dual-RSU HIL mirroring the RPi3 setup)
#   4. Pure Artery IEEE 802.11p highway handover simulation (D250m_80211p)

ARTERY_BUILD := artery-sim/deps/artery/build

.PHONY: all build run test vm vm-hil rpi3 sim hil-dual clean help

all: build

build:
	$(MAKE) -C rsu-optee-gateway all

run test:
	$(MAKE) -C rsu-optee-gateway run

vm:
	$(MAKE) -C rsu-optee-gateway vm

vm-hil:
	$(MAKE) -C rsu-optee-gateway vm VM_ARGS=hil-dual

rpi3:
	$(MAKE) -C rsu-optee-gateway rpi3 PI_IP=$(PI_IP)

sim:
	cmake --build $(ARTERY_BUILD) --target tee_v2x -j$$(nproc)
	cmake -DRUN_FLAGS="-u Cmdenv -c D250m_80211p" $(ARTERY_BUILD)
	cmake --build $(ARTERY_BUILD) --target run_tee_v2x_handover

hil-dual:
	@test -n "$(HIL_IFACE)" || { echo "error: pass HIL_IFACE=<host_nic> (e.g. make hil-dual HIL_IFACE=enp3s0)" >&2; exit 2; }
	./artery-sim/run-hil-dual.sh --rebuild --iface "$(HIL_IFACE)" $(if $(GUI),--gui)

clean:
	$(MAKE) -C rsu-optee-gateway clean
	rm -rf build artery-sim/scenario/results artery-sim/scenario/*.sealed \
		artery-sim/scenario/.cmdenv-log .cmdenv-log

help:
	@echo "Targets:"
	@echo "  make build                      Build rsu-optee-gateway ./app (HOST_SIM self-test + HIL daemon)"
	@echo "  make run                        Run the 7-scenario OP-TEE gateway self-test"
	@echo "  make vm                         Sync repo & run self-test in optee-arm64-vm"
	@echo "  make vm-hil                     Run dual-RSU (rsu[0]+rsu[1]) in optee-arm64-vm (pair with HIL_IFACE=virbr0)"
	@echo "  make rpi3 [PI_IP=<ip>]          Cross-compile & deploy .ta + ./app for Raspberry Pi 3"
	@echo "  make sim                        Build tee_v2x and run Artery simulation (D250m_80211p)"
	@echo "  make hil-dual HIL_IFACE=<nic>   Rebuild tee_v2x and run Artery HIL_RPi3_DualRsu (add GUI=1 for sumo-gui)"
	@echo "  make clean                      Clean build artifacts, sealed state files, and simulation results"
