# OP-TEE RSU Gateway (Arm TrustZone on Raspberry Pi 3 Cortex-A53 and QEMU ARMv8-A)
#
# Structure:
#   include/    shared TA UUID, command IDs, and status codes (gateway_ta.h)
#   ta/         Secure World Trusted Application (GlobalPlatform TEE Internal Core API)
#   host/       Normal World Client Application (GlobalPlatform TEE Client API / libteec)
#
# Targets:
#   make              build ./app (and the .ta when TA_DEV_KIT_DIR is present)
#   make run          build and run the self-test (bootstrap, tamper checks, Secure Marshaling, Secrecy Forwarding)
#   make hil-quad     run concurrent rsu[0]..rsu[3] OP-TEE daemons over raw Ethernet (for Artery HIL_RPi3_QuadRsu)
#   make rpi3         cross-compile ./app and .ta for Raspberry Pi 3 (-mcpu=cortex-a53) via build-rpi3.sh
#   make vm           delegate build/run (or VM_ARGS=hil-quad) to the ARM64 OP-TEE QEMU VM via ./vm-make.sh
#   make clean        remove build artifacts and sealed state files

TA_UUID := 9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718
TA_BINARY := ta/$(TA_UUID).ta

# Auto-detect OP-TEE environment (/opt/optee inside the ARM64 QEMU VM or custom paths)
OPTEE_DIR ?= /opt/optee
TA_DEV_KIT_DIR ?= $(wildcard $(OPTEE_DIR)/optee_os/out/arm-plat-*/export-ta_arm64)
TEEC_EXPORT ?= $(wildcard $(OPTEE_DIR)/optee_client/out/export/usr)

# Modes:
#   HOST_SIM (default) - compiles natively with g++ using the in-process TA session backend;
#                        runs full TrustZone security logic on VM/host without cross-compilation.
#   OPTEE              - compiles against libteec (-DUSE_OPTEE) and builds ta/$(TA_UUID).ta via TA_DEV_KIT_DIR.
TEE_MODE ?= HOST_SIM

PLATFORM ?= native

ifneq ($(CROSS_COMPILE),)
    CXX := $(CROSS_COMPILE)g++
    CC  := $(CROSS_COMPILE)gcc
else
    CXX ?= g++
    CC  ?= gcc
endif

COMMON_DIR := ../common
PROTOCOL_DIR := ../protocol
NET_DIR := ../net
ROOT := ..
BUILD := build_$(TEE_MODE)_$(PLATFORM)

COMMON_FLAGS := -O2 -g -Wall -Wextra $(CPU_FLAGS)
Host_Include := -Ihost -Iinclude -Ita -I$(COMMON_DIR) -I$(PROTOCOL_DIR) -I$(NET_DIR)
Host_Cpp_Files := $(wildcard host/*.cpp)
Host_Protocol_Files := $(wildcard $(COMMON_DIR)/*.cpp $(PROTOCOL_DIR)/*.cpp $(NET_DIR)/*.cpp)

ifeq ($(TEE_MODE),OPTEE)
    Host_Defines := -DUSE_OPTEE
    Host_Include += -I$(TEEC_EXPORT)/include
    Host_Link_Flags := -L$(TEEC_EXPORT)/lib -lteec -lssl -lcrypto -lpthread
    ifeq ($(CROSS_COMPILE),)
        Host_Link_Flags += -Wl,-rpath,$(TEEC_EXPORT)/lib
    endif
    Extra_Ta_Files := ta/codec.cpp
else
    Host_Defines :=
    Host_Link_Flags := -lssl -lcrypto -lpthread
    Extra_Ta_Files := ta/codec.cpp ta/crypto_tee.cpp ta/gateway_session.cpp
endif

Host_Cpp_Flags := $(COMMON_FLAGS) $(Host_Include) $(Host_Defines) -std=c++17 -MMD -MP

Host_Objects := $(patsubst host/%.cpp,$(BUILD)/host/%.o,$(Host_Cpp_Files)) \
                $(patsubst ta/%.cpp,$(BUILD)/ta_sim/%.o,$(Extra_Ta_Files)) \
                $(patsubst ../%.cpp,$(BUILD)/common/%.o,$(Host_Protocol_Files))

.PHONY: all ta run caps hil-quad rpi3 vm clean

rpi3:
	@./build-rpi3.sh $(PI_IP)

all: app
	@echo "built: ./app (TEE_MODE=$(TEE_MODE), PLATFORM=$(PLATFORM))$(if $(wildcard $(TA_BINARY)), + $(TA_BINARY),)"

ta:
ifneq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk),)
	$(MAKE) -C ta CROSS_COMPILE=$(or $(CROSS_COMPILE),aarch64-linux-gnu-) TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)
else ifeq ($(TEE_MODE),OPTEE)
	@echo "note: TA_DEV_KIT_DIR not set or not found; skipping Secure World .ta build"
endif

app: $(Host_Objects)
	$(CXX) $(COMMON_FLAGS) $^ -o $@ $(Host_Link_Flags)

$(BUILD)/host/%.o: host/%.cpp include/gateway_ta.h
	@mkdir -p $(dir $@)
	$(CXX) $(Host_Cpp_Flags) -c $< -o $@

$(BUILD)/ta_sim/%.o: ta/%.cpp include/gateway_ta.h
	@mkdir -p $(dir $@)
	$(CXX) $(Host_Cpp_Flags) -c $< -o $@

$(BUILD)/common/%.o: ../%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(Host_Cpp_Flags) -c $< -o $@

run: all
	./app

caps: app
	sudo setcap cap_net_raw=ep app

# Launch all 4 isolated RSU gateway processes (rsu[0]..rsu[3]) sharing one Ethernet NIC,
# matching the 4-RSU Manhattan Grid Raspberry Pi 3 HIL so the VM (over virbr0) or local NIC pairs directly with Artery.
hil-quad: caps
	@iface="$(IFACE)"; \
	if [ -z "$$iface" ]; then \
		iface=$$(ip -o -4 route show to default 2>/dev/null | awk '{print $$5; exit}'); \
	fi; \
	if [ -z "$$iface" ]; then \
		echo "error: set IFACE=<nic> for hil-quad" >&2; exit 2; \
	fi; \
	timeout="$(or $(SESSION_TIMEOUT),120)"; \
	echo "[hil-4rsu] starting rsu[0] + rsu[1] + rsu[2] + rsu[3] (4 OP-TEE TA sessions) on $$iface (Ctrl+C to stop)..."; \
	trap 'kill -TERM $$p0 $$p1 $$p2 $$p3 2>/dev/null || true; wait $$p0 $$p1 $$p2 $$p3 2>/dev/null || true' EXIT INT TERM; \
	./app rsu --name rsu[0] --iface "$$iface" --sealed rsu0.sealed --fresh --session-timeout "$$timeout" & p0=$$!; \
	./app rsu --name rsu[1] --iface "$$iface" --sealed rsu1.sealed --fresh --session-timeout "$$timeout" & p1=$$!; \
	./app rsu --name rsu[2] --iface "$$iface" --sealed rsu2.sealed --fresh --session-timeout "$$timeout" & p2=$$!; \
	./app rsu --name rsu[3] --iface "$$iface" --sealed rsu3.sealed --fresh --session-timeout "$$timeout" & p3=$$!; \
	wait $$p0 $$p1 $$p2 $$p3

# Delegate build/run to the ARM64 QEMU OP-TEE VM (VM_ARGS=hil-quad runs quad-RSU over virbr0)
vm:
	@$(CURDIR)/vm-make.sh $(or $(VM_ARGS),run)

clean:
	rm -rf build_* app ta/*.o ta/*.d ta/*.ta ta/*.elf ta/*.dmp ta/*.map \
		../common/*.o ../common/.*.cmd ../common/*.d \
		gateway.sealed* rsu*.sealed*

-include $(Host_Objects:.o=.d)
