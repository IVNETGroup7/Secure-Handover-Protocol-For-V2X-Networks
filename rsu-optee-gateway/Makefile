# OP-TEE RSU Gateway (Arm TrustZone on QEMU ARMv8-A and Raspberry Pi 5 Cortex-A76)
#
# Structure:
#   include/    shared TA UUID, command IDs, and status codes (gateway_ta.h)
#   ta/         Secure World Trusted Application (GlobalPlatform TEE Internal Core API)
#   host/       Normal World Client Application (GlobalPlatform TEE Client API / libteec)
#
# Targets:
#   make              build ./app (and the .ta when TA_DEV_KIT_DIR is present)
#   make run          build and run the self-test (bootstrap, tamper checks, Secure Marshaling, Secrecy Forwarding)
#   make network      run ../bootstrap --pretty --rsu-exec ./app (real ESA + vehicle + Cloud + OP-TEE RSU)
#   make bench        run the Secure Marshaling throughput/latency benchmark across payload sizes
#   make rpi5         cross-compile ./app (and .ta if TA_DEV_KIT_DIR is set) for Raspberry Pi 5 (-mcpu=cortex-a76)
#   make vm           delegate the build/run to the ARM64 OP-TEE QEMU VM via ./vm-make.sh
#   make clean        remove build artifacts, sealed state files, and capability stamps

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
ifeq ($(PLATFORM),rpi5)
    CROSS_COMPILE ?= aarch64-linux-gnu-
    CPU_FLAGS ?= -mcpu=cortex-a76
endif

ifneq ($(CROSS_COMPILE),)
    CXX := $(CROSS_COMPILE)g++
    CC  := $(CROSS_COMPILE)gcc
else
    CXX ?= g++
    CC  ?= gcc
endif

BOOTSTRAP_COMMON := ../common
BOOTSTRAP_PROTOCOL := ../protocol
BOOTSTRAP_NET := ../net
ROOT := ..
BUILD := build_$(TEE_MODE)_$(PLATFORM)

COMMON_FLAGS := -O2 -g -Wall -Wextra $(CPU_FLAGS)
Host_Include := -Ihost -Iinclude -Ita -I$(BOOTSTRAP_COMMON) -I$(BOOTSTRAP_PROTOCOL) -I$(BOOTSTRAP_NET)
Host_Cpp_Files := $(wildcard host/*.cpp)
Host_Bootstrap_Files := $(wildcard $(BOOTSTRAP_COMMON)/*.cpp $(BOOTSTRAP_PROTOCOL)/*.cpp $(BOOTSTRAP_NET)/*.cpp)

ifeq ($(TEE_MODE),OPTEE)
    Host_Defines := -DUSE_OPTEE
    Host_Include += -I$(TEEC_EXPORT)/include
    Host_Link_Flags := -L$(TEEC_EXPORT)/lib -lteec -lssl -lcrypto -lpthread -Wl,-rpath,$(TEEC_EXPORT)/lib
    Extra_Ta_Files := ta/codec.cpp
else
    Host_Defines :=
    Host_Link_Flags := -lssl -lcrypto -lpthread
    Extra_Ta_Files := ta/codec.cpp ta/crypto_tee.cpp ta/gateway_session.cpp
endif

Host_Cpp_Flags := $(COMMON_FLAGS) $(Host_Include) $(Host_Defines) -std=c++17 -MMD -MP

Host_Objects := $(patsubst host/%.cpp,$(BUILD)/host/%.o,$(Host_Cpp_Files)) \
                $(patsubst ta/%.cpp,$(BUILD)/ta_sim/%.o,$(Extra_Ta_Files)) \
                $(patsubst ../%.cpp,$(BUILD)/common/%.o,$(Host_Bootstrap_Files))

CLOUD := --cloud $(CURDIR)/cloud.crt
SMARTDATA := --smartdata 32,1024,65535

.PHONY: all ta run network bench rpi5 vm clean FORCE ensure_caps

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

ensure_caps: app $(ROOT)/bootstrap
	@sudo setcap cap_net_raw=ep app 2>/dev/null || true
	@sudo setcap cap_net_raw=ep $(ROOT)/bootstrap 2>/dev/null || true

network: all ensure_caps
	$(ROOT)/bootstrap --pretty --rsu-exec $(CURDIR)/app $(CLOUD) $(SMARTDATA)

bench: all ensure_caps
	$(ROOT)/bootstrap --pretty --rsu-exec $(CURDIR)/app $(CLOUD) \
		--smartdata 32,256,1024,4096,16384,65535 --smartdata-count 100

# Cross-compile for Raspberry Pi 5 (Arm Cortex-A76, ARMv8.2-A)
rpi5:
	$(MAKE) PLATFORM=rpi5 CROSS_COMPILE=aarch64-linux-gnu- all

# Delegate build/run to the ARM64 QEMU OP-TEE VM
vm:
	@$(CURDIR)/vm-make.sh $(or $(VM_ARGS),run)

$(ROOT)/bootstrap: FORCE
	$(MAKE) -C $(ROOT) CXX=$(CXX) build

FORCE:

clean:
	rm -rf build_* app ta/*.o ta/*.d ta/*.ta ta/*.elf ta/*.dmp ta/*.map \
		gateway.sealed* .caps_* cloud.crt

-include $(Host_Objects:.o=.d)
