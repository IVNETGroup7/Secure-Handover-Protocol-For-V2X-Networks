# RSU gateway on Intel SGX (tee.pdf): two binaries bound by Enclave/Enclave.edl
#   App/      Non-Secure World -> ./app               (normal Linux process: queues, packet manager, OCALLs)
#   Enclave/  Secure World     -> enclave.signed.so   (control: bootstrap; marshaling: data path)
#
#   make            builds in simulation mode (SGX_MODE=SIM: no SGX hardware needed)
#   make run        builds and runs ./app: the self-test (the repository's vehicle and ESA against the enclave)
#   make network    ESA, RSU and vehicle on the raw sockets, with this gateway as the RSU (../bootstrap --pretty)
#   make view       the same, drawn at the end as a sequence diagram (../bootstrap --view)
#   make clean
#
# Raw sockets need CAP_NET_RAW: "network" and "view" give it to ./app and ../bootstrap with sudo setcap,
# again only when a binary changes (setcap needs sudo once per build)
#   make SGX_MODE=HW    on a CPU with SGX (driver + PSW installed)
#
# Needs the Intel SGX SDK (/opt/intel/sgxsdk) and Intel SGX-SSL (/opt/intel/sgxssl); setup-vm.sh installs both
# in the VM. Based on the SDK's SampleCode/SampleEnclave/Makefile and SGX-SSL's Linux/sgx/test_app/sgx_{t,u}.mk.

SGX_SDK ?= /opt/intel/sgxsdk
SGXSSL ?= /opt/intel/sgxssl
SGX_MODE ?= SIM
SGX_DEBUG ?= 1

include $(SGX_SDK)/buildenv.mk

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
# the bootstrap at the repository root: common/ (types, crypto, constants) and protocol/ (vehicle, ESA)
BOOTSTRAP_COMMON := ../common
BOOTSTRAP_PROTOCOL := ../protocol
BOOTSTRAP_NET := ../net
ROOT := ..
# objects of the sources outside this folder (../common, ../protocol), kept apart from the bootstrap's own build
BUILD := build

ifeq ($(SGX_DEBUG), 1)
    COMMON_FLAGS := -m64 -O0 -g -Wall -Wextra
    App_Defines := -DDEBUG -UNDEBUG -UEDEBUG
else
    COMMON_FLAGS := -m64 -O2 -Wall -Wextra
    App_Defines := -DNDEBUG -UEDEBUG -UDEBUG
endif

ifeq ($(SGX_MODE), HW)
    Urts_Library := sgx_urts
    Uae_Library := sgx_uae_service
    Trts_Library := sgx_trts
    Service_Library := sgx_tservice
else
    Urts_Library := sgx_urts_sim
    Uae_Library := sgx_uae_service_sim
    Trts_Library := sgx_trts_sim
    Service_Library := sgx_tservice_sim
endif

# sgx_edger8r: our EDL, the SDK's (sgx_tstdc.edl) and SGX-SSL's (sgx_tsgxssl.edl and, without FIPS, the
# sgxssl_file.edl of nofilefunc: no file I/O in the enclave)
EDL_SEARCH := --search-path $(CURDIR)/Enclave --search-path $(SGX_SDK)/include \
              --search-path $(SGXSSL)/include --search-path $(SGXSSL)/include/nofilefunc

######## App (Non-Secure World) ########

# the self-test runs the repository's own vehicle and ESA against the enclave: all of common/ and protocol/
App_Cpp_Files := $(wildcard App/*.cpp)
App_Bootstrap_Files := $(wildcard $(BOOTSTRAP_COMMON)/*.cpp $(BOOTSTRAP_PROTOCOL)/*.cpp $(BOOTSTRAP_NET)/*.cpp)
App_Objects := App/Enclave_u.o $(App_Cpp_Files:.cpp=.o) $(patsubst ../%.cpp,$(BUILD)/app/%.o,$(App_Bootstrap_Files))
App_Include := -IApp -IEnclave -I$(BOOTSTRAP_COMMON) -I$(BOOTSTRAP_PROTOCOL) -I$(BOOTSTRAP_NET) -I$(SGX_SDK)/include
App_C_Flags := $(COMMON_FLAGS) -fPIC -Wno-attributes $(App_Include) $(App_Defines)
App_Cpp_Flags := $(App_C_Flags) -std=c++17 -MMD -MP
# libsgx_usgxssl: the untrusted side of SGX-SSL's OCALLs; libcrypto: the App's own OpenSSL (outside the enclave).
# rpath: with CAP_NET_RAW (setcap) the loader ignores LD_LIBRARY_PATH, so the SDK's libraries are found by path
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library) -l$(Uae_Library) \
                  -L$(SGXSSL)/lib64 -lsgx_usgxssl -lcrypto -lpthread -Wl,-rpath,$(SGX_SDK)/sdk_libs

######## Enclave (Secure World) ########

# crypto: common/Crypto.cpp, the same code as the vehicle and the ESA (OpenSSL from SGX-SSL here)
Enclave_Cpp_Files := $(wildcard Enclave/*.cpp)
Enclave_Bootstrap_Files := $(BOOTSTRAP_COMMON)/Crypto.cpp
Enclave_Objects := Enclave/Enclave_t.o $(Enclave_Cpp_Files:.cpp=.o) \
                   $(patsubst ../%.cpp,$(BUILD)/enclave/%.o,$(Enclave_Bootstrap_Files))
Enclave_Include := -IEnclave -I$(BOOTSTRAP_COMMON) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
                   -I$(SGX_SDK)/include/libcxx -I$(SGXSSL)/include
# trusted libc only (-nostdinc); tsgxsslio.h: the stdio replacements SGX-SSL's OpenSSL headers expect
Enclave_C_Flags := $(COMMON_FLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections \
                   -fstack-protector-strong $(MITIGATION_CFLAGS) $(Enclave_Include) -include tsgxsslio.h
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++ -std=c++17 -MMD -MP
# SGX-SSL first (tsgxssl whole), then the SDK: trts whole, the rest in a group (SDK and SGX-SSL guidelines)
Enclave_Link_Flags := $(MITIGATION_LDFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
    -L$(SGXSSL)/lib64 -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto \
    -L$(SGX_LIBRARY_PATH) -Wl,--whole-archive -l$(Trts_Library) -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tcrypto -l$(Service_Library) -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,--version-script=Enclave/Enclave.lds

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config := Enclave/Enclave.config.xml
# test signing key (RSA-3072, e = 3, as sgx_sign requires): generated once, never committed
Enclave_Key := Enclave/Enclave_private.pem

Build_Stamp := .config_$(SGX_MODE)_$(SGX_DEBUG)

.PHONY: all run network view clean
all: $(Build_Stamp) app $(Signed_Enclave_Name)
	@echo "built: ./app + $(Signed_Enclave_Name) (SGX_MODE=$(SGX_MODE), SGX_DEBUG=$(SGX_DEBUG))"

run: all
	./app

network: all .caps_app .caps_bootstrap
	$(ROOT)/bootstrap --pretty --rsu-exec $(CURDIR)/app

# colors only on a terminal (tested on make's own output)
view: all .caps_app .caps_bootstrap
	color=; [ -t 1 ] && color=--color; $(ROOT)/bootstrap --view $$color --rsu-exec $(CURDIR)/app

# ESA and vehicle: the repository's own bootstrap (its static ./bootstrap, without Docker)
$(ROOT)/bootstrap: FORCE
	$(MAKE) -C $(ROOT) build

.caps_app: app
	sudo setcap cap_net_raw=ep app
	@touch $@

.caps_bootstrap: $(ROOT)/bootstrap
	sudo setcap cap_net_raw=ep $(ROOT)/bootstrap
	@touch $@

.PHONY: FORCE
FORCE:

# another mode or debug setting: rebuild everything
$(Build_Stamp):
	@rm -rf .config_* app $(Enclave_Name) $(Signed_Enclave_Name) $(App_Objects) $(Enclave_Objects) \
		App/Enclave_u.* Enclave/Enclave_t.* $(BUILD)
	@touch $@

######## generated bridge (sgx_edger8r) ########
# one run writes the .h and the .c: the objects depend on the .h, which has the recipe

App/Enclave_u.h: Enclave/Enclave.edl
	cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl $(EDL_SEARCH)
App/Enclave_u.c: App/Enclave_u.h

Enclave/Enclave_t.h: Enclave/Enclave.edl
	cd Enclave && $(SGX_EDGER8R) --trusted Enclave.edl $(EDL_SEARCH)
Enclave/Enclave_t.c: Enclave/Enclave_t.h

######## App ########

App/Enclave_u.o: App/Enclave_u.c App/Enclave_u.h
	$(CC) $(App_C_Flags) -c $< -o $@

App/%.o: App/%.cpp App/Enclave_u.h Enclave/gateway.h
	$(CXX) $(App_Cpp_Flags) -c $< -o $@

$(BUILD)/app/%.o: ../%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(App_Cpp_Flags) -c $< -o $@

app: $(App_Objects)
	$(CXX) $^ -o $@ $(App_Link_Flags)

######## Enclave ########

Enclave/Enclave_t.o: Enclave/Enclave_t.c Enclave/Enclave_t.h
	$(CC) $(Enclave_C_Flags) -c $< -o $@

Enclave/%.o: Enclave/%.cpp Enclave/Enclave_t.h Enclave/gateway.h
	$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@

$(BUILD)/enclave/%.o: ../%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@

$(Enclave_Name): $(Enclave_Objects)
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)

$(Enclave_Key):
	openssl genrsa -out $@ -3 3072

$(Signed_Enclave_Name): $(Enclave_Name) $(Enclave_Key) $(Enclave_Config)
	$(SGX_SIGNER) sign -key $(Enclave_Key) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config)

clean:
	rm -rf .config_* app $(Enclave_Name) $(Signed_Enclave_Name) $(App_Objects) $(Enclave_Objects) \
		App/Enclave_u.* Enclave/Enclave_t.* App/*.d Enclave/*.d $(BUILD) gateway.sealed .caps_*

# header dependencies (-MMD)
-include $(App_Objects:.o=.d) $(Enclave_Objects:.o=.d)
