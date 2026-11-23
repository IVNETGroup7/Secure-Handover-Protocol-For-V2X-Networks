# Standalone build for libtee_v2x.so against CrowNet (OMNeT++ 6.3 + INET 4 + Veins + Artery + Simu5G).
# Run inside the v2x-crownet:6.3.0 container where opp_configfilepath is available.

CONFIGFILE := $(shell opp_configfilepath)
ifeq ($(CONFIGFILE),)
$(error opp_configfilepath not found; run inside the v2x-crownet:6.3.0 container)
endif
include $(CONFIGFILE)

REPO_ROOT    := $(abspath ..)
CROWNET_ROOT := $(abspath deps/crownet)
GATEWAY_ROOT := $(REPO_ROOT)/rsu-optee-gateway
BUILD_DIR    := $(abspath build)
TARGET       := $(BUILD_DIR)/libtee_v2x.so

INET_SRC     := $(CROWNET_ROOT)/inet4/src
VEINS_SRC    := $(CROWNET_ROOT)/veins/src
VEINS_INET   := $(CROWNET_ROOT)/veins/subprojects/veins_inet/src
ARTERY_SRC   := $(CROWNET_ROOT)/artery/src
ARTERY_LIB   := $(CROWNET_ROOT)/artery/build/Release/lib
VANETZA_INC  := $(CROWNET_ROOT)/artery/extern/vanetza
VANETZA_LIB  := $(CROWNET_ROOT)/artery/extern/vanetza/build/Release/lib
SIMU5G_SRC   := $(CROWNET_ROOT)/simu5g/src
CROWNET_SRC  := $(CROWNET_ROOT)/crownet/src

PROTO_SRCS := \
	$(wildcard $(REPO_ROOT)/common/*.cpp) \
	$(wildcard $(REPO_ROOT)/protocol/*.cpp) \
	$(wildcard $(REPO_ROOT)/net/*.cpp) \
	$(GATEWAY_ROOT)/host/packet_manager.cpp \
	$(GATEWAY_ROOT)/host/tee_session.cpp \
	$(GATEWAY_ROOT)/host/benchmark.cpp \
	$(GATEWAY_ROOT)/ta/codec.cpp \
	$(GATEWAY_ROOT)/ta/crypto_tee.cpp \
	$(GATEWAY_ROOT)/ta/gateway_session.cpp

SIM_SRCS := \
	$(abspath src/BackhaulBroker.cc) \
	$(abspath src/CtraPredictor.cc) \
	$(abspath src/TeeRsuService.cc) \
	$(abspath src/VehicleTeeService.cc)

OBJS := \
	$(patsubst $(REPO_ROOT)/%.cpp,$(BUILD_DIR)/obj/%.o,$(PROTO_SRCS)) \
	$(patsubst $(abspath src)/%.cc,$(BUILD_DIR)/obj/sim/%.o,$(SIM_SRCS))

INCLUDES := \
	-I$(abspath src) \
	-I$(REPO_ROOT)/common \
	-I$(REPO_ROOT)/protocol \
	-I$(REPO_ROOT)/net \
	-I$(GATEWAY_ROOT)/include \
	-I$(GATEWAY_ROOT)/host \
	-I$(GATEWAY_ROOT)/ta \
	-I$(OMNETPP_INCL_DIR) \
	-I$(INET_SRC) \
	-I$(ARTERY_SRC) \
	-I$(ARTERY_SRC)/traci/sumo \
	-I$(VANETZA_INC) \
	-I$(VANETZA_INC)/vanetza/asn1/support \
	-I$(SIMU5G_SRC) \
	-I$(CROWNET_SRC)

CXXFLAGS_ALL := -std=c++17 -O3 -DNDEBUG=1 -fPIC -fno-omit-frame-pointer \
	-DWITH_OMNETPP -DINET_IMPORT $(INCLUDES)

LDFLAGS_ALL := -shared \
	-L$(OMNETPP_LIB_DIR) \
	-L$(INET_SRC) \
	-L$(ARTERY_LIB) \
	-L$(VANETZA_LIB) \
	-L$(SIMU5G_SRC) \
	-L$(CROWNET_SRC) \
	-Wl,-rpath,$(OMNETPP_LIB_DIR) \
	-Wl,-rpath,$(INET_SRC) \
	-Wl,-rpath,$(VEINS_SRC) \
	-Wl,-rpath,$(VEINS_INET) \
	-Wl,-rpath,$(ARTERY_LIB) \
	-Wl,-rpath,$(VANETZA_LIB) \
	-Wl,-rpath,$(SIMU5G_SRC) \
	-Wl,-rpath,$(CROWNET_SRC) \
	-lINET -lartery_core -ltraci -lvanetza_common -lsimu5g -lCROWNET \
	-loppsim -loppcommon -lssl -lcrypto

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CXX) -o $@ $(OBJS) $(LDFLAGS_ALL)

$(BUILD_DIR)/obj/%.o: $(REPO_ROOT)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_ALL) -c $< -o $@

$(BUILD_DIR)/obj/sim/%.o: $(abspath src)/%.cc
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_ALL) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

