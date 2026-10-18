# Secure bootstrap (vehicle, RSU, ESA) without Artery/OMNeT++: C++17 + OpenSSL 3
#   make          builds and runs the 3 processes (ESA, RSU, vehicle) over raw sockets
#   make pretty   the same, with the output of each component separated by a bar
#   make build    only builds ./bootstrap
#   make clean
#
# Raw sockets need CAP_NET_RAW. Without sudo, the processes run in a Docker container (no VM: same kernel),
# where they have it: an empty image (FROM scratch) with the static ./bootstrap, and --network none
# (the container's own loopback only).
#
#   common/    message, payloads, crypto, vehicle traits, time
#   protocol/  bootstrap protocol (BootstrapService, ExternalSecurityAgent) and its API (Bootstrap.h)
#   net/       raw Ethernet sockets (AF_PACKET)
#   main.cpp   one process per node

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -g
CPPFLAGS += -Icommon -Iprotocol -Inet -MMD -MP
LDFLAGS  += -static -Wl,--no-warnings   # static: runs in an empty image (no-warnings: libcrypto's dlopen notes)
LDLIBS   += -lssl -lcrypto   # libssl: the HTTPS of the cloud (net/Https.h)

BUILD := build
LIB   := $(BUILD)/libbootstrap.a
BIN   := bootstrap
IMAGE := secure-bootstrap

LIB_SRCS := $(wildcard common/*.cpp protocol/*.cpp net/*.cpp)
LIB_OBJS := $(LIB_SRCS:%.cpp=$(BUILD)/%.o)
MAIN_OBJ := $(BUILD)/main.o

.PHONY: run pretty build clean
run: $(BUILD)/image
	docker run --rm --network none $(IMAGE)

pretty: $(BUILD)/image
	docker run --rm --network none $(IMAGE) --pretty

build: $(BIN)

$(LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

$(BIN): $(MAIN_OBJ) $(LIB)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

# image rebuilt only when ./bootstrap changes (stamp file)
$(BUILD)/image: $(BIN)
	@mkdir -p $(BUILD)/docker
	cp $(BIN) $(BUILD)/docker/bootstrap
	printf 'FROM scratch\nCOPY bootstrap /bootstrap\nENTRYPOINT ["/bootstrap"]\n' | docker build -q -t $(IMAGE) -f - $(BUILD)/docker
	@touch $@

clean:
	rm -rf $(BUILD) $(BIN)
	-docker image rm -f $(IMAGE) >/dev/null 2>&1

-include $(LIB_OBJS:.o=.d) $(MAIN_OBJ:.o=.d)
