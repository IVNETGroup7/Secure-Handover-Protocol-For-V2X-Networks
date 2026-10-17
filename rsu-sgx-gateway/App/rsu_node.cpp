// The gateway as the RSU node on the raw sockets (tee.pdf step 3): it speaks the same frames as the RSU of the
// repository's main.cpp (net/Link.h), so ../bootstrap's ESA and vehicle work with it unchanged.
//
//   radio (vehicles)  -> OT queue -> PacketManager -> enclave (ECDH, OTP, Auth_Granted, Active_02)
//                                                  -> replies on the radio, or into the IT queue
//   IT queue          -> backhaul (HTTPS session with the ESA)
//   backhaul (ESA)    -> PacketManager::onHttps (Activation_Token)

#include "modes.h"
#include "Link.h"
#include "gateway.h"
#include "packet_manager.h"
#include "packet_queue.h"
#include <csignal>
#include <cstdio>
#include <exception>
#include <random>
#include <stdexcept>

namespace
{

volatile std::sig_atomic_t gStop = 0;   // SIGINT / SIGTERM (../bootstrap stops the servers with SIGTERM)

void onStopSignal(int)
{
    gStop = 1;
}

// key of the HTTPS session with the ESA (what main.cpp's RSU sends in Session_Hello)
std::string sessionKey()
{
    std::random_device random;
    char key[65];
    for (int i = 0; i < 32; ++i) {
        std::snprintf(key + 2 * i, 3, "%02x", static_cast<unsigned>(random() & 0xff));
    }
    return key;
}

// a frame that does not parse (another program on the link): reported, not fatal
template<typename Handle>
void deliver(const std::string& node, const Bytes& frame, Handle handle)
{
    try {
        handle(deserialize(frame));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[%s] frame dropped: %s\n", node.c_str(), e.what());
    }
}

} // namespace

int runRsuNode(sgx_enclave_id_t eid, const RsuOptions& options)
{
    struct sigaction action{};
    action.sa_handler = onStopSignal; // no SA_RESTART: poll() returns at once
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);

    RawSocket radio(options.iface, kRadioEtherType);
    RawSocket backhaul(options.iface, kBackhaulEtherType);
    PacketManager gateway(eid, options.name);

    // HTTPS session with the ESA first: its Session_Ack carries CY_e, which goes into the enclave
    const Bytes esaPublicKey = openHttpsSession(backhaul, options.name, sessionKey(), options.iface,
        [] { return gStop != 0; });
    const int init = gateway.initGateway({}, esaPublicKey);
    if (init != GW_OK) {
        throw std::runtime_error(std::string("ecall_init_gateway: ") + statusName(init));
    }

    // OT queue: frames from the vehicles; IT queue: packets to the ESA
    PacketQueue ot;
    PacketQueue it;
    PacketManager::Transport transport;
    transport.radio = [&](const BootstrapMsg& msg) { sendMsg(radio, msg); };
    transport.https = [&](const BootstrapMsg& msg) { it.push(serialize(msg)); };
    gateway.setTransport(transport);

    std::printf("[%s] SGX gateway: HTTPS session with the ESA, radio on %s (EtherType 0x88b5)\n",
        options.name.c_str(), options.iface.c_str());
    std::fflush(stdout);
    signalReady(options.readyFd);

    while (!gStop) {
        waitFor({ &radio, &backhaul });
        drain(radio, [&](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Bootstrap) {
                ot.push(body);
            }
        });
        drain(backhaul, [&](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Bootstrap) {
                deliver(options.name, body, [&](const BootstrapMsg& msg) {
                    if (msg.getDestination() == options.name) { // the session is ours alone; the link is shared
                        gateway.onHttps(msg);
                    }
                });
            }
        });
        while (auto frame = ot.pop()) {
            deliver(options.name, *frame, [&](const BootstrapMsg& msg) {
                if (msg.getSender() != options.name) { // the link also returns our own frames
                    gateway.onRadio(msg);
                }
            });
        }
        while (auto packet = it.pop()) {
            sendFrame(backhaul, FrameKind::Bootstrap, *packet);
        }
    }
    return 0;
}
