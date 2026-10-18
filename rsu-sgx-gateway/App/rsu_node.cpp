// The gateway as the RSU node on the raw sockets (tee.pdf step 3, Fig. 5 of the paper): it speaks the same
// frames as the RSU of the repository's main.cpp (net/Link.h), so ../bootstrap's ESA and vehicle work with it
// unchanged; with a cloud (net/Https.h), the vehicles' SmartData goes on to it.
//
//   radio (vehicles)   -> OT queue -> PacketManager -> enclave: bootstrap (ECDH, OTP, Auth_Granted, Active_02)
//                                                             or Secure Marshaling (SmartData)
//                                                  -> replies on the radio, or into the IT queue
//   IT queue           -> backhaul (HTTPS session with the ESA)  or  HTTPS POST to the cloud (TLS here, in the App,
//                         until it moves into the enclave)
//   backhaul (ESA)     -> PacketManager::onHttps (Activation_Token)

#include "modes.h"
#include "Https.h"
#include "Link.h"
#include "Trace.h"
#include "gateway.h"
#include "packet_manager.h"
#include "packet_queue.h"
#include <csignal>
#include <cstdio>
#include <exception>
#include <memory>
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

// IT queue -> cloud: one HTTPS POST of the marshaled SmartData
void postToCloud(HttpsClient& cloud, const std::string& node, const ItPacket& packet, PacketManager& gateway)
{
    if (packet.traced) {
        trace::send(node, std::string("POST ") + kSmartDataPath, "cloud", packet.vehicle, "HTTPS", packet.bytes.size());
    }
    try {
        bool newSession = false;
        const HttpResponse response = cloud.post(kSmartDataPath, "application/json", packet.bytes,
            { { "X-Gateway", node }, { "X-Vehicle", packet.vehicle } }, &newSession);
        if (newSession) {
            trace::detail(node, "HTTPS session with the cloud: " + cloud.session() + ", certificate verified");
        }
        const bool ok = response.status / 100 == 2;
        if (ok) {
            gateway.benchmark().posted(packet.otSize, Clock::now() - packet.received);
        } else {
            gateway.benchmark().postFailed(packet.otSize);
        }
        if (packet.traced || !ok) {
            trace::check(node, ok, "cloud: " + std::to_string(response.status) + " " + response.reason + " "
                + response.body);
        }
    } catch (const std::exception& e) {
        gateway.benchmark().postFailed(packet.otSize);
        trace::check(node, false, std::string("POST to the cloud: ") + e.what());
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

    // HTTPS session with the cloud (when there is one): its certificate verified against the one we trust
    std::unique_ptr<HttpsClient> cloud;
    std::string cloudSession;
    if (!options.cloudCertificate.empty()) {
        cloud = std::make_unique<HttpsClient>(options.cloudAddress, options.cloudPort, options.cloudCertificate);
        cloudSession = cloud->connect();
    }

    // OT queue: packets from the vehicles; IT queue: packets to the ESA and to the cloud
    PacketQueue<OtPacket> ot;
    PacketQueue<ItPacket> it;
    PacketManager::Transport transport;
    transport.radio = [&](const BootstrapMsg& msg) { sendMsg(radio, msg); };
    transport.https = [&](const BootstrapMsg& msg) { it.push({ ItPacket::To::Esa, "", serialize(msg), {}, 0, false }); };
    if (cloud) {
        transport.cloud = [&](ItPacket packet) { it.push(std::move(packet)); };
    }
    gateway.setTransport(transport);

    std::printf("[%s] SGX gateway: HTTPS session with the ESA, radio on %s (EtherType 0x88b5)\n",
        options.name.c_str(), options.iface.c_str());
    if (cloud) {
        std::printf("[%s] HTTPS session with the cloud %s:%u: %s, certificate verified (%s)\n", options.name.c_str(),
            options.cloudAddress.c_str(), options.cloudPort, cloudSession.c_str(), options.cloudCertificate.c_str());
    }
    std::fflush(stdout);
    signalReady(options.readyFd);

    Reassembler reassembler;
    auto step = [&] {
        drain(radio, [&](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Bootstrap) {
                ot.push({ OtPacket::Kind::Bootstrap, "", body, Clock::now() });
            } else if (kind == FrameKind::Data_Fragment) {
                if (auto packet = reassembler.add(body); packet && packet->to == options.name) {
                    ot.push({ OtPacket::Kind::SmartData, packet->from, std::move(packet->bytes), Clock::now() });
                }
            }
        });
        drain(backhaul, [&](FrameKind kind, const Bytes& body) {
            if (kind != FrameKind::Bootstrap) {
                return;
            }
            try {
                const BootstrapMsg msg = deserialize(body);
                if (msg.getDestination() == options.name) { // the session is ours alone; the link is shared
                    gateway.onHttps(msg);
                }
            } catch (const std::exception& e) {
                std::fprintf(stderr, "[%s] frame dropped: %s\n", options.name.c_str(), e.what());
            }
        });
        while (auto packet = ot.pop()) {
            gateway.onOtPacket(*packet);
        }
        while (auto packet = it.pop()) {
            if (packet->to == ItPacket::To::Esa) {
                sendFrame(backhaul, FrameKind::Bootstrap, packet->bytes);
            } else {
                postToCloud(*cloud, options.name, *packet, gateway);
            }
        }
    };
    while (!gStop) {
        waitFor({ &radio, &backhaul });
        step();
    }
    step(); // what already arrived when the stop came

    if (!gateway.benchmark().empty()) {
        gateway.benchmark().print(stdout, options.name);
    }
    if (reassembler.dropped() > 0) {
        std::printf("[%s] %zu SmartData packet(s) lost on the radio (a fragment missing)\n", options.name.c_str(),
            reassembler.dropped());
    }
    return 0;
}
