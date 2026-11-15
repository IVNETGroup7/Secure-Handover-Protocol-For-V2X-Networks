#include "modes.h"
#include "Link.h"
#include "SmartData.h"
#include "gateway_ta.h"
#include "packet_manager.h"
#include "packet_queue.h"
#include <chrono>
#include <csignal>
#include <cstdio>
#include <exception>
#include <random>
#include <stdexcept>

namespace
{

volatile std::sig_atomic_t gStop = 0;

void onStopSignal(int)
{
    gStop = 1;
}

std::string sessionKey()
{
    std::random_device random;
    char key[65];
    for (int i = 0; i < 32; ++i) {
        std::snprintf(key + 2 * i, 3, "%02x", static_cast<unsigned>(random() & 0xff));
    }
    return key;
}

} // namespace

int runRsuNode(TeeSession& tee, const RsuOptions& options)
{
    struct sigaction action{};
    action.sa_handler = onStopSignal; // no SA_RESTART: poll() returns at once
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);

    RawSocket radio(options.iface, kRadioEtherType);
    RawSocket backhaul(options.iface, kBackhaulEtherType);
    PacketManager gateway(tee, options.name);

    // Optional simulation-time clock anchor (used in Artery HIL mode so RPi3 RSU hardware clocks align with simTime)
    bool clockAnchored = false;
    std::chrono::steady_clock::time_point wallRef{};
    int64_t simRefNs = 0;
    gateway.setClock([&]() -> uint64_t {
        if (!clockAnchored) {
            return static_cast<uint64_t>(SimTime::now().ns());
        }
        const auto elapsedNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - wallRef).count();
        const int64_t t = simRefNs + elapsedNs;
        return static_cast<uint64_t>(t > 0 ? t : 0);
    });

    // HTTPS session with the ESA first: Session_Hello with my certificate (CY_g); its Session_Ack carries CY_e,
    // which goes into the OP-TEE TA with the certificate
    const GatewayCertificate certificate = newGatewayCertificate(options.name);
    gateway.setGatewayPublicKey(certificate.publicKey);
    const Bytes esaPublicKey = openHttpsSession(backhaul, options.name, sessionKey(), certificate.certificate,
        options.iface, [] { return gStop != 0; }, std::chrono::seconds(options.sessionTimeoutSeconds));
    const int init = gateway.initGateway(certificate.certificate, esaPublicKey);
    if (init != GW_OK) {
        throw std::runtime_error(std::string("TA_GATEWAY_CMD_INIT_GATEWAY: ") + statusName(init));
    }

    // Cloud X.509 PEM arrives dynamically from Artery BackhaulBroker over backhaul Data_Fragment
    bool hilCloudReady = false;

    // OT queue: packets from vehicles; IT queue: packets to ESA and Cloud
    PacketQueue<OtPacket> ot;
    PacketQueue<ItPacket> it;
    PacketManager::Transport transport;
    transport.radio = [&](const BootstrapMsg& msg) { sendMsg(radio, msg); };
    transport.https = [&](const BootstrapMsg& msg) { it.push({ ItPacket::To::Esa, "", serialize(msg), {}, 0, false }); };
    transport.cloud = [&](ItPacket packet) { it.push(std::move(packet)); };
    transport.cloudRefused = [&]() {
        if (hilCloudReady) {
            sendFrame(backhaul, FrameKind::Cloud_Refused, toBytes(options.name + "\n"));
        }
    };
    gateway.setTransport(transport);

    std::printf("[%s] OP-TEE gateway: session #%llu (storage %s), HTTPS session with ESA, radio on %s (0x88b5)\n",
        options.name.c_str(), static_cast<unsigned long long>(tee.sessionId()), tee.storageId().c_str(),
        options.iface.c_str());
    std::fflush(stdout);

    Reassembler reassembler;
    Reassembler backhaulReassembler;
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
            try {
                if (kind == FrameKind::Bootstrap) {
                    const BootstrapMsg msg = deserialize(body);
                    if (msg.getDestination() == options.name) { // the session is ours alone; the link is shared
                        gateway.onHttps(msg);
                    }
                } else if (kind == FrameKind::Clock_Anchor) {
                    if (const auto simNs = parseClockAnchor(body)) {
                        wallRef = std::chrono::steady_clock::now();
                        simRefNs = *simNs;
                        clockAnchored = true;
                    }
                } else if (kind == FrameKind::Handover_Trigger) {
                    if (const auto trig = parseHandoverTrigger(body); trig && trig->rsu == options.name) {
                        gateway.startHandover(trig->session, trig->targetRsu);
                    }
                } else if (kind == FrameKind::Data_Fragment && !hilCloudReady) {
                    if (auto packet = backhaulReassembler.add(body);
                        packet && packet->from == "cloud" && packet->to == options.name) {
                        const std::string pem(packet->bytes.begin(), packet->bytes.end());
                        const int session = gateway.initCloudSession(pem, kCloudAddress);
                        if (session == GW_OK) {
                            hilCloudReady = true;
                            sendFrame(backhaul, FrameKind::Cloud_Ready, toBytes(options.name + "\n"));
                            std::printf("[%s] Cloud session pinned in OP-TEE TA (HIL backhaul bridge)\n",
                                options.name.c_str());
                            std::fflush(stdout);
                        } else {
                            std::fprintf(stderr, "[%s] TA_GATEWAY_CMD_INIT_CLOUD_SESSION: %s\n",
                                options.name.c_str(), statusName(session));
                        }
                    }
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
            } else if (hilCloudReady) {
                sendData(backhaul, options.name, "cloud", packet->bytes);
                gateway.benchmark().posted(packet->otSize, Clock::now() - packet->received);
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

