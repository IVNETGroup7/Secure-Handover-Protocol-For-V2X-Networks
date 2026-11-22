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
#include <stdexcept>

namespace
{

volatile std::sig_atomic_t gStop = 0;

void onStopSignal(int)
{
    gStop = 1;
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

    // Step 2 (Gateway Bootstrapping):
    //   1. Generate Gateway identity keypair (X_gw, Y_gw) strictly inside the OP-TEE TA
    //   2. Exchange Session_Hello(Y_gw) / Session_Ack(CA_pub, gwCert, esaCert) over backhaul
    //   3. Pin Root CA, verify CA-signed Gateway & ESA certificates, and derive K_esa inside the TA
    Bytes gwPublicKey;
    const int idStatus = gateway.initIdentity(gwPublicKey);
    if (idStatus != GW_OK) {
        throw std::runtime_error(std::string("TA_GATEWAY_CMD_INIT_IDENTITY: ") + statusName(idStatus));
    }
    const SessionAck ack = openHttpsSession(backhaul, options.name, gwPublicKey,
        options.iface, [] { return gStop != 0; }, std::chrono::seconds(options.sessionTimeoutSeconds));
    radio.setPeerMac(backhaul.peerMac());
    const int init = gateway.initGateway(ack.caPublicKey, ack.gatewayCert, ack.esaCert);
    if (init != GW_OK) {
        throw std::runtime_error(std::string("TA_GATEWAY_CMD_INIT_GATEWAY: ") + statusName(init));
    }

    // Cloud X.509 PEM arrives dynamically from Artery BackhaulBroker over backhaul Data_Fragment
    bool hilCloudReady = false;

    // OT queue: packets from vehicles; IT queue: packets to ESA and Cloud
    PacketQueue<OtPacket> ot;
    PacketQueue<ItPacket> it;
    PacketManager::Transport transport;
    transport.radio = [&](const ProtocolMsg& msg) { sendMsg(radio, msg); };
    transport.https = [&](const ProtocolMsg& msg) { it.push({ ItPacket::To::Esa, "", serialize(msg), {}, 0, false }); };
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
            if (kind == FrameKind::Protocol) {
                ot.push({ OtPacket::Kind::Protocol, "", body, Clock::now() });
            } else if (kind == FrameKind::Data_Fragment) {
                if (auto packet = reassembler.add(body); packet && packet->to == options.name) {
                    ot.push({ OtPacket::Kind::SmartData, packet->from, std::move(packet->bytes), Clock::now() });
                }
            }
        });
        drain(backhaul, [&](FrameKind kind, const Bytes& body) {
            try {
                if (kind == FrameKind::Protocol) {
                    const ProtocolMsg msg = deserialize(body);
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
                } else if (kind == FrameKind::Data_Fragment) {
                    if (auto packet = backhaulReassembler.add(body);
                        packet && packet->from == "cloud" && packet->to == options.name) {
                        if (hilCloudReady) {
                            sendFrame(backhaul, FrameKind::Cloud_Ready, toBytes(options.name + "\n"));
                        } else {
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
                sendFrame(backhaul, FrameKind::Protocol, packet->bytes);
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

