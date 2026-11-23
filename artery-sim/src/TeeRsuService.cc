// Include INET 4 / OMNeT++ headers BEFORE project headers (common/SimTime.h defines global ::SimTime).
#include <inet/common/packet/Packet.h>
#include <inet/common/packet/chunk/BytesChunk.h>
#include <inet/networklayer/common/L3AddressResolver.h>
#include <inet/networklayer/common/L3AddressTag_m.h>
#include <inet/transportlayer/common/L4PortTag_m.h>
#include <omnetpp.h>

#include "TeeRsuService.h"
#include "BackhaulBroker.h"
#include "Link.h"
#include "MessageType.h"
#include "SimTime.h"
#include "gateway_ta.h"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

Define_Module(TeeRsuService)

namespace
{

// Push peer RSU CA certificates to physical RPi3 TAs and re-anchor cRealTimeScheduler after init completes.
struct HilSchedulerSync : public omnetpp::cISimulationLifecycleListener
{
    HilSchedulerSync(omnetpp::cSimulation* sim, TeeRsuService* rsu) : mSim(sim), mRsu(rsu) {}

    void lifecycleEvent(omnetpp::SimulationLifecycleEventType eventType, omnetpp::cObject*) override
    {
        if (eventType == omnetpp::LF_POST_NETWORK_INITIALIZE && mRsu) {
            mRsu->syncHilPeers();
        }
        if ((eventType == omnetpp::LF_POST_NETWORK_INITIALIZE
                || eventType == omnetpp::LF_ON_SIMULATION_START)
            && mSim) {
            if (auto* sched = mSim->getScheduler()) {
                sched->executionResumed();
            }
        }
    }

    omnetpp::cSimulation* mSim = nullptr;
    TeeRsuService* mRsu = nullptr;
};

// "rsu[0]" -> "rsu0": a storage object / file name
std::string fileName(const std::string& name)
{
    std::string out;
    for (char c : name) {
        if (c != '[' && c != ']') {
            out += c;
        }
    }
    return out;
}

// K_g given as hex ("" -> empty: generated in the TA)
Bytes hexKey(const std::string& hex)
{
    Bytes key;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        key.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return key;
}

} // namespace

TeeRsuService::~TeeRsuService()
{
    shutdownHil();
    mGateway.reset();
    mTee.reset();
}

void TeeRsuService::shutdownHil()
{
    mHilSyncListener.reset();
    if (mHilPollMsg) {
        cancelAndDelete(mHilPollMsg);
        mHilPollMsg = nullptr;
    }
    mHilRadio.reset();
    mHilBackhaul.reset();
}

void TeeRsuService::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == inet::INITSTAGE_LOCAL) {
        mName = getParentModule()->getFullName(); // <rsu>.app[0]
        mLocalPort = par("localPort").intValue();
        mVehiclePort = par("vehiclePort").intValue();
        mMarshalLatencySignal = registerSignal("marshalLatencyUs");
        mHandoverGrantedSignal = registerSignal("handoverGranted");

        mEnableHil = par("enableHil").boolValue();
        mHilIface = par("hilIface").stdstringValue();
        if (mHilIface.empty()) {
            if (const char* envIface = std::getenv("HIL_IFACE")) {
                mHilIface = envIface;
            }
        }
    } else if (stage == inet::INITSTAGE_APPLICATION_LAYER) {
        mBroker = dynamic_cast<BackhaulBroker*>(getSimulation()->getSystemModule()->getSubmodule(
            par("backhaulModule").stringValue()));
        if (!mBroker) {
            throw omnetpp::cRuntimeError("%s: no BackhaulBroker '%s' in the network", mName.c_str(),
                par("backhaulModule").stringValue());
        }

        mSocket.setOutputGate(gate("socketOut"));
        mSocket.setCallback(this);
        mSocket.bind(mLocalPort);

        if (mEnableHil) {
            mBroker->otpAlgo();
            initHil();
        } else {
            initLocalTee();
        }
    }
}

void TeeRsuService::initHil()
{
    if (mHilIface.empty()) {
        throw omnetpp::cRuntimeError(
            "%s: HIL enabled but no host interface specified; set HIL_IFACE=<iface> or pass "
            "--*.rsu[*].app[0].hilIface=\\\"<iface>\\\"",
            mName.c_str());
    }
    EV_INFO << mName << ": Hardware-in-the-Loop (HIL) enabled on interface " << mHilIface
            << " (zero local RSU TEE state on host PC)\n";
    try {
        mHilRadio = std::make_unique<RawSocket>(mHilIface, kRadioEtherType);
        mHilBackhaul = std::make_unique<RawSocket>(mHilIface, kBackhaulEtherType);
    } catch (const std::exception& e) {
        throw omnetpp::cRuntimeError("%s: failed to initialize HIL on %s: %s",
            mName.c_str(), mHilIface.c_str(), e.what());
    }

    const int timeoutMs = static_cast<int>(par("hilHandshakeTimeout").doubleValue() * 1000.0);
    std::printf("[HIL] %s waiting up to %.1fs for physical RSU Session_Hello on %s (0x88b6)...\n",
        mName.c_str(), timeoutMs / 1000.0, mHilIface.c_str());
    std::fflush(stdout);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    bool registered = false;
    while (!registered && std::chrono::steady_clock::now() < deadline) {
        waitFor({ mHilBackhaul.get() }, 100);
        drain(*mHilBackhaul, [&](FrameKind kind, const Bytes& body) {
            if (registered || kind != FrameKind::Session_Hello) {
                return;
            }
            const auto hello = parseSessionHello(body);
            if (!hello || hello->rsu != mName) {
                return;
            }
            const auto piMac = mHilBackhaul->lastSrcMac();
            mHilBackhaul->setPeerMac(piMac);
            mHilRadio->setPeerMac(piMac);
            mGatewayPublicKey = hello->gatewayPublicKey;
            const auto reg = mBroker->registerRsu(mName, mGatewayPublicKey,
                [this](const ProtocolMsg& msg) { onBackhaul(msg); },
                [this](const std::string& peer, const Bytes& cert) { mPendingPeers[peer] = cert; });
            mCaPublicKey = reg.caPublicKey;
            mGatewayCert = reg.gatewayCert;
            mEsaCert = reg.esaCert;
            sendHilSessionAck();
            registered = true;
            std::printf("[HIL] %s registered physical RSU TEE CY_g (%zu B) with CA/ESA -> Session_Ack sent\n",
                mName.c_str(), mGatewayPublicKey.size());
            std::fflush(stdout);
        });
    }
    if (!registered) {
        throw omnetpp::cRuntimeError(
            "%s: timed out waiting for physical RSU Session_Hello on %s (start './app rsu --name %s ...' on RPi3)",
            mName.c_str(), mHilIface.c_str(), mName.c_str());
    }

    // Pin the Cloud certificate on the physical RSU BEFORE simulation time starts so all 4 RSUs
    // finish OP-TEE TA_GATEWAY_CMD_INIT_CLOUD_SESSION (~2 s each on RPi3) prior to t=0.
    const Bytes cloudPem = toBytes(mBroker->cloudCertificate());
    auto lastCloudSent = std::chrono::steady_clock::time_point::min();
    while (!mHilCloudReady && std::chrono::steady_clock::now() < deadline) {
        const auto now = std::chrono::steady_clock::now();
        if (lastCloudSent == std::chrono::steady_clock::time_point::min()
            || now - lastCloudSent >= std::chrono::milliseconds(1000)) {
            sendData(*mHilBackhaul, "cloud", mName, cloudPem);
            lastCloudSent = now;
        }
        waitFor({ mHilBackhaul.get() }, 100);
        drain(*mHilBackhaul, [&](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Cloud_Ready) {
                if (auto tag = parseRsuTag(body); tag && *tag == mName) {
                    mHilCloudReady = true;
                }
            } else if (kind == FrameKind::Session_Hello) {
                if (auto hello = parseSessionHello(body);
                    hello && hello->rsu == mName && hello->gatewayPublicKey == mGatewayPublicKey) {
                    sendHilSessionAck();
                }
            }
        });
    }
    if (!mHilCloudReady) {
        throw omnetpp::cRuntimeError(
            "%s: timed out waiting for physical RSU Cloud_Ready on %s",
            mName.c_str(), mHilIface.c_str());
    }
    std::printf("[HIL] %s cloud session pinned (Cloud_Ready received)\n", mName.c_str());
    std::fflush(stdout);

    if (!mHilSyncListener) {
        mHilSyncListener = std::make_unique<HilSchedulerSync>(getSimulation(), this);
        omnetpp::getEnvir()->addLifecycleListener(mHilSyncListener.get());
    }
    if (auto* sched = getSimulation()->getScheduler()) {
        sched->executionResumed();
    }

    mHilPollMsg = new omnetpp::cMessage("hilPoll");
    scheduleAt(omnetpp::simTime() + omnetpp::simtime_t(1, omnetpp::SIMTIME_MS), mHilPollMsg);
}

void TeeRsuService::syncHilPeers()
{
    if (mHilPeersSynced || !mHilBackhaul) {
        return;
    }
    mHilPeersSynced = true;
    const int timeoutMs = static_cast<int>(par("hilHandshakeTimeout").doubleValue() * 1000.0);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    while (!mPendingPeers.empty() && std::chrono::steady_clock::now() < deadline) {
        for (const auto& [peerName, peerCert] : mPendingPeers) {
            sendFrame(*mHilBackhaul, FrameKind::Peer_Cert, packPeerCert(mName, peerName, peerCert));
        }
        const auto retryAt = std::chrono::steady_clock::now() + kSessionRetry;
        while (!mPendingPeers.empty() && std::chrono::steady_clock::now() < retryAt
            && std::chrono::steady_clock::now() < deadline) {
            waitFor({ mHilBackhaul.get() }, 100);
            drain(*mHilBackhaul, [&](FrameKind kind, const Bytes& body) {
                if (kind == FrameKind::Peer_Cert_Ack) {
                    if (const auto ack = parsePeerCertAck(body); ack && ack->destRsu == mName) {
                        mPendingPeers.erase(ack->peerName);
                    }
                }
            });
        }
    }
    if (!mPendingPeers.empty()) {
        throw omnetpp::cRuntimeError("%s: timed out registering %zu peer RSU cert(s) on %s",
            mName.c_str(), mPendingPeers.size(), mHilIface.c_str());
    }
    std::printf("[HIL] %s peer RSU certificates verified in TrustZone (K_rsu ready)\n", mName.c_str());
    std::fflush(stdout);
}

void TeeRsuService::flushLocalPendingPeers()
{
    for (const auto& [peerName, peerCert] : mPendingPeers) {
        const int st = mGateway->registerPeerRsu(peerName, peerCert);
        if (st != GW_OK) {
            throw omnetpp::cRuntimeError("%s: TA_GATEWAY_CMD_REGISTER_PEER_RSU(%s): %s",
                mName.c_str(), peerName.c_str(), statusName(st));
        }
    }
    mPendingPeers.clear();
}

void TeeRsuService::initLocalTee()
{
    // This RSU's own OP-TEE TA session, with its own Secure Storage object (fresh unless freshState = false)
    std::string sealed = par("sealedStatePath").stdstringValue();
    if (sealed.empty()) {
        sealed = fileName(mName) + ".sealed";
    }
    mTee = std::make_unique<TeeSession>(sealed, par("freshState").boolValue(), mBroker->otpAlgo());
    mGateway = std::make_unique<PacketManager>(*mTee, mName);

    // Step 2: generate Gateway identity (X_gw, CY_g) inside TA, certify via CA, verify ESA cert & derive K_esa
    const int idStatus = mGateway->initIdentity(mGatewayPublicKey);
    if (idStatus != GW_OK) {
        throw omnetpp::cRuntimeError("%s: TA_GATEWAY_CMD_INIT_IDENTITY: %s", mName.c_str(), statusName(idStatus));
    }
    const auto reg = mBroker->registerRsu(mName, mGatewayPublicKey,
        [this](const ProtocolMsg& msg) { onBackhaul(msg); },
        [this](const std::string& peerName, const Bytes& peerCert) {
            mPendingPeers[peerName] = peerCert;
            if (mLocalGatewayReady) {
                flushLocalPendingPeers();
            }
        });

    const int init = mGateway->initGateway(reg.caPublicKey, reg.gatewayCert, reg.esaCert,
        hexKey(par("groupKey").stdstringValue()));
    if (init != GW_OK) {
        throw omnetpp::cRuntimeError("%s: TA_GATEWAY_CMD_INIT_GATEWAY: %s", mName.c_str(), statusName(init));
    }
    mLocalGatewayReady = true;
    flushLocalPendingPeers();
    const int cloud = mGateway->initCloudSession(mBroker->cloudCertificate(), kCloudAddress);
    if (cloud != GW_OK) {
        throw omnetpp::cRuntimeError("%s: TA_GATEWAY_CMD_INIT_CLOUD_SESSION: %s", mName.c_str(), statusName(cloud));
    }

    PacketManager::Transport transport;
    transport.radio = [this](const ProtocolMsg& msg) { sendRadio(msg); };
    transport.https = [this](const ProtocolMsg& msg) { sendHttps(msg); };
    transport.cloud = [this](ItPacket packet) { mBroker->postToCloud(mName, packet.bytes); };
    mGateway->setTransport(transport);
}

void TeeRsuService::onRadioRx(const ProtocolMsg& msg)
{
    if (msg.getType() == Handover_Predict && msg.getDestination() == mName) {
        ++mHandoversTriggered;
    }
    if (mEnableHil) {
        if (!mHilRadio || msg.getDestination() != mName) {
            return;
        }
        sendMsg(*mHilRadio, msg);
        EV_INFO << mName << " [HIL]: forwarded 5G NR radio " << messageTypeName(msg.getType())
                << " from " << msg.getSender() << " to physical RSU on " << mHilIface << "\n";
        return;
    }
    if (msg.getType() == Secure_Data) {
        if (msg.getDestination() == mName) {
            secureData(msg);
        }
        return;
    }
    mGateway->onRadio(msg); // filters by destination (logical unicast)
}

void TeeRsuService::socketDataArrived(inet::UdpSocket*, inet::Packet* packet)
{
    std::unique_ptr<inet::Packet> owned(packet);
    try {
        const auto addrInd = packet->findTag<inet::L3AddressInd>();
        const auto portInd = packet->findTag<inet::L4PortInd>();
        const auto chunk = packet->peekDataAsBytes();
        const Bytes wire = chunk->getBytes();
        const ProtocolMsg msg = deserialize(wire);
        if (addrInd) {
            mPeerEndpoints[msg.getSender()] = {
                addrInd->getSrcAddress(),
                portInd ? portInd->getSrcPort() : mVehiclePort
            };
        }
        onRadioRx(msg);
    } catch (const std::runtime_error& e) {
        EV_ERROR << mName << ": 5G NR UDP frame dropped: " << e.what() << "\n";
    }
}

void TeeRsuService::socketErrorArrived(inet::UdpSocket*, inet::Indication* indication)
{
    EV_WARN << mName << ": UDP socket error indication: " << indication->getName() << "\n";
    delete indication;
}

void TeeRsuService::socketClosed(inet::UdpSocket*)
{
}

// Secure_Data: OT packet -> TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT -> IT packet for the cloud
void TeeRsuService::secureData(const ProtocolMsg& msg)
{
    // the TA invocation's own (wall clock) time: simulation time does not move inside an event
    const auto start = std::chrono::steady_clock::now();
    const Reply reply = mGateway->marshal(getPayload(msg), static_cast<uint64_t>(SimTime::now().ns()));
    const double us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count();
    emit(mMarshalLatencySignal, us);
    if (reply.status != GW_OK) {
        ++mMarshalRefused;
        EV_WARN << mName << ": SmartData of " << msg.getSender() << " refused by the TA (" << statusName(reply.status)
            << ")\n";
        return;
    }
    ++mMarshaled;
    mBroker->postToCloud(mName, reply.payload);
}

void TeeRsuService::onBackhaul(const ProtocolMsg& msg)
{
    Enter_Method("onBackhaul");
    if (mEnableHil && mHilBackhaul) {
        try {
            if (msg.getType() == Activation_Token) {
                sendHilClockAnchor();
            }
            sendMsg(*mHilBackhaul, msg);
            EV_INFO << mName << " [HIL]: forwarded backhaul " << messageTypeName(msg.getType())
                    << " to physical RSU on " << mHilIface << "\n";
        } catch (const std::exception& e) {
            EV_ERROR << mName << " [HIL]: sendMsg backhaul error: " << e.what() << "\n";
        }
        return;
    }
    try {
        mGateway->onHttps(msg); // Activation_Token, Forwarding_Notice
    } catch (const std::runtime_error& e) {
        EV_ERROR << mName << ": backhaul message dropped: " << e.what() << "\n";
    }
}

void TeeRsuService::sendHttps(const ProtocolMsg& msg)
{
    mBroker->sendBackhaul(msg);
}

void TeeRsuService::sendRadio(const ProtocolMsg& msg)
{
    if (msg.getType() == Forwarding_Granted) {
        ++mHandoversGranted;
        emit(mHandoverGrantedSignal, mHandoversGranted);
    }

    const std::string& dest = msg.getDestination();
    PeerEndpoint ep;
    const auto it = mPeerEndpoints.find(dest);
    if (it != mPeerEndpoints.end()) {
        ep = it->second;
    } else {
        if (!inet::L3AddressResolver().tryResolve(dest.c_str(), ep.addr)) {
            EV_WARN << mName << ": cannot resolve 5G NR destination '" << dest << "' for "
                    << messageTypeName(msg.getType()) << "\n";
            return;
        }
        ep.port = mVehiclePort;
    }

    const Bytes wire = serialize(msg);
    auto* pkt = new inet::Packet(messageTypeName(msg.getType()));
    pkt->insertAtBack(inet::makeShared<inet::BytesChunk>(wire));
    mSocket.sendTo(pkt, ep.addr, ep.port);
}

void TeeRsuService::handleMessage(omnetpp::cMessage* msg)
{
    if (msg == mHilPollMsg) {
        pollHil();
        scheduleAt(omnetpp::simTime() + omnetpp::simtime_t(1, omnetpp::SIMTIME_MS), mHilPollMsg);
        return;
    }
    if (!msg->isSelfMessage()) {
        mSocket.processMessage(msg);
        return;
    }
    delete msg;
}

void TeeRsuService::sendHilSessionAck()
{
    if (!mHilBackhaul) {
        return;
    }
    sendFrame(*mHilBackhaul, FrameKind::Session_Ack,
        packSessionAck(mName, mCaPublicKey, mGatewayCert, mEsaCert, mBroker->otpAlgo()));
}

void TeeRsuService::sendHilClockAnchor()
{
    if (!mHilBackhaul) {
        return;
    }
    const auto wallNow = std::chrono::steady_clock::now();
    const auto simNow = omnetpp::simTime();
    sendFrame(*mHilBackhaul, FrameKind::Clock_Anchor, packClockAnchor(simNow.inUnit(omnetpp::SIMTIME_NS)));
    mHilClockSent = true;
    mHilClockRefWall = wallNow;
    mHilClockRefSim = simNow;
}

void TeeRsuService::maybeSyncHilClock()
{
    // Only rsu[0] drives periodic clock anchors on the shared 0x88b6 bus, and rate-limits
    // by wall clock (>= 50 ms) so TraCI startup catch-up does not burst-drop frames on the NIC.
    if (getParentModule()->getIndex() != 0) {
        return;
    }
    const auto wallNow = std::chrono::steady_clock::now();
    const auto simNow = omnetpp::simTime();
    bool sync = !mHilClockSent;
    if (mHilClockSent) {
        const double wallDelta = std::chrono::duration<double>(wallNow - mHilClockRefWall).count();
        const double simDelta = (simNow - mHilClockRefSim).dbl();
        if (wallDelta >= 0.050 && std::abs(wallDelta - simDelta) > 0.020) {
            sync = true;
        }
    }
    if (sync) {
        sendHilClockAnchor();
    }
}

void TeeRsuService::maybeSendHilCloudCert()
{
    if (mHilCloudReady || !mHilBackhaul) {
        return;
    }
    const auto simNow = omnetpp::simTime();
    if (mLastCloudCertSent < 0 || (simNow - mLastCloudCertSent).dbl() >= 0.1) {
        sendData(*mHilBackhaul, "cloud", mName, toBytes(mBroker->cloudCertificate()));
        mLastCloudCertSent = simNow;
    }
}

void TeeRsuService::pollHil()
{
    maybeSyncHilClock();
    maybeSendHilCloudCert();

    if (mHilRadio) {
        drain(*mHilRadio, [this](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Protocol) {
                try {
                    ProtocolMsg msg = deserialize(body);
                    if (msg.getSender() != mName) {
                        return;
                    }
                    EV_INFO << mName << " [HIL]: received radio frame " << messageTypeName(msg.getType())
                            << " from physical RSU -> transmitting over 5G NR to "
                            << msg.getDestination() << "\n";
                    sendRadio(msg);
                } catch (const std::exception& e) {
                    EV_ERROR << mName << " [HIL]: deserialize radio error: " << e.what() << "\n";
                }
            }
        });
    }
    if (mHilBackhaul) {
        drain(*mHilBackhaul, [this](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Protocol) {
                try {
                    ProtocolMsg msg = deserialize(body);
                    if (msg.getSender() != mName) {
                        return;
                    }
                    EV_INFO << mName << " [HIL]: received backhaul frame " << messageTypeName(msg.getType())
                            << " from physical RSU -> forwarding to simulation backhaul broker\n";
                    mBroker->sendBackhaul(msg);
                } catch (const std::exception& e) {
                    EV_ERROR << mName << " [HIL]: deserialize backhaul error: " << e.what() << "\n";
                }
            } else if (kind == FrameKind::Data_Fragment) {
                if (auto packet = mHilBackhaulReassembler.add(body);
                    packet && packet->to == "cloud" && packet->from == mName) {
                    if (mBroker->postToCloud(mName, packet->bytes)) {
                        ++mMarshaled;
                    } else {
                        ++mMarshalRefused;
                    }
                }
            } else if (kind == FrameKind::Cloud_Ready) {
                if (auto tag = parseRsuTag(body); tag && *tag == mName) {
                    mHilCloudReady = true;
                }
            } else if (kind == FrameKind::Cloud_Refused) {
                if (auto tag = parseRsuTag(body); tag && *tag == mName) {
                    ++mMarshalRefused;
                }
            } else if (kind == FrameKind::Session_Hello) {
                if (auto hello = parseSessionHello(body);
                    hello && hello->rsu == mName && hello->gatewayPublicKey == mGatewayPublicKey) {
                    sendHilSessionAck();
                }
            }
        });
    }
}

void TeeRsuService::finish()
{
    shutdownHil();
    recordScalar("marshaledPackets", mMarshaled);
    recordScalar("marshalRefused", mMarshalRefused);
    recordScalar("teeIgnored", mGateway ? mGateway->ignored() : 0);
    recordScalar("handoversTriggered", mHandoversTriggered);
    recordScalar("handoversGranted", mHandoversGranted);
    cSimpleModule::finish();
    // the TA session goes with this RSU
    mGateway.reset();
    mTee.reset();
}
