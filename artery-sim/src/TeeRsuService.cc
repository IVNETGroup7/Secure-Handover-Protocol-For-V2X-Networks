#include "TeeRsuService.h"
#include "BackhaulBroker.h"
#include "MessageType.h"
#include "Link.h"
#include "SimTime.h"
#include "V2xFrame.h"
#include "gateway_ta.h"
#include <omnetpp.h>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/common/byte_order.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/geonet/interface.hpp>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

Define_Module(TeeRsuService)

namespace
{

constexpr short kHandoverTimer = 1;     // self-message: announce a vehicle to the next RSU (its name is the vehicle)

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
    if (mHilPollMsg) {
        cancelAndDelete(mHilPollMsg);
        mHilPollMsg = nullptr;
    }
    mHilRadio.reset();
    mHilBackhaul.reset();
}

void TeeRsuService::initialize()
{
    ItsG5Service::initialize();
    mName = getParentModule()->getParentModule()->getFullName(); // <rsu>.middleware.TeeRsuService
    mNextRsu = par("nextRsu").stdstringValue();
    mHandoverDelay = par("handoverDelay");
    mMarshalLatencySignal = registerSignal("marshalLatencyUs");
    mHandoverGrantedSignal = registerSignal("handoverGranted");

    mBroker = dynamic_cast<BackhaulBroker*>(getSimulation()->getSystemModule()->getSubmodule(
        par("backhaulModule").stringValue()));
    if (!mBroker) {
        throw omnetpp::cRuntimeError("%s: no BackhaulBroker '%s' in the network", mName.c_str(),
            par("backhaulModule").stringValue());
    }

    mEnableHil = par("enableHil").boolValue();
    mHilIface = par("hilIface").stdstringValue();
    if (mHilIface.empty()) {
        if (const char* envIface = std::getenv("HIL_IFACE")) {
            mHilIface = envIface;
        }
    }

    if (mEnableHil) {
        initHil();
    } else {
        initLocalTee();
    }
}

void TeeRsuService::initHil()
{
    if (mHilIface.empty()) {
        throw omnetpp::cRuntimeError(
            "%s: HIL enabled but no host interface specified; set HIL_IFACE=<iface> or pass "
            "--*.rsu[*].middleware.TeeRsuService.hilIface=\\\"<iface>\\\"",
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
            mGatewayPublicKey = hello->gatewayPublicKey;
            mEsaPublicKey = mBroker->registerRsu(mName, hello->sessionKey, mGatewayPublicKey,
                [this](const ProtocolMsg& msg) { onBackhaul(msg); });
            Bytes ack = toBytes(mName + "\n");
            ack.insert(ack.end(), mEsaPublicKey.begin(), mEsaPublicKey.end());
            sendFrame(*mHilBackhaul, FrameKind::Session_Ack, ack);
            registered = true;
            std::printf("[HIL] %s registered physical RSU CY_g (%zu B) with ESA -> Session_Ack sent\n",
                mName.c_str(), mGatewayPublicKey.size());
            std::fflush(stdout);
        });
    }
    if (!registered) {
        throw omnetpp::cRuntimeError(
            "%s: timed out waiting for physical RSU Session_Hello on %s (start './app rsu --name %s ...' on RPi3)",
            mName.c_str(), mHilIface.c_str(), mName.c_str());
    }

    mHilPollMsg = new omnetpp::cMessage("hilPoll");
    scheduleAt(omnetpp::simTime() + omnetpp::simtime_t(1, omnetpp::SIMTIME_MS), mHilPollMsg);
}

void TeeRsuService::initLocalTee()
{
    // This RSU's own OP-TEE TA session, with its own Secure Storage object (fresh unless freshState = false)
    std::string sealed = par("sealedStatePath").stdstringValue();
    if (sealed.empty()) {
        sealed = fileName(mName) + ".sealed";
    }
    mTee = std::make_unique<TeeSession>(sealed, par("freshState").boolValue());
    mGateway = std::make_unique<PacketManager>(*mTee, mName);

    char sessionKey[65];
    for (int i = 0; i < 32; ++i) {
        std::snprintf(sessionKey + 2 * i, 3, "%02x", static_cast<unsigned>(intuniform(0, 255)));
    }
    const GatewayCertificate certificate = newGatewayCertificate(mName);
    mGatewayPublicKey = certificate.publicKey;
    const Bytes esaPublicKey = mBroker->registerRsu(mName, sessionKey, certificate.publicKey,
        [this](const ProtocolMsg& msg) { onBackhaul(msg); });

    const int init = mGateway->initGateway(certificate.certificate, esaPublicKey, hexKey(par("groupKey").stdstringValue()));
    if (init != GW_OK) {
        throw omnetpp::cRuntimeError("%s: TA_GATEWAY_CMD_INIT_GATEWAY: %s", mName.c_str(), statusName(init));
    }
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
    // the operator chose the RSU of CY_g: the other RSUs in range leave its Activation_Request alone
    if (msg.getType() == Activation_Request
        && unpackActivationRequest(getPayload(msg)).gatewayPublicKey != mGatewayPublicKey) {
        return;
    }
    if (msg.getType() == Handover_Predict && msg.getDestination() == mName) {
        ++mHandoversTriggered;
    }
    if (mEnableHil) {
        if (!mHilRadio || (msg.getDestination() != mName && msg.getDestination() != "esa")) {
            return;
        }
        sendMsg(*mHilRadio, msg);
        EV_INFO << mName << " [HIL]: forwarded radio " << messageTypeName(msg.getType())
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

void TeeRsuService::indicate(const vanetza::btp::DataIndication&, omnetpp::cPacket* packet,
    const artery::NetworkInterface&)
{
    Enter_Method("indicate");
    std::unique_ptr<omnetpp::cPacket> owned(packet);
    const auto frame = dynamic_cast<const V2xFrame*>(packet);
    if (!frame) {
        return;
    }
    try {
        onRadioRx(frame->msg());
    } catch (const std::runtime_error& e) { // a malformed frame or payload: dropped, the simulation goes on
        EV_ERROR << mName << ": frame dropped: " << e.what() << "\n";
    }
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
            sendMsg(*mHilBackhaul, msg);
            EV_INFO << mName << " [HIL]: forwarded backhaul " << messageTypeName(msg.getType())
                    << " to physical RSU on " << mHilIface << "\n";
        } catch (const std::exception& e) {
            EV_ERROR << mName << " [HIL]: sendMsg backhaul error: " << e.what() << "\n";
        }
        return;
    }
    try {
        mGateway->onHttps(msg); // Activation_Token, Forwarding_Notice, Handover_Command
    } catch (const std::runtime_error& e) {
        EV_ERROR << mName << ": backhaul message dropped: " << e.what() << "\n";
    }
}

void TeeRsuService::sendHttps(const ProtocolMsg& msg)
{
    mBroker->sendBackhaul(msg);

    // the vehicle is active here (the protocol ended for this RSU): pre-announce it to the next RSU
    if (msg.getType() == Active_02 && !mNextRsu.empty()) {
        scheduleAt(omnetpp::simTime() + mHandoverDelay, new omnetpp::cMessage(msg.getVehicle().c_str(), kHandoverTimer));
    }
}

void TeeRsuService::sendRadio(const ProtocolMsg& msg)
{
    if (msg.getType() == Forwarding_Granted) {
        ++mHandoversGranted;
        emit(mHandoverGrantedSignal, mHandoversGranted);
    }

    // Vanetza has no GeoUnicast here: single-hop broadcast, receivers filter by destination (logical unicast)
    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP0)); // TC0
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    request(req, new V2xFrame(msg));
}

void TeeRsuService::handleMessage(omnetpp::cMessage* msg)
{
    if (msg == mHilPollMsg) {
        pollHil();
        scheduleAt(omnetpp::simTime() + omnetpp::simtime_t(1, omnetpp::SIMTIME_MS), mHilPollMsg);
        return;
    }
    if (msg->isSelfMessage() && msg->getKind() == kHandoverTimer) {
        ++mHandoversTriggered;
        if (mEnableHil && mHilBackhaul) {
            sendFrame(*mHilBackhaul, FrameKind::Handover_Trigger,
                packHandoverTrigger(mName, msg->getName(), mNextRsu));
            EV_INFO << mName << " [HIL]: sent Handover_Trigger (" << msg->getName() << " -> " << mNextRsu
                    << ") to physical RSU\n";
        } else {
            mGateway->startHandover(msg->getName(), mNextRsu); // Forwarding_Notice to mNextRsu
        }
    }
    delete msg;
}

void TeeRsuService::maybeSyncHilClock()
{
    const auto wallNow = std::chrono::steady_clock::now();
    const auto simNow = omnetpp::simTime();
    bool sync = !mHilClockSent;
    if (mHilClockSent) {
        const double wallDelta = std::chrono::duration<double>(wallNow - mHilClockRefWall).count();
        const double simDelta = (simNow - mHilClockRefSim).dbl();
        if (std::abs(wallDelta - simDelta) > 0.020) {
            sync = true;
        }
    }
    if (sync && mHilBackhaul) {
        sendFrame(*mHilBackhaul, FrameKind::Clock_Anchor, packClockAnchor(simNow.inUnit(omnetpp::SIMTIME_NS)));
        mHilClockSent = true;
        mHilClockRefWall = wallNow;
        mHilClockRefSim = simNow;
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
                    if (msg.getType() == Forwarding_Granted) {
                        ++mHandoversGranted;
                        emit(mHandoverGrantedSignal, mHandoversGranted);
                    }
                    EV_INFO << mName << " [HIL]: received radio frame " << messageTypeName(msg.getType())
                            << " from physical RSU -> transmitting over simulation radio to "
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
                    if (msg.getType() == Active_02 && !mNextRsu.empty()) {
                        scheduleAt(omnetpp::simTime() + mHandoverDelay,
                            new omnetpp::cMessage(msg.getVehicle().c_str(), kHandoverTimer));
                    }
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
                    Bytes ack = toBytes(mName + "\n");
                    ack.insert(ack.end(), mEsaPublicKey.begin(), mEsaPublicKey.end());
                    sendFrame(*mHilBackhaul, FrameKind::Session_Ack, ack);
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
    ItsG5Service::finish();
    // the TA session goes with this RSU
    mGateway.reset();
    mTee.reset();
}
