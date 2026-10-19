#include "TeeRsuService.h"
#include "BackhaulBroker.h"
#include "BootstrapPayload.h"
#include "Link.h"
#include "SimTime.h"
#include "V2xFrame.h"
#include "gateway.h"
#include "ocalls.h"
#include <omnetpp.h>
#include <sgx_urts.h>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/common/byte_order.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/geonet/interface.hpp>
#include <chrono>
#include <cstdio>
#include <stdexcept>

Define_Module(TeeRsuService)

namespace
{

constexpr short kHandoverTimer = 1;     // self-message: announce a vehicle to the next RSU (its name is the vehicle)

// "rsu[0]" -> "rsu0": a file name
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

// K_g given as hex ("" -> empty: generated in the enclave)
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
    mGateway.reset();
    if (mEid != 0) {
        sgx_destroy_enclave(mEid);
    }
}

void TeeRsuService::initialize()
{
    ItsG5Service::initialize();
    mName = getParentModule()->getParentModule()->getFullName(); // <rsu>.middleware.TeeRsuService
    mNextRsu = par("nextRsu").stdstringValue();
    mHandoverDelay = par("handoverDelay");
    mMarshalLatencySignal = registerSignal("marshalLatencyUs");
    mHandoverGrantedSignal = registerSignal("handoverGranted");

    // Option A: this RSU's own enclave, with its own sealed state (fresh unless freshState = false)
    const std::string enclavePath = par("enclavePath").stdstringValue();
    const sgx_status_t created = sgx_create_enclave(enclavePath.c_str(), SGX_DEBUG_FLAG, nullptr, nullptr, &mEid,
        nullptr);
    if (created != SGX_SUCCESS) {
        throw omnetpp::cRuntimeError("%s: sgx_create_enclave(%s) failed: sgx_status_t 0x%04x", mName.c_str(),
            enclavePath.c_str(), static_cast<unsigned>(created));
    }
    std::string sealed = par("sealedStatePath").stdstringValue();
    if (sealed.empty()) {
        sealed = fileName(mName) + ".sealed";
    }
    if (par("freshState").boolValue()) {
        std::remove(sealed.c_str());
    }
    setSealedStatePath(mEid, sealed);
    mGateway = std::make_unique<PacketManager>(mEid, mName);

    // HTTPS session with the ESA over the backhaul: my certificate's key (CY_g) for CY_e
    mBroker = dynamic_cast<BackhaulBroker*>(getSimulation()->getSystemModule()->getSubmodule(
        par("backhaulModule").stringValue()));
    if (!mBroker) {
        throw omnetpp::cRuntimeError("%s: no BackhaulBroker '%s' in the network", mName.c_str(),
            par("backhaulModule").stringValue());
    }
    char sessionKey[65];
    for (int i = 0; i < 32; ++i) {
        std::snprintf(sessionKey + 2 * i, 3, "%02x", static_cast<unsigned>(intuniform(0, 255)));
    }
    const GatewayCertificate certificate = newGatewayCertificate(mName);
    mGatewayPublicKey = certificate.publicKey;
    const Bytes esaPublicKey = mBroker->registerRsu(mName, sessionKey, certificate.publicKey,
        [this](const BootstrapMsg& msg) { onBackhaul(msg); });

    const int init = mGateway->initGateway(certificate.certificate, esaPublicKey, hexKey(par("groupKey").stdstringValue()));
    if (init != GW_OK) {
        throw omnetpp::cRuntimeError("%s: ecall_init_gateway: %s", mName.c_str(), statusName(init));
    }
    const int cloud = mGateway->initCloudSession(mBroker->cloudCertificate(), kCloudAddress);
    if (cloud != GW_OK) {
        throw omnetpp::cRuntimeError("%s: ecall_init_cloud_session: %s", mName.c_str(), statusName(cloud));
    }

    PacketManager::Transport transport;
    transport.radio = [this](const BootstrapMsg& msg) { sendRadio(msg); };
    transport.https = [this](const BootstrapMsg& msg) { sendHttps(msg); };
    transport.cloud = [this](ItPacket packet) { mBroker->postToCloud(mName, packet.bytes); };
    mGateway->setTransport(transport);
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
        const BootstrapMsg msg = frame->msg();
        if (msg.getType() == Secure_Data) {
            if (msg.getDestination() == mName) {
                secureData(msg);
            }
            return;
        }
        // the operator chose the RSU of CY_g: the other RSUs in range leave its Activation_Request alone
        if (msg.getType() == Activation_Request
            && unpackActivationRequest(getPayload(msg)).gatewayPublicKey != mGatewayPublicKey) {
            return;
        }
        mGateway->onRadio(msg); // filters by destination (logical unicast)
    } catch (const std::runtime_error& e) { // a malformed frame or payload: dropped, the simulation goes on
        EV_ERROR << mName << ": frame dropped: " << e.what() << "\n";
    }
}

// Secure_Data: OT packet -> ecall_secure_marshal_ot_to_it -> IT packet for the cloud
void TeeRsuService::secureData(const BootstrapMsg& msg)
{
    // the ECALL's own (wall clock) time: simulation time does not move inside an event
    const auto start = std::chrono::steady_clock::now();
    const Reply reply = mGateway->marshal(getPayload(msg), static_cast<uint64_t>(SimTime::now().ns()));
    const double us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count();
    emit(mMarshalLatencySignal, us);
    if (reply.status != GW_OK) {
        ++mMarshalRefused;
        EV_WARN << mName << ": SmartData of " << msg.getSender() << " refused by the enclave (" << statusName(reply.status)
            << ")\n";
        return;
    }
    ++mMarshaled;
    mBroker->postToCloud(mName, reply.payload);
}

void TeeRsuService::onBackhaul(const BootstrapMsg& msg)
{
    Enter_Method("onBackhaul");
    try {
        mGateway->onHttps(msg); // Activation_Token, Forwarding_Notice, Handover_Command
    } catch (const std::runtime_error& e) {
        EV_ERROR << mName << ": backhaul message dropped: " << e.what() << "\n";
    }
}

void TeeRsuService::sendHttps(const BootstrapMsg& msg)
{
    mBroker->sendBackhaul(msg);

    // the vehicle is active here (the protocol ended for this RSU): pre-announce it to the next RSU
    if (msg.getType() == Active_02 && !mNextRsu.empty()) {
        scheduleAt(omnetpp::simTime() + mHandoverDelay, new omnetpp::cMessage(msg.getVehicle().c_str(), kHandoverTimer));
    }
}

void TeeRsuService::sendRadio(const BootstrapMsg& msg)
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
    if (msg->isSelfMessage() && msg->getKind() == kHandoverTimer) {
        ++mHandoversTriggered;
        mGateway->startHandover(msg->getName(), mNextRsu); // Forwarding_Notice to mNextRsu
    }
    delete msg;
}

void TeeRsuService::finish()
{
    recordScalar("marshaledPackets", mMarshaled);
    recordScalar("marshalRefused", mMarshalRefused);
    recordScalar("enclaveIgnored", mGateway ? mGateway->ignored() : 0);
    recordScalar("handoversTriggered", mHandoversTriggered);
    recordScalar("handoversGranted", mHandoversGranted);
    ItsG5Service::finish();
    // the enclave goes with this RSU (finish: OMNeT++ is done with it; also at deletion, whichever first)
    mGateway.reset();
    if (mEid != 0) {
        sgx_destroy_enclave(mEid);
        mEid = 0;
    }
}
