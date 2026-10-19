#include "VehicleTeeService.h"
#include "BackhaulBroker.h"
#include "Bootstrap.h"
#include "V2xFrame.h"
#include "artery/application/VehicleDataProvider.h"
#include <omnetpp.h>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/common/byte_order.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/geonet/interface.hpp>
#include <algorithm>
#include <limits>
#include <stdexcept>

Define_Module(VehicleTeeService)

VehicleTeeService::~VehicleTeeService()
{
    cancelAndDelete(mStartTimer);
    cancelAndDelete(mDataTimer);
}

void VehicleTeeService::initialize()
{
    ItsG5Service::initialize();
    mName = getParentModule()->getParentModule()->getFullName(); // <node>.middleware.VehicleTeeService
    mHandoverX = par("handoverX").doubleValue();
    mBootstrapDelaySignal = registerSignal("bootstrapDelay");
    mHandoverDelaySignal = registerSignal("handoverE2EDelayMs");
    mSecureDataSignal = registerSignal("secureDataSent");

    mBroker = dynamic_cast<BackhaulBroker*>(getSimulation()->getSystemModule()->getSubmodule(
        par("backhaulModule").stringValue()));
    if (!mBroker) {
        throw omnetpp::cRuntimeError("%s: no BackhaulBroker '%s' in the network", mName.c_str(),
            par("backhaulModule").stringValue());
    }

    mStartTimer = new omnetpp::cMessage("bootstrap");
    mDataTimer = new omnetpp::cMessage("Secure_Data");
    scheduleAt(omnetpp::simTime() + par("startDelay"), mStartTimer);
}

void VehicleTeeService::startBootstrap()
{
    // CY_g of the RSU the operator chose (here: "firstRsu"), as it registered its certificate with the ESA
    BootstrapService::Config config;
    config.name = mName;
    config.role = BootstrapService::Role::Vehicle;
    config.autoStart = false;
    config.clockOffset = par("clockOffset").doubleValue();
    config.gatewayPublicKey = mBroker->gatewayPublicKey(par("firstRsu").stdstringValue());
    config.deferHandover = true;    // the Forwarding_Request waits for handoverX (checkHandover)
    config.seed = static_cast<unsigned>(intuniform(0, std::numeric_limits<int>::max()));
    mBootstrap = std::make_unique<BootstrapService>(config);

    BootstrapService::Transport transport;
    transport.radio = [this](const BootstrapMsg& msg) { sendRadio(msg); };
    mBootstrap->setTransport(transport);

    mBootstrap->setHandoverCallback([this](const BootstrapResult& result) {
        ++mHandovers;
        const double ms = (omnetpp::simTime() - mRequestSentAt).dbl() * 1000.0;
        emit(mHandoverDelaySignal, ms);
        EV_INFO << mName << ": handed over to " << result.rsu << " in " << ms << " ms\n";
        getParentModule()->getParentModule()->bubble(("handover: " + result.rsu).c_str());
    });

    mStartedAt = omnetpp::simTime();
    initBootstrap(*mBootstrap, [this](const BootstrapResult& result) {
        mReady = true;
        emit(mBootstrapDelaySignal, omnetpp::simTime() - mStartedAt);
        getParentModule()->getParentModule()->bubble(("bootstrap OK: " + result.rsu).c_str());
        if (!mDataTimer->isScheduled()) {
            scheduleAt(omnetpp::simTime() + par("dataInterval"), mDataTimer);
        }
    });
}

void VehicleTeeService::sendSecureData()
{
    // a CAM-sized SmartData: where (x, m), when (the vehicle's clock, set by sendSecureData), what (1: CAM-like)
    const std::string rsu = mBootstrap->currentRsu();
    mBootstrap->sendSecureData(randomBytes(static_cast<size_t>(par("dataSize").intValue())),
        static_cast<uint32_t>(std::max(0.0, positionX())), 1);
    ++mSecureDataSent;
    ++mSentTo[rsu];
    emit(mSecureDataSignal, mSecureDataSent);
}

void VehicleTeeService::checkHandover()
{
    if (mBootstrap && mBootstrap->handoverPending() && (mHandoverX < 0 || positionX() >= mHandoverX)) {
        EV_INFO << mName << ": at x = " << positionX() << " m, Forwarding_Request to " << mBootstrap->handoverTarget()
            << "\n";
        mRequestSentAt = omnetpp::simTime();
        mBootstrap->requestForwarding();
    }
}

void VehicleTeeService::indicate(const vanetza::btp::DataIndication&, omnetpp::cPacket* packet,
    const artery::NetworkInterface&)
{
    Enter_Method("indicate");
    std::unique_ptr<omnetpp::cPacket> owned(packet);
    const auto frame = dynamic_cast<const V2xFrame*>(packet);
    if (!frame || !mBootstrap) {
        return;
    }
    try {
        mBootstrap->indicate(frame->msg()); // filters by destination (logical unicast)
        checkHandover();                    // a Handover_Command may have just arrived
    } catch (const std::runtime_error& e) { // a malformed frame or payload: dropped, the simulation goes on
        EV_ERROR << mName << ": frame dropped: " << e.what() << "\n";
    }
}

void VehicleTeeService::handleMessage(omnetpp::cMessage* msg)
{
    if (msg == mStartTimer) {
        startBootstrap();
    } else if (msg == mDataTimer) {
        checkHandover();
        sendSecureData();
        scheduleAt(omnetpp::simTime() + par("dataInterval"), mDataTimer);
    } else {
        delete msg;
    }
}

void VehicleTeeService::sendRadio(const BootstrapMsg& msg)
{
    // DCC profile: the protocol's messages (bootstrap, Forwarding_Request: a few, short) as TC0 / DP0; Secure_Data,
    // periodic at 10 Hz, as DP2, as CAMs. DCC grants DP0 a burst of 20 packets per 10 s only (ETSI TS 102 687):
    // 10 Hz on DP0 drains it, then the packets wait in a 2-packet queue (too late for their OTP) or are dropped
    const auto profile = msg.getType() == Secure_Data ? vanetza::dcc::Profile::DP2 : vanetza::dcc::Profile::DP0;

    // Vanetza has no GeoUnicast here: single-hop broadcast, receivers filter by destination (logical unicast)
    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(profile));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    request(req, new V2xFrame(msg));
}

double VehicleTeeService::positionX() const
{
    return getFacilities().get_const<artery::VehicleDataProvider>().position().x.value();
}

void VehicleTeeService::finish()
{
    recordScalar("bootstrapped", mReady ? 1 : 0);
    recordScalar("secureDataSent", mSecureDataSent);
    recordScalar("handovers", mHandovers);
    for (const auto& [rsu, sent] : mSentTo) {
        recordScalar(("secureDataSentTo " + rsu).c_str(), sent);
    }
    if (mBootstrap) {
        recordScalar("bootstrapMessagesSent", mBootstrap->sent());
        recordScalar("bootstrapMessagesReceived", mBootstrap->received());
    }
    ItsG5Service::finish();
}
