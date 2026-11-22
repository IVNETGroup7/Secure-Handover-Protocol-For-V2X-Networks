#include "VehicleTeeService.h"
#include "BackhaulBroker.h"
#include "Trace.h"
#include "V2xFrame.h"
#include "artery/application/VehicleDataProvider.h"
#include <omnetpp.h>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/common/byte_order.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/geonet/interface.hpp>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <vector>

Define_Module(VehicleTeeService)

namespace
{
constexpr double kPi = 3.14159265358979323846;
} // namespace

VehicleTeeService::~VehicleTeeService()
{
    cancelAndDelete(mStartTimer);
    cancelAndDelete(mBootstrapLaunchTimer);
    cancelAndDelete(mBootstrapTimeoutTimer);
    cancelAndDelete(mDataTimer);
}

void VehicleTeeService::initialize()
{
    ItsG5Service::initialize();
    mName = getParentModule()->getParentModule()->getFullName(); // <node>.middleware.VehicleTeeService
    mEnableCtra = par("enableCtra").boolValue();
    mPredictionHorizon = par("predictionHorizon").doubleValue();
    mPredictionStep = par("predictionStep").doubleValue();
    mPredictRadius = par("predictRadius").doubleValue();
    mHandoverRadius = par("handoverRadius").doubleValue();
    mHandoverX = par("handoverX").doubleValue();

    mBootstrapDelaySignal = registerSignal("bootstrapDelay");
    mHandoverDelaySignal = registerSignal("handoverE2EDelayMs");
    mPrefetchLeadTimeSignal = registerSignal("prefetchLeadTimeMs");
    mCtraPredictionSignal = registerSignal("ctraPredictions");
    mSecureDataSignal = registerSignal("secureDataSent");

    mBroker = dynamic_cast<BackhaulBroker*>(getSimulation()->getSystemModule()->getSubmodule(
        par("backhaulModule").stringValue()));
    if (!mBroker) {
        throw omnetpp::cRuntimeError("%s: no BackhaulBroker '%s' in the network", mName.c_str(),
            par("backhaulModule").stringValue());
    }

    discoverRsus();

    mStartTimer = new omnetpp::cMessage("bootstrap");
    mBootstrapLaunchTimer = new omnetpp::cMessage("bootstrapOtLaunch");
    mBootstrapTimeoutTimer = new omnetpp::cMessage("bootstrapTimeout");
    mDataTimer = new omnetpp::cMessage("Secure_Data");
    scheduleAt(omnetpp::simTime() + par("startDelay"), mStartTimer);
}

void VehicleTeeService::discoverRsus()
{
    std::vector<CtraPredictor::RsuCandidate> candidates;
    omnetpp::cModule* sys = getSimulation()->getSystemModule();
    for (int i = 0; ; ++i) {
        omnetpp::cModule* rsu = sys->getSubmodule("rsu", i);
        if (!rsu) {
            break;
        }
        if (omnetpp::cModule* mob = rsu->getSubmodule("mobility")) {
            const double rx = mob->par("initialX").doubleValue();
            const double ry = mob->par("initialY").doubleValue();
            candidates.push_back({ rsu->getFullName(), rx, ry });
        }
    }
    mPredictor.setCandidates(std::move(candidates));
}

void VehicleTeeService::updateKinematics()
{
    const auto& vdp = getFacilities().get_const<artery::VehicleDataProvider>();
    const double x = vdp.position().x.value();
    const double y = vdp.position().y.value();
    const double v = vdp.speed().value();
    // Convert Artery TrueNorth clockwise angle to OMNeT++ Cartesian heading psi (dx/dt = v*cos(psi), dy/dt = v*sin(psi))
    const double psi = vdp.heading().value() - (kPi / 2.0);
    const double a = vdp.acceleration().value();
    mPredictor.update(x, y, v, psi, a, omnetpp::simTime().dbl());
}

void VehicleTeeService::startBootstrap()
{
    updateKinematics();

    const std::string firstRsu = par("firstRsu").stdstringValue();

    VehicleAgent::Config config;
    config.name = mName;
    config.targetRsu = firstRsu;
    config.autoStart = false;
    config.clockOffset = par("clockOffset").doubleValue();
    config.deferHandover = true;    // Handover_Command pre-fetches keys; Forwarding_Request waits for checkHandover()
    config.seed = static_cast<unsigned>(intuniform(0, std::numeric_limits<int>::max()));
    mAgent = std::make_unique<VehicleAgent>(config);

    mAgent->setTransport([this](const ProtocolMsg& msg) { sendRadio(msg); });

    mAgent->handover().setPrefetchCallback([this](const std::string& targetRsu) {
        mPrefetchReadyAt = omnetpp::simTime();
        ++mPrefetchesCompleted;
        const double rttMs = (mPrefetchReadyAt - mPredictSentAt).dbl() * 1000.0;
        EV_INFO << mName << ": [CTRA pre-fetch ready] Handover_Command from " << targetRsu
                << " pre-computed in " << rttMs << " ms (holding keys until handover zone)\n";
    });

    mAgent->handover().setHandoverCallback([this](const HandoverResult& result) {
        ++mHandovers;
        mPredictedRsu.clear();
        mPrefetchReadyAt = omnetpp::SimTime::ZERO;
        const double ms = (omnetpp::simTime() - mRequestSentAt).dbl() * 1000.0;
        emit(mHandoverDelaySignal, ms);
        EV_INFO << mName << ": handed over to " << result.rsu << " in " << ms << " ms\n";
        getParentModule()->getParentModule()->bubble(("handover: " + result.rsu).c_str());
    });

    mAgent->bootstrap().setFailureCallback([this](const std::string& reason) {
        cancelEvent(mBootstrapTimeoutTimer);
        throw omnetpp::cRuntimeError("%s: bootstrap failed (%s)", mName.c_str(), reason.c_str());
    });

    // Phase A (IT Domain): Human Operator out-of-band sends Activation_Request(CY_g, t_0, t_f, UUID_d, SHA256(fw_d))
    // directly to the ESA -> encrypted Activation_Token delivered to firstRsu's TEE before OT bootstrap begins.
    const simtime_t now = SimTime::now();
    const VehicleTraits& traits = mAgent->session().traits();
    mBroker->requestActivation(firstRsu, now, now + kActivationWindow, traits.uuid, traits.firmwareHash);

    // Allow Phase A backhaul delivery (20 ms sim / HIL Ethernet) before Phase B starts over 802.11p
    scheduleAt(omnetpp::simTime() + omnetpp::simtime_t(100, omnetpp::SIMTIME_MS), mBootstrapLaunchTimer);
}

void VehicleTeeService::launchOtBootstrap()
{
    if (!mAgent) {
        return;
    }
    mStartedAt = omnetpp::simTime();
    mAgent->bootstrap().start([this](const BootstrapResult& result) {
        mReady = true;
        cancelEvent(mBootstrapTimeoutTimer);
        emit(mBootstrapDelaySignal, omnetpp::simTime() - mStartedAt);
        getParentModule()->getParentModule()->bubble(("bootstrap OK: " + result.rsu).c_str());
        if (!mDataTimer->isScheduled()) {
            scheduleAt(omnetpp::simTime() + par("dataInterval"), mDataTimer);
        }
    });
    if (!mReady && par("bootstrapTimeout").doubleValue() > 0.0 && !mBootstrapTimeoutTimer->isScheduled()) {
        scheduleAt(omnetpp::simTime() + par("bootstrapTimeout"), mBootstrapTimeoutTimer);
    }
}

void VehicleTeeService::sendSecureData()
{
    const std::string rsu = mAgent->session().currentRsu();
    mAgent->data().send(randomBytes(static_cast<size_t>(par("dataSize").intValue())),
        static_cast<uint32_t>(std::max(0.0, positionX())), 1);
    ++mSecureDataSent;
    ++mSentTo[rsu];
    emit(mSecureDataSignal, mSecureDataSent);
}

void VehicleTeeService::checkPrediction()
{
    if (!mReady || !mEnableCtra || !mAgent || mAgent->handover().inFlight()) {
        return;
    }

    const std::string current = mAgent->session().currentRsu();
    if (current.empty()) {
        return;
    }

    const auto pred = mPredictor.predictNextRsu(current, mPredictionHorizon, mPredictionStep, mPredictRadius);
    if (!pred) {
        return;
    }

    const bool newTarget = (pred->targetRsu != mPredictedRsu);
    const bool retryLostPrefetch = (!mAgent->handover().pending()
        && (omnetpp::simTime() - mPredictSentAt).dbl() >= 3.0);
    if (!newTarget && !retryLostPrefetch) {
        return;
    }

    mPredictedRsu = pred->targetRsu;
    mPredictSentAt = omnetpp::simTime();
    ++mPredictionsSent;
    emit(mCtraPredictionSignal, mPredictionsSent);

    const auto& st = mPredictor.state();
    char summary[256];
    std::snprintf(summary, sizeof(summary),
        "CTRA state [x=%.1f m, y=%.1f m, v=%.1f m/s, psi=%.1f deg, a=%.2f m/s^2, omega=%.2f rad/s] "
        "-> most likely RSU: %s (d_curr=%.1f m, d_min=%.1f m in %.1f s)",
        st.x, st.y, st.v, st.psi * 180.0 / kPi, st.a, st.omega,
        pred->targetRsu.c_str(), pred->currentDistance, pred->minDistance, pred->timeToClosest);
    trace::step(mName, "CTRA Trajectory Predictor");
    trace::detail(mName, summary);
    trace::detail(mName, "notifying ONLY " + pred->targetRsu + " via " + current
        + " (selective token pre-fetch, other candidate RSUs untouched)");

    EV_INFO << mName << ": " << summary << "\n";
    getParentModule()->getParentModule()->bubble(("CTRA predict: " + pred->targetRsu).c_str());
    mAgent->handover().requestPrediction(pred->targetRsu);
}

void VehicleTeeService::checkHandover()
{
    if (!mAgent) {
        return;
    }

    // Retry Forwarding_Request if an 802.11p frame was lost, after allowing
    // enough time for an in-flight OP-TEE response (~1.7 s with concurrent ECDH).
    if (mAgent->handover().inFlight() && (omnetpp::simTime() - mRequestSentAt).dbl() >= 2.5) {
        mRequestSentAt = omnetpp::simTime();
        mAgent->handover().requestForwarding();
        return;
    }

    if (!mAgent->handover().pending()) {
        return;
    }

    const std::string& target = mAgent->handover().targetRsu();
    bool shouldRequest = false;
    if (mEnableCtra) {
        shouldRequest = mPredictor.shouldExecuteHandover(mAgent->session().currentRsu(), target, mHandoverRadius);
    } else {
        shouldRequest = (mHandoverX < 0 || positionX() >= mHandoverX);
    }

    if (shouldRequest) {
        if (mPrefetchReadyAt > omnetpp::SimTime::ZERO) {
            const double leadMs = (omnetpp::simTime() - mPrefetchReadyAt).dbl() * 1000.0;
            emit(mPrefetchLeadTimeSignal, leadMs);
        }
        EV_INFO << mName << ": at (" << mPredictor.state().x << ", " << mPredictor.state().y
                << ") m (dist=" << mPredictor.distanceToRsu(target) << " m), Forwarding_Request to pre-fetched "
                << target << "\n";
        mRequestSentAt = omnetpp::simTime();
        mAgent->handover().requestForwarding();
    }
}

void VehicleTeeService::indicate(const vanetza::btp::DataIndication&, omnetpp::cPacket* packet,
    const artery::NetworkInterface&)
{
    Enter_Method("indicate");
    std::unique_ptr<omnetpp::cPacket> owned(packet);
    const auto frame = dynamic_cast<const V2xFrame*>(packet);
    if (!frame || !mAgent) {
        return;
    }
    try {
        mAgent->indicate(frame->msg()); // filters by destination (logical unicast)
        checkHandover();                // a Handover_Command may have just arrived
    } catch (const std::runtime_error& e) { // a malformed frame or payload: dropped, the simulation goes on
        EV_ERROR << mName << ": frame dropped: " << e.what() << "\n";
    }
}

void VehicleTeeService::handleMessage(omnetpp::cMessage* msg)
{
    if (msg == mStartTimer) {
        startBootstrap();
    } else if (msg == mBootstrapLaunchTimer) {
        launchOtBootstrap();
    } else if (msg == mBootstrapTimeoutTimer) {
        if (!mReady) {
            throw omnetpp::cRuntimeError(
                "%s: bootstrap failed (timed out after %.1f s with %s; sent=%d, received=%d)",
                mName.c_str(), par("bootstrapTimeout").doubleValue(), par("firstRsu").stringValue(),
                mAgent ? mAgent->session().sent() : 0, mAgent ? mAgent->session().received() : 0);
        }
    } else if (msg == mDataTimer) {
        updateKinematics();
        checkPrediction();
        checkHandover();
        sendSecureData();
        scheduleAt(omnetpp::simTime() + par("dataInterval"), mDataTimer);
    } else {
        delete msg;
    }
}

void VehicleTeeService::sendRadio(const ProtocolMsg& msg)
{
    // DCC profile: initial pre-ECDH messages as TC0 / DP0 (< 1 s burst); once ECDH starts, Auth_Request
    // and all subsequent traffic use DP2 to avoid DP0's 10 s BurstBudget lockout on HIL/RPi3 latency.
    const bool preEcdh = msg.getType() == PTP
        || msg.getType() == PTP_Delay_Request
        || msg.getType() == ECDH_Request;
    const auto profile = preEcdh ? vanetza::dcc::Profile::DP0 : vanetza::dcc::Profile::DP2;

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
    recordScalar("ctraPredictionsSent", mPredictionsSent);
    recordScalar("prefetchesCompleted", mPrefetchesCompleted);
    recordScalar("handovers", mHandovers);
    for (const auto& [rsu, sent] : mSentTo) {
        recordScalar(("secureDataSentTo " + rsu).c_str(), sent);
    }
    if (mAgent) {
        recordScalar("protocolMessagesSent", mAgent->session().sent());
        recordScalar("protocolMessagesReceived", mAgent->session().received());
    }
    ItsG5Service::finish();
}
