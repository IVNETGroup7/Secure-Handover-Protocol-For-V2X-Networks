// Include INET 4 / Artery / OMNeT++ headers BEFORE project headers (common/SimTime.h defines global ::SimTime).
#include "artery/application/Middleware.h"
#include "artery/traci/VehicleController.h"
#include <inet/common/ModuleAccess.h>
#include <inet/common/packet/Packet.h>
#include <inet/common/packet/chunk/BytesChunk.h>
#include <inet/mobility/contract/IMobility.h>
#include <inet/networklayer/common/L3AddressResolver.h>
#include <inet/networklayer/contract/IInterfaceTable.h>
#include <inet/networklayer/ipv4/IIpv4RoutingTable.h>
#include <inet/networklayer/ipv4/Ipv4Route.h>
#include <omnetpp.h>

#include "VehicleTeeService.h"
#include "BackhaulBroker.h"
#include "MessageType.h"
#include "Trace.h"
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
    unsubscribeNrServingCell();
    cancelAndDelete(mStartTimer);
    cancelAndDelete(mBootstrapLaunchTimer);
    cancelAndDelete(mBootstrapTimeoutTimer);
    cancelAndDelete(mDataTimer);
}

void VehicleTeeService::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == inet::INITSTAGE_LOCAL) {
        mName = getParentModule()->getFullName(); // <node>.app[0]
        mLocalPort = par("localPort").intValue();
        mDestPort = par("destPort").intValue();
        mEnableCtra = par("enableCtra").boolValue();
        mPredictionHorizon = par("predictionHorizon").doubleValue();
        mPredictionStep = par("predictionStep").doubleValue();
        mPredictRadius = par("predictRadius").doubleValue();
        mHandoverRadius = par("handoverRadius").doubleValue();

        mBootstrapDelaySignal = registerSignal("bootstrapDelay");
        mHandoverDelaySignal = registerSignal("handoverE2EDelayMs");
        mPrefetchLeadTimeSignal = registerSignal("prefetchLeadTimeMs");
        mCtraPredictionSignal = registerSignal("ctraPredictions");
        mSecureDataSignal = registerSignal("secureDataSent");
        mNrServingCellSignal = registerSignal("nrServingCellId");
        mNrRadioHandoversSignal = registerSignal("nrRadioHandovers");
    } else if (stage == inet::INITSTAGE_APPLICATION_LAYER) {
        mBroker = dynamic_cast<BackhaulBroker*>(getSimulation()->getSystemModule()->getSubmodule(
            par("backhaulModule").stringValue()));
        if (!mBroker) {
            throw omnetpp::cRuntimeError("%s: no BackhaulBroker '%s' in the network", mName.c_str(),
                par("backhaulModule").stringValue());
        }
        mBroker->otpAlgo();

        ensureDefaultCellularRoute();

        mSocket.setOutputGate(gate("socketOut"));
        mSocket.setCallback(this);
        mSocket.bind(mLocalPort);

        discoverRsus();
        subscribeNrServingCell();

        mStartTimer = new omnetpp::cMessage("bootstrap");
        mBootstrapLaunchTimer = new omnetpp::cMessage("bootstrapOtLaunch");
        mBootstrapTimeoutTimer = new omnetpp::cMessage("bootstrapTimeout");
        mDataTimer = new omnetpp::cMessage("Secure_Data");
        scheduleAt(omnetpp::simTime() + par("startDelay"), mStartTimer);
    }
}

void VehicleTeeService::ensureDefaultCellularRoute()
{
    omnetpp::cModule* host = getParentModule();
    auto* rt = inet::L3AddressResolver().findIpv4RoutingTableOf(host);
    auto* ift = inet::L3AddressResolver().findInterfaceTableOf(host);
    if (!rt || !ift) {
        return;
    }
    inet::NetworkInterface* cellIf = ift->findInterfaceByName("cellular");
    if (!cellIf) {
        return;
    }
    if (!rt->getDefaultRoute()) {
        auto* defaultRoute = new inet::Ipv4Route();
        defaultRoute->setDestination(inet::Ipv4Address::UNSPECIFIED_ADDRESS);
        defaultRoute->setNetmask(inet::Ipv4Address::UNSPECIFIED_ADDRESS);
        defaultRoute->setInterface(cellIf);
        rt->addRoute(defaultRoute);
    }
    cellIf->setBroadcast(false);
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
        if (omnetpp::cModule* mobMod = rsu->getSubmodule("mobility")) {
            double rx = 0.0;
            double ry = 0.0;
            if (auto* mob = dynamic_cast<inet::IMobility*>(mobMod)) {
                const inet::Coord pos = mob->getCurrentPosition();
                rx = pos.x;
                ry = pos.y;
            } else {
                rx = mobMod->par("initialX").doubleValue();
                ry = mobMod->par("initialY").doubleValue();
            }
            candidates.push_back({ rsu->getFullName(), rx, ry });
        }
    }
    mPredictor.setCandidates(std::move(candidates));
}

void VehicleTeeService::updateKinematics()
{
    omnetpp::cModule* host = getParentModule();
    if (auto* mw = dynamic_cast<artery::Middleware*>(
            findModuleByPath(par("middlewareModule").stringValue()))) {
        if (const auto* vc = mw->getFacilities().get_const_ptr<traci::VehicleController>()) {
            const auto pos = vc->getPosition();
            const double x = pos.x.value();
            const double y = pos.y.value();
            const double v = vc->getSpeed().value();
            // Convert Artery TrueNorth clockwise angle to OMNeT++ Cartesian heading psi (dx/dt = v*cos(psi), dy/dt = v*sin(psi))
            const double psi = vc->getHeading().getTrueNorth().value() - (kPi / 2.0);
            mPredictor.update(x, y, v, psi, std::numeric_limits<double>::quiet_NaN(), omnetpp::simTime().dbl());
            return;
        }
    }

    if (auto* mob = dynamic_cast<inet::IMobility*>(host->getSubmodule("mobility"))) {
        const inet::Coord pos = mob->getCurrentPosition();
        const inet::Coord vel = mob->getCurrentVelocity();
        const double v = std::hypot(vel.x, vel.y);
        const double psi = (v > 1e-4) ? std::atan2(vel.y, vel.x) : mPredictor.state().psi;
        mPredictor.update(pos.x, pos.y, v, psi, std::numeric_limits<double>::quiet_NaN(), omnetpp::simTime().dbl());
    }
}

void VehicleTeeService::subscribeNrServingCell()
{
    omnetpp::cModule* host = getParentModule();
    if (host && host->hasPar("nrServingNodeId")) {
        const int initCell = static_cast<int>(host->par("nrServingNodeId").intValue());
        if (initCell > 0) {
            onNrServingCellChanged(initCell);
        }
    }
    if (omnetpp::cModule* nrPhy = findModuleByPath("^.cellularNic.nrPhy")) {
        mNrPhyModule = nrPhy;
        mServingCellSignal = registerSignal("servingCell");
        mNrPhyModule->subscribe(mServingCellSignal, this);
    }
}

void VehicleTeeService::unsubscribeNrServingCell()
{
    if (mNrPhyModule && mServingCellSignal != SIMSIGNAL_NULL) {
        if (mNrPhyModule->isSubscribed(mServingCellSignal, this)) {
            mNrPhyModule->unsubscribe(mServingCellSignal, this);
        }
    }
    mNrPhyModule = nullptr;
}

void VehicleTeeService::receiveSignal(omnetpp::cComponent*, omnetpp::simsignal_t signalID, long value,
    omnetpp::cObject*)
{
    if (signalID == mServingCellSignal) {
        onNrServingCellChanged(static_cast<int>(value));
    }
}

void VehicleTeeService::onNrServingCellChanged(int cellId)
{
    if (cellId <= 0 || cellId == mLastNrServingCellId) {
        return;
    }
    if (mLastNrServingCellId != 0) {
        ++mNrRadioHandovers;
        emit(mNrRadioHandoversSignal, mNrRadioHandovers);
        char detail[128];
        std::snprintf(detail, sizeof(detail), "gNodeB macNodeId %d -> %d (5G NR X2 handover #%ld)",
            mLastNrServingCellId, cellId, mNrRadioHandovers);
        trace::step(mName, "5G NR Radio Handover");
        trace::detail(mName, detail);
        EV_INFO << mName << ": [5G NR] " << detail << "\n";
    }
    mLastNrServingCellId = cellId;
    emit(mNrServingCellSignal, static_cast<long>(cellId));
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
    config.seed = static_cast<unsigned>(intuniform(0, std::numeric_limits<int>::max()));
    mAgent = std::make_unique<VehicleAgent>(config);

    mAgent->setTransport([this](const ProtocolMsg& msg) { sendRadio(msg); });

    mAgent->handover().setPrefetchCallback([this](const std::string& targetRsu) {
        mPrefetchReadyAt = omnetpp::simTime();
        ++mPrefetchesCompleted;
        const double rttMs = (mPrefetchReadyAt - mPredictSentAt).dbl() * 1000.0;
        EV_INFO << mName << ": [CTRA pre-compute ready] keys for " << targetRsu
                << " pre-computed in " << rttMs << " ms (holding keys until handover zone)\n";
    });

    mAgent->handover().setHandoverCallback([this](const HandoverResult& result) {
        ++mHandovers;
        mPredictedRsu.clear();
        mPrefetchReadyAt = omnetpp::SimTime::ZERO;
        const double ms = (omnetpp::simTime() - mRequestSentAt).dbl() * 1000.0;
        emit(mHandoverDelaySignal, ms);
        EV_INFO << mName << ": handed over to " << result.rsu << " in " << ms << " ms\n";
        getParentModule()->bubble(("handover: " + result.rsu).c_str());
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

    // Allow Phase A backhaul delivery (20 ms sim / HIL Ethernet) before Phase B starts over 5G NR
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
        getParentModule()->bubble(("bootstrap OK: " + result.rsu).c_str());
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
        + " (selective token pre-fetch over 5G NR, other candidate RSUs untouched)");

    EV_INFO << mName << ": " << summary << "\n";
    getParentModule()->bubble(("CTRA predict: " + pred->targetRsu).c_str());
    mAgent->handover().requestPrediction(pred->targetRsu);
}

void VehicleTeeService::checkHandover()
{
    if (!mAgent) {
        return;
    }

    // Retry Forwarding_Request (and re-send encrypted Handover_Predict in case of 5G NR handover loss)
    if (mAgent->handover().inFlight() && (omnetpp::simTime() - mRequestSentAt).dbl() >= 2.5) {
        mRequestSentAt = omnetpp::simTime();
        mAgent->handover().resendPrediction();
        mAgent->handover().requestForwarding();
        return;
    }

    if (!mAgent->handover().pending()) {
        return;
    }

    const std::string& target = mAgent->handover().targetRsu();
    const bool shouldRequest = !mEnableCtra
        || mPredictor.shouldExecuteHandover(mAgent->session().currentRsu(), target, mHandoverRadius);

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

void VehicleTeeService::socketDataArrived(inet::UdpSocket*, inet::Packet* packet)
{
    std::unique_ptr<inet::Packet> owned(packet);
    if (!mAgent) {
        return;
    }
    try {
        const auto chunk = packet->peekDataAsBytes();
        const Bytes wire = chunk->getBytes();
        mAgent->indicate(deserialize(wire));
        checkHandover();
    } catch (const std::runtime_error& e) {
        EV_ERROR << mName << ": 5G NR UDP frame dropped: " << e.what() << "\n";
    }
}

void VehicleTeeService::socketErrorArrived(inet::UdpSocket*, inet::Indication* indication)
{
    EV_WARN << mName << ": UDP socket error indication: " << indication->getName() << "\n";
    delete indication;
}

void VehicleTeeService::socketClosed(inet::UdpSocket*)
{
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
    } else if (!msg->isSelfMessage()) {
        mSocket.processMessage(msg);
    } else {
        delete msg;
    }
}

inet::L3Address VehicleTeeService::resolveRsuAddress(const std::string& rsuName)
{
    const auto it = mRsuAddresses.find(rsuName);
    if (it != mRsuAddresses.end()) {
        return it->second;
    }
    const inet::L3Address addr = inet::L3AddressResolver().resolve(rsuName.c_str());
    mRsuAddresses[rsuName] = addr;
    return addr;
}

void VehicleTeeService::sendRadio(const ProtocolMsg& msg)
{
    const inet::L3Address destAddr = resolveRsuAddress(msg.getDestination());
    const Bytes wire = serialize(msg);
    auto* pkt = new inet::Packet(messageTypeName(msg.getType()));
    pkt->insertAtBack(inet::makeShared<inet::BytesChunk>(wire));
    mSocket.sendTo(pkt, destAddr, mDestPort);
}

double VehicleTeeService::positionX() const
{
    return mPredictor.state().x;
}

void VehicleTeeService::finish()
{
    unsubscribeNrServingCell();
    recordScalar("bootstrapped", mReady ? 1 : 0);
    recordScalar("secureDataSent", mSecureDataSent);
    recordScalar("ctraPredictionsSent", mPredictionsSent);
    recordScalar("prefetchesCompleted", mPrefetchesCompleted);
    recordScalar("handovers", mHandovers);
    recordScalar("nrRadioHandovers", mNrRadioHandovers);
    recordScalar("nrServingCellId", mLastNrServingCellId);
    for (const auto& [rsu, sent] : mSentTo) {
        recordScalar(("secureDataSentTo " + rsu).c_str(), sent);
    }
    if (mAgent) {
        recordScalar("protocolMessagesSent", mAgent->session().sent());
        recordScalar("protocolMessagesReceived", mAgent->session().received());
    }
    cSimpleModule::finish();
}
