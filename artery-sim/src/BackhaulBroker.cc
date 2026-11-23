#include "BackhaulBroker.h"
#include "MessageType.h"
#include "SmartData.h"
#include "Trace.h"
#include "V2xFrame.h"
#include <omnetpp.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>

Define_Module(BackhaulBroker)

namespace
{

struct Stats
{
    size_t count = 0;
    double mean = 0.0;
    double stddev = 0.0;
    double min = 0.0;
    double p50 = 0.0;
    double p95 = 0.0;
    double p99 = 0.0;
    double max = 0.0;
};

double percentile(const std::vector<double>& sorted, double p)
{
    if (sorted.empty()) {
        return 0.0;
    }
    const double idx = (p / 100.0) * static_cast<double>(sorted.size() - 1);
    const size_t lo = static_cast<size_t>(std::floor(idx));
    const size_t hi = static_cast<size_t>(std::ceil(idx));
    const double frac = idx - static_cast<double>(lo);
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

Stats computeStats(const std::vector<double>& values)
{
    Stats s;
    if (values.empty()) {
        return s;
    }
    std::vector<double> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    s.count = sorted.size();
    s.min = sorted.front();
    s.max = sorted.back();
    s.p50 = percentile(sorted, 50.0);
    s.p95 = percentile(sorted, 95.0);
    s.p99 = percentile(sorted, 99.0);
    const double sum = std::accumulate(sorted.begin(), sorted.end(), 0.0);
    s.mean = sum / static_cast<double>(s.count);
    double var = 0.0;
    for (double v : sorted) {
        const double d = v - s.mean;
        var += d * d;
    }
    s.stddev = (s.count > 1) ? std::sqrt(var / static_cast<double>(s.count - 1)) : 0.0;
    return s;
}

std::optional<int64_t> parseJsonTimingNs(const std::string& json)
{
    const std::string key = "\"Timing\":";
    const size_t pos = json.find(key);
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    const size_t start = pos + key.size();
    size_t end = start;
    while (end < json.size() && (json[end] >= '0' && json[end] <= '9')) {
        ++end;
    }
    if (end == start) {
        return std::nullopt;
    }
    try {
        return std::stoll(json.substr(start, end - start));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::string fmt(double v, int prec = 3)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(prec) << v;
    return oss.str();
}

} // namespace

BackhaulBroker::BackhaulBroker()
{
    mCloudJsonSignal = registerSignal("cloudJsonBytes");
}

BackhaulBroker::~BackhaulBroker() = default;

void BackhaulBroker::initialize()
{
    mQuietTrace = par("quietTrace").boolValue();
    if (const char* envVerbose = std::getenv("V2X_VERBOSE"); envVerbose && envVerbose[0] == '1') {
        mQuietTrace = false;
    }
    trace::setEnabled(!mQuietTrace);
    otpAlgo();
}

OtpAlgo BackhaulBroker::otpAlgo()
{
    if (!mOtpAlgo) {
        std::string name = par("otpAlgo").stdstringValue();
        if (name.empty()) {
            if (const char* envAlgo = std::getenv("OTP_ALGO"); envAlgo && envAlgo[0] != '\0') {
                name = envAlgo;
            }
        }
        if (name.empty()) {
            name = "ascon";
        }
        const auto parsed = parseOtpAlgo(name);
        if (!parsed) {
            throw omnetpp::cRuntimeError(
                "BackhaulBroker: invalid otpAlgo '%s' (expected 'ascon' or 'poly1305')", name.c_str());
        }
        mOtpAlgo = *parsed;
        setOtpAlgorithm(*mOtpAlgo);
        std::printf("[BackhaulBroker] OTP algorithm: %s%s\n", otpAlgoName(*mOtpAlgo),
            mQuietTrace ? " (focused evaluation mode)" : "");
        std::fflush(stdout);
    }
    return *mOtpAlgo;
}

CertificateAuthority& BackhaulBroker::ca()
{
    if (!mCa) {
        mCa = std::make_unique<CertificateAuthority>(newCertificateAuthority("iiot-root-ca"));
    }
    return *mCa;
}

ExternalSecurityAgent& BackhaulBroker::esa()
{
    if (!mEsa) {
        mEsa = std::make_unique<ExternalSecurityAgent>(ca(), par("esaName").stdstringValue());
        mEsa->setTransport([this](const ProtocolMsg& msg) { sendBackhaul(msg); });
    }
    return *mEsa;
}

HumanOperator& BackhaulBroker::humanOperator()
{
    if (!mOperator) {
        mOperator = std::make_unique<HumanOperator>("operator");
        // Operator <-> ESA traffic stays strictly inside the IT domain
        mOperator->setTransport([this](const ProtocolMsg& msg) { sendBackhaul(msg); });
    }
    return *mOperator;
}

CloudIdentity& BackhaulBroker::cloud()
{
    if (!mCloud) {
        mCloud = std::make_unique<CloudIdentity>(newCloudIdentity(ca(), kCloudAddress));
    }
    return *mCloud;
}

BackhaulBroker::RsuRegistration BackhaulBroker::registerRsu(const std::string& rsuName,
    const Bytes& gatewayPublicKey, RsuCallback onMessage, PeerCertCallback onPeerCert)
{
    Enter_Method_Silent();
    const Bytes gwCert = ca().issue(gatewayPublicKey, rsuName);
    if (!esa().registerRsu(rsuName, gwCert)) {
        throw omnetpp::cRuntimeError("BackhaulBroker: ESA rejected certificate for RSU '%s'", rsuName.c_str());
    }
    mRsus[rsuName] = std::move(onMessage);
    mGatewayKeys[rsuName] = gatewayPublicKey;
    mGatewayCerts[rsuName] = gwCert;
    mPeerCertCallbacks[rsuName] = std::move(onPeerCert);

    for (const auto& [otherName, otherCert] : mGatewayCerts) {
        if (otherName == rsuName) {
            continue;
        }
        if (const auto& otherCb = mPeerCertCallbacks[otherName]) {
            otherCb(rsuName, gwCert);
        }
        if (const auto& myCb = mPeerCertCallbacks[rsuName]) {
            myCb(otherName, otherCert);
        }
    }
    return RsuRegistration{ ca().publicKeyDer, gwCert, esa().certificate() };
}

void BackhaulBroker::requestActivation(const std::string& rsuName, simtime_t t0, simtime_t tf,
    const Uuid& uuid, const Sha256& firmwareHash)
{
    Enter_Method_Silent();
    if (mActivationReqSec < 0.0) {
        mActivationReqSec = omnetpp::simTime().dbl();
    }
    humanOperator().requestActivation(gatewayPublicKey(rsuName), t0, tf, uuid, firmwareHash);
}

const Bytes& BackhaulBroker::gatewayPublicKey(const std::string& rsuName) const
{
    const auto key = mGatewayKeys.find(rsuName);
    if (key == mGatewayKeys.end()) {
        throw omnetpp::cRuntimeError("BackhaulBroker: no RSU '%s' registered", rsuName.c_str());
    }
    return key->second;
}

std::string BackhaulBroker::cloudCertificate()
{
    Enter_Method_Silent();
    return cloud().pem();
}

void BackhaulBroker::sendBackhaul(const ProtocolMsg& msg)
{
    Enter_Method_Silent();
    auto frame = new V2xFrame(msg);
    scheduleAt(omnetpp::simTime() + par("latency"), frame);
}

void BackhaulBroker::handleMessage(omnetpp::cMessage* message)
{
    if (auto frame = dynamic_cast<V2xFrame*>(message)) {
        try {
            deliver(frame->msg());
        } catch (const std::runtime_error& e) {
            EV_ERROR << "frame dropped: " << e.what() << "\n";
            ++mUndeliverable;
        }
    }
    delete message;
}

void BackhaulBroker::deliver(const ProtocolMsg& msg)
{
    const std::string& destination = msg.getDestination();
    if (destination == esa().getFullName()) {
        ++mDelivered;
        esa().handleMessage(msg);
        return;
    }
    if (destination == humanOperator().name()) {
        ++mDelivered;
        const size_t before = humanOperator().confirmationsReceived();
        humanOperator().handleMessage(msg);
        if (humanOperator().confirmationsReceived() > before && mOperatorConfirmSec < 0.0) {
            mOperatorConfirmSec = omnetpp::simTime().dbl();
        }
        return;
    }
    const auto rsu = mRsus.find(destination);
    if (rsu == mRsus.end()) {
        EV_INFO << messageTypeName(msg.getType()) << " for " << destination << ": not in the scenario\n";
        ++mUndeliverable;
        return;
    }
    ++mDelivered;
    rsu->second(msg);
}

void BackhaulBroker::recordVehicleTx(MessageType type, size_t wireBytes, int servingGnbId)
{
    mCurrentServingGnb = servingGnbId;
    if (type == Secure_Data) {
        ++mSecureDataSent;
        mDataBytesSent += wireBytes;
        const double now = omnetpp::simTime().dbl();
        if (mFirstDataTxSec < 0.0) {
            mFirstDataTxSec = now;
        }
        mLastDataTxSec = now;
    } else {
        ++mControlPacketsSent;
        mControlBytesSent += wireBytes;
    }
}

void BackhaulBroker::recordBootstrapTiming(double startSec, double readySec)
{
    mBootstrapped = true;
    mBootstrapStartSec = startSec;
    mBootstrapReadySec = readySec;
    if (mQuietTrace) {
        std::printf("[EVAL t=%.3fs] Bootstrap complete (delay=%.2f ms)\n",
            readySec, (readySec - startSec) * 1000.0);
        std::fflush(stdout);
    }
}

void BackhaulBroker::recordCtraPrediction(double tSec, const std::string& fromRsu, const std::string& predictedRsu,
    double currDistM, double minDistM, double ttcSec)
{
    ++mCtraPredictionsSent;
    mPendingPredFrom = fromRsu;
    mPendingPredTarget = predictedRsu;
    mPendingPredTimeSec = tSec;
    mPendingPrefetchReadySec = -1.0;
    if (mQuietTrace) {
        std::printf("[EVAL t=%.3fs] CTRA predict: %s -> %s (d_curr=%.1f m, d_min=%.1f m in %.1f s)\n",
            tSec, fromRsu.c_str(), predictedRsu.c_str(), currDistM, minDistM, ttcSec);
        std::fflush(stdout);
    }
}

void BackhaulBroker::recordPrefetchReady(double tSec, const std::string& targetRsu, double /*rttMs*/)
{
    if (targetRsu == mPendingPredTarget) {
        mPendingPrefetchReadySec = tSec;
    }
}

void BackhaulBroker::recordHandoverRequest(double tSec, const std::string& /*fromRsu*/,
    const std::string& /*targetRsu*/, double distM)
{
    ++mHandoversAttempted;
    mPendingFwdReqSec = tSec;
    mPendingHandoverDistM = distM;
}

void BackhaulBroker::recordHandoverComplete(double tSec, const std::string& fromRsu, const std::string& targetRsu,
    double e2eDelayMs, double leadTimeMs)
{
    ++mHandoversCompleted;
    const bool accurate = (!mPendingPredTarget.empty() && mPendingPredTarget == targetRsu);
    if (accurate) {
        ++mCtraPredictionsAccurate;
    }

    HandoverRecord rec;
    rec.id = static_cast<int>(mHandoversCompleted);
    rec.fromRsu = fromRsu;
    rec.toRsu = targetRsu;
    rec.ctraPredictTimeSec = mPendingPredTimeSec;
    rec.ctraAccurate = accurate;
    rec.prefetchReadyTimeSec = mPendingPrefetchReadySec;
    rec.fwdReqTimeSec = mPendingFwdReqSec;
    rec.fwdGrantedTimeSec = tSec;
    rec.prefetchLeadTimeMs = leadTimeMs;
    rec.handoverE2EDelayMs = e2eDelayMs;
    rec.handoverDistM = mPendingHandoverDistM;

    // Pair with the nearest unmatched 5G NR X2 radio handover event
    for (auto& nr : mNrHandovers) {
        if (!nr.matched && std::abs(nr.timeSec - tSec) <= 10.0) {
            nr.matched = true;
            rec.nrX2HandoverTimeSec = nr.timeSec;
            rec.nrFromGnb = nr.fromGnb;
            rec.nrToGnb = nr.toGnb;
            break;
        }
    }

    mHandoverRecords.push_back(rec);

    if (mQuietTrace) {
        std::printf("[EVAL t=%.3fs] Handover #%d: %s -> %s (delay=%.2f ms, prefetch_lead=%.0f ms, CTRA=%s)\n",
            tSec, rec.id, fromRsu.c_str(), targetRsu.c_str(), e2eDelayMs, leadTimeMs,
            accurate ? "HIT" : "MISS");
        std::fflush(stdout);
    }

    mPendingPredFrom.clear();
    mPendingPredTarget.clear();
    mPendingPredTimeSec = -1.0;
    mPendingPrefetchReadySec = -1.0;
    mPendingFwdReqSec = -1.0;
    mPendingHandoverDistM = -1.0;
}

void BackhaulBroker::recordNrRadioHandover(double tSec, int fromGnb, int toGnb)
{
    mCurrentServingGnb = toGnb;
    mNrHandovers.push_back({ tSec, fromGnb, toGnb, false });
    if (mQuietTrace) {
        std::printf("[EVAL t=%.3fs] 5G NR X2 Handover #%zu: gNB[%d] -> gNB[%d]\n",
            tSec, mNrHandovers.size(), fromGnb - 1, toGnb - 1);
        std::fflush(stdout);
    }
}

void BackhaulBroker::recordNrRadioSample(double sinrDlDb, double sinrUlDb, double cqiDl, double cqiUl)
{
    if (!std::isnan(sinrDlDb)) {
        mSinrDlSamples.push_back(sinrDlDb);
    }
    if (!std::isnan(sinrUlDb)) {
        mSinrUlSamples.push_back(sinrUlDb);
    }
    if (!std::isnan(cqiDl)) {
        mCqiDlSamples.push_back(cqiDl);
    }
    if (!std::isnan(cqiUl)) {
        mCqiUlSamples.push_back(cqiUl);
    }
}

void BackhaulBroker::recordRsuSecureDataRx(const std::string& rsuName, int64_t rsuRxNs, size_t wireBytes)
{
    ++mRsuSecureDataRx;
    mRsuRxQueues[rsuName].push_back({ rsuRxNs, wireBytes });
}

void BackhaulBroker::recordRsuMarshalRefused(const std::string& rsuName)
{
    ++mMarshalRefusedTotal;
    ++mMarshalRefusedPerRsu[rsuName];
}

void BackhaulBroker::recordRsuTaWallUs(const std::string& /*rsuName*/, double wallUs)
{
    mTaWallUs.push_back(wallUs);
}

bool BackhaulBroker::postToCloud(const std::string& rsuName, const Bytes& itPacket)
{
    Enter_Method_Silent();
    const std::string text(itPacket.begin(), itPacket.end());
    const std::string field = std::string("\r\n") + kSessionKeyHeader + ": ";
    const size_t end = text.find("\r\n\r\n");
    const size_t start = text.find(field);
    std::optional<Bytes> json;
    if (end != std::string::npos && start != std::string::npos && start < end) {
        const size_t value = start + field.size();
        if (const auto ys = base64Decode(text.substr(value, text.find("\r\n", value) - value))) {
            try {
                const Bytes kEg = computeKEg(cloud().key.get(), publicKeyFromDer(*ys).get());
                json = aesGcmDecrypt(kEg, Bytes(itPacket.begin() + static_cast<long>(end) + 4, itPacket.end()));
            } catch (const std::runtime_error&) {
                json.reset();
            }
        }
    }
    if (!json) {
        EV_WARN << "cloud: IT packet of " << rsuName << " does not open with K_eg\n";
        ++mCloudRefused;
        return false;
    }

    ++mCloudStored;
    ++mCloudStoredPerRsu[rsuName];
    mCloudJsonBytesTotal += json->size();
    emit(mCloudJsonSignal, static_cast<long>(json->size()));

    const int64_t cloudRxNs = omnetpp::simTime().inUnit(omnetpp::SIMTIME_NS);
    const double cloudRxSec = cloudRxNs / 1e9;
    if (mFirstCloudRxSec < 0.0) {
        mFirstCloudRxSec = cloudRxSec;
    }
    mLastCloudRxSec = cloudRxSec;

    // Extract exact vehicle transmission timestamp ("Timing":<ns>) from decrypted SmartData JSON
    const std::string jsonStr(json->begin(), json->end());
    const auto txNsOpt = parseJsonTimingNs(jsonStr);
    const int64_t txNs = txNsOpt.value_or(cloudRxNs);

    // Match the corresponding RSU radio arrival timestamp (skipping any older refused packets in HIL)
    int64_t rsuRxNs = cloudRxNs;
    size_t otBytes = 0;
    auto& q = mRsuRxQueues[rsuName];
    while (!q.empty() && q.front().rxNs < txNs) {
        q.pop_front();
    }
    if (!q.empty()) {
        rsuRxNs = q.front().rxNs;
        otBytes = q.front().wireBytes;
        q.pop_front();
    }

    const double e2eMs = std::max(0.0, static_cast<double>(cloudRxNs - txNs) / 1e6);
    const double uplinkMs = (rsuRxNs >= txNs) ? static_cast<double>(rsuRxNs - txNs) / 1e6 : 0.0;
    const double rsuTaMs = (cloudRxNs >= rsuRxNs) ? static_cast<double>(cloudRxNs - rsuRxNs) / 1e6 : 0.0;
    const double jitterMs = mHasPrevE2e ? std::abs(e2eMs - mPrevE2eMs) : 0.0;
    mHasPrevE2e = true;
    mPrevE2eMs = e2eMs;

    // Detect RSU transition at Cloud -> compute Handover Interruption Time (HIT)
    if (!mLastCloudRsu.empty() && mLastCloudRsu != rsuName && mLastCloudRxNs >= 0) {
        const double hitMs = static_cast<double>(cloudRxNs - mLastCloudRxNs) / 1e6;
        for (auto it = mHandoverRecords.rbegin(); it != mHandoverRecords.rend(); ++it) {
            if (it->fromRsu == mLastCloudRsu && it->toRsu == rsuName && it->interruptionTimeMs < 0.0) {
                it->interruptionTimeMs = hitMs;
                break;
            }
        }
    }
    mLastCloudRsu = rsuName;
    mLastCloudRxNs = cloudRxNs;

    mPacketRecords.push_back(PacketRecord{
        mCloudStored,
        static_cast<double>(txNs) / 1e9,
        static_cast<double>(rsuRxNs) / 1e9,
        cloudRxSec,
        rsuName,
        mCurrentServingGnb,
        otBytes,
        json->size(),
        uplinkMs,
        rsuTaMs,
        e2eMs,
        jitterMs
    });

    return true;
}

std::string BackhaulBroker::resolveCsvPrefix() const
{
    std::string prefix = par("csvOutputPrefix").stdstringValue();
    if (prefix.empty()) {
        if (const char* envPrefix = std::getenv("CSV_PREFIX"); envPrefix && envPrefix[0] != '\0') {
            prefix = envPrefix;
        }
    }
    if (!prefix.empty()) {
        return prefix;
    }

    const auto* cfg = getSimulation()->getEnvir()->getConfigEx();
    const char* resultDir = cfg->getVariable(CFGVAR_RESULTDIR);
    const char* configName = cfg->getVariable(CFGVAR_CONFIGNAME);
    const std::string dir = (resultDir && resultDir[0] != '\0') ? resultDir : "results";
    const std::string name = (configName && configName[0] != '\0') ? configName : "sim";
    const std::string algo = mOtpAlgo ? otpAlgoName(*mOtpAlgo) : "ascon";
    return dir + "/" + name + "-" + algo;
}

void BackhaulBroker::exportMetricsAndReport()
{
    const std::string prefix = resolveCsvPrefix();
    const std::string summaryPath = prefix + "-summary.csv";
    const std::string handoversPath = prefix + "-handovers.csv";
    const std::string packetsPath = prefix + "-packets.csv";

    const auto* cfg = getSimulation()->getEnvir()->getConfigEx();
    const std::string configName = cfg->getVariable(CFGVAR_CONFIGNAME) ? cfg->getVariable(CFGVAR_CONFIGNAME) : "";
    const std::string algoName = mOtpAlgo ? otpAlgoName(*mOtpAlgo) : "ascon";
    const double simDurSec = omnetpp::simTime().dbl();
    const double activeDurSec = (mFirstDataTxSec >= 0.0 && mLastDataTxSec > mFirstDataTxSec)
        ? (mLastDataTxSec - mFirstDataTxSec) : 0.0;

    // Collect latency / jitter / handover vectors
    std::vector<double> e2eVec, uplinkVec, rsuTaVec, jitterVec;
    e2eVec.reserve(mPacketRecords.size());
    uplinkVec.reserve(mPacketRecords.size());
    rsuTaVec.reserve(mPacketRecords.size());
    jitterVec.reserve(mPacketRecords.size());
    for (size_t i = 0; i < mPacketRecords.size(); ++i) {
        const auto& p = mPacketRecords[i];
        e2eVec.push_back(p.e2eLatencyMs);
        uplinkVec.push_back(p.nrUplinkMs);
        rsuTaVec.push_back(p.rsuTaMs);
        if (i > 0) {
            jitterVec.push_back(p.jitterMs);
        }
    }

    std::vector<double> hoDelayVec, hoHitVec, leadTimeVec;
    for (const auto& h : mHandoverRecords) {
        if (h.handoverE2EDelayMs >= 0.0) hoDelayVec.push_back(h.handoverE2EDelayMs);
        if (h.interruptionTimeMs >= 0.0) hoHitVec.push_back(h.interruptionTimeMs);
        if (h.prefetchLeadTimeMs >= 0.0) leadTimeVec.push_back(h.prefetchLeadTimeMs);
    }

    const Stats e2eSt = computeStats(e2eVec);
    const Stats upSt = computeStats(uplinkVec);
    const Stats taSt = computeStats(rsuTaVec);
    const Stats taWallSt = computeStats(mTaWallUs);
    const Stats jitSt = computeStats(jitterVec);
    const Stats hoSt = computeStats(hoDelayVec);
    const Stats hitSt = computeStats(hoHitVec);
    const Stats leadSt = computeStats(leadTimeVec);
    const Stats sinrDlSt = computeStats(mSinrDlSamples);
    const Stats sinrUlSt = computeStats(mSinrUlSamples);
    const Stats cqiDlSt = computeStats(mCqiDlSamples);
    const Stats cqiUlSt = computeStats(mCqiUlSamples);

    const double otPdrPct = (mSecureDataSent > 0)
        ? (100.0 * static_cast<double>(mRsuSecureDataRx) / static_cast<double>(mSecureDataSent)) : 0.0;
    const double e2ePdrPct = (mSecureDataSent > 0)
        ? (100.0 * static_cast<double>(mCloudStored) / static_cast<double>(mSecureDataSent)) : 0.0;
    const double e2ePlrPct = 100.0 - e2ePdrPct;
    const long taTotal = mCloudStored + mMarshalRefusedTotal;
    const double taAcceptPct = (taTotal > 0)
        ? (100.0 * static_cast<double>(mCloudStored) / static_cast<double>(taTotal)) : 0.0;

    const double otGoodputKbps = (activeDurSec > 0.0)
        ? (static_cast<double>(mDataBytesSent) * 8.0 / 1000.0 / activeDurSec) : 0.0;
    const double cloudGoodputKbps = (activeDurSec > 0.0)
        ? (static_cast<double>(mCloudJsonBytesTotal) * 8.0 / 1000.0 / activeDurSec) : 0.0;
    const size_t totalTxBytes = mControlBytesSent + mDataBytesSent;
    const double ctrlOverheadPct = (totalTxBytes > 0)
        ? (100.0 * static_cast<double>(mControlBytesSent) / static_cast<double>(totalTxBytes)) : 0.0;

    const double bootstrapMs = (mBootstrapped && mBootstrapStartSec >= 0.0)
        ? (mBootstrapReadySec - mBootstrapStartSec) * 1000.0 : 0.0;
    const double operatorConfirmMs = (mActivationReqSec >= 0.0 && mOperatorConfirmSec >= mActivationReqSec)
        ? (mOperatorConfirmSec - mActivationReqSec) * 1000.0 : 0.0;
    const double hoSuccessPct = (mHandoversAttempted > 0)
        ? (100.0 * static_cast<double>(mHandoversCompleted) / static_cast<double>(mHandoversAttempted)) : 0.0;
    const double ctraAccPct = (mCtraPredictionsSent > 0)
        ? (100.0 * static_cast<double>(mCtraPredictionsAccurate) / static_cast<double>(mCtraPredictionsSent)) : 0.0;
    const int numCandidateNeighbors = std::max(1, static_cast<int>(mRsus.size()) - 1);
    const double backhaulReductionPct = (numCandidateNeighbors > 1)
        ? (100.0 * static_cast<double>(numCandidateNeighbors - 1) / static_cast<double>(numCandidateNeighbors)) : 0.0;

    // 1. Write summary CSV
    {
        std::ofstream out(summaryPath);
        if (out) {
            out << "category,metric,value,unit,description\n";
            auto row = [&](const char* cat, const char* metric, const std::string& val, const char* unit, const char* desc) {
                out << cat << "," << metric << "," << val << "," << unit << ",\"" << desc << "\"\n";
            };
            row("metadata", "config_name", configName, "-", "OMNeT++ simulation configuration");
            row("metadata", "mode", mHilMode ? "HIL_OPTEE_HARDWARE" : "HOST_SIM", "-", "RSU Trusted Execution backend");
            row("metadata", "radio_technology", "5G_NR_Simu5G_CrowNet", "-", "V2X radio access stack");
            row("metadata", "otp_algorithm", algoName, "-", "Single run-wide OTP/MAC primitive");
            row("metadata", "sim_duration_s", fmt(simDurSec, 3), "s", "Total simulated time");
            row("metadata", "active_data_duration_s", fmt(activeDurSec, 3), "s", "Active Secure_Data transmission window");

            row("reliability", "secure_data_sent", std::to_string(mSecureDataSent), "packets", "Total Secure_Data packets transmitted by vehicle");
            row("reliability", "rsu_secure_data_received", std::to_string(mRsuSecureDataRx), "packets", "Secure_Data packets delivered over 5G NR to RSUs");
            row("reliability", "cloud_stored", std::to_string(mCloudStored), "packets", "IT SmartData packets decrypted and stored by Cloud");
            row("reliability", "marshal_refused", std::to_string(mMarshalRefusedTotal), "packets", "Packets rejected by OP-TEE TA (e.g. OTP slot expiry during Cloud key rotation)");
            row("reliability", "cloud_refused", std::to_string(mCloudRefused), "packets", "IT packets failing Cloud AES-GCM / ECDH verification");
            row("reliability", "ot_pdr_pct", fmt(otPdrPct, 3), "%", "5G NR Uplink Packet Delivery Ratio (Vehicle -> RSU)");
            row("reliability", "e2e_cloud_pdr_pct", fmt(e2ePdrPct, 3), "%", "End-to-End Packet Delivery Ratio (Vehicle -> 5G NR -> OP-TEE TA -> Cloud)");
            row("reliability", "e2e_plr_pct", fmt(e2ePlrPct, 3), "%", "End-to-End Packet Loss Ratio");
            row("reliability", "ta_acceptance_rate_pct", fmt(taAcceptPct, 3), "%", "OP-TEE TA Secure Marshaling acceptance rate");

            row("throughput", "ot_tx_goodput_kbps", fmt(otGoodputKbps, 3), "kbps", "Vehicle OT Secure_Data transmission goodput");
            row("throughput", "cloud_it_goodput_kbps", fmt(cloudGoodputKbps, 3), "kbps", "Cloud decrypted SmartData JSON goodput");
            row("throughput", "control_packets_sent", std::to_string(mControlPacketsSent), "packets", "Bootstrap + CTRA + Secrecy Forwarding control packets sent");
            row("throughput", "control_bytes_sent", std::to_string(mControlBytesSent), "B", "Total security control plane bytes sent by vehicle");
            row("throughput", "data_bytes_sent", std::to_string(mDataBytesSent), "B", "Total Secure_Data payload bytes sent by vehicle");
            row("throughput", "protocol_control_overhead_pct", fmt(ctrlOverheadPct, 3), "%", "Security control bytes as % of total vehicle bytes");
            row("throughput", "backhaul_messages_delivered", std::to_string(mDelivered), "messages", "IT/backhaul messages delivered (ESA + RSU peer notices)");

            row("latency", "e2e_latency_mean_ms", fmt(e2eSt.mean, 3), "ms", "Mean End-to-End OT->Cloud latency");
            row("latency", "e2e_latency_std_ms", fmt(e2eSt.stddev, 3), "ms", "Stddev End-to-End OT->Cloud latency");
            row("latency", "e2e_latency_min_ms", fmt(e2eSt.min, 3), "ms", "Min End-to-End OT->Cloud latency");
            row("latency", "e2e_latency_p50_ms", fmt(e2eSt.p50, 3), "ms", "Median (p50) End-to-End OT->Cloud latency");
            row("latency", "e2e_latency_p95_ms", fmt(e2eSt.p95, 3), "ms", "95th percentile End-to-End OT->Cloud latency");
            row("latency", "e2e_latency_p99_ms", fmt(e2eSt.p99, 3), "ms", "99th percentile End-to-End OT->Cloud latency");
            row("latency", "e2e_latency_max_ms", fmt(e2eSt.max, 3), "ms", "Max End-to-End OT->Cloud latency");
            row("latency", "jitter_mean_ms", fmt(jitSt.mean, 3), "ms", "Mean RFC 3550 inter-packet delay variation (IPDV)");
            row("latency", "jitter_p95_ms", fmt(jitSt.p95, 3), "ms", "95th percentile latency jitter");
            row("latency", "jitter_max_ms", fmt(jitSt.max, 3), "ms", "Max latency jitter");
            row("latency", "nr_uplink_latency_mean_ms", fmt(upSt.mean, 3), "ms", "Mean 5G NR uplink latency (Vehicle -> RSU)");
            row("latency", "nr_uplink_latency_p95_ms", fmt(upSt.p95, 3), "ms", "95th percentile 5G NR uplink latency");
            row("latency", "rsu_ta_turnaround_mean_ms", fmt(taSt.mean, 3), "ms", "Mean RSU OP-TEE + backhaul turnaround (RSU RX -> Cloud)");
            row("latency", "rsu_ta_turnaround_p95_ms", fmt(taSt.p95, 3), "ms", "95th percentile RSU OP-TEE + backhaul turnaround");
            row("latency", "rsu_ta_turnaround_max_ms", fmt(taSt.max, 3), "ms", "Max RSU OP-TEE + backhaul turnaround");
            if (!mTaWallUs.empty()) {
                row("latency", "host_ta_invoke_mean_us", fmt(taWallSt.mean, 2), "us", "Mean HOST_SIM TA marshal wall-clock time");
                row("latency", "host_ta_invoke_p95_us", fmt(taWallSt.p95, 2), "us", "95th percentile HOST_SIM TA marshal wall-clock time");
            }

            row("handover", "bootstrap_success", mBootstrapped ? "1" : "0", "bool", "Initial Operator + CA + OP-TEE bootstrap succeeded");
            row("handover", "bootstrap_delay_ms", fmt(bootstrapMs, 3), "ms", "OT bootstrap completion latency (PTP + ECDH + Auth + Active_01)");
            row("handover", "operator_confirmations", std::to_string(mOperator ? mOperator->confirmationsReceived() : 0), "count", "Active_03 confirmations received by Human Operator");
            row("handover", "operator_e2e_confirmation_ms", fmt(operatorConfirmMs, 3), "ms", "Phase A Activation_Request -> Phase C Active_03 total delay");
            row("handover", "handovers_attempted", std::to_string(mHandoversAttempted), "count", "Secrecy Forwarding handovers initiated");
            row("handover", "handovers_completed", std::to_string(mHandoversCompleted), "count", "Secrecy Forwarding handovers completed");
            row("handover", "handover_success_rate_pct", fmt(hoSuccessPct, 2), "%", "Secrecy Forwarding handover success rate");
            row("handover", "handover_latency_mean_ms", fmt(hoSt.mean, 3), "ms", "Mean Secrecy Forwarding latency (Forwarding_Request -> Granted)");
            row("handover", "handover_latency_std_ms", fmt(hoSt.stddev, 3), "ms", "Stddev Secrecy Forwarding handover latency");
            row("handover", "handover_latency_min_ms", fmt(hoSt.min, 3), "ms", "Min Secrecy Forwarding handover latency");
            row("handover", "handover_latency_max_ms", fmt(hoSt.max, 3), "ms", "Max Secrecy Forwarding handover latency");
            row("handover", "handover_interruption_time_mean_ms", fmt(hitSt.mean, 3), "ms", "Mean Handover Interruption Time (HIT: Cloud packet gap across RSU switch)");
            row("handover", "handover_interruption_time_max_ms", fmt(hitSt.max, 3), "ms", "Max Handover Interruption Time (HIT)");

            row("ctra", "ctra_predictions_sent", std::to_string(mCtraPredictionsSent), "count", "CTRA Handover_Predict notifications sent");
            row("ctra", "ctra_predictions_accurate", std::to_string(mCtraPredictionsAccurate), "count", "CTRA predictions matching actual handover target RSU");
            row("ctra", "ctra_prediction_accuracy_pct", fmt(ctraAccPct, 2), "%", "CTRA single-target RSU prediction accuracy");
            row("ctra", "prefetch_lead_time_mean_ms", fmt(leadSt.mean, 2), "ms", "Mean token pre-fetch lead time before Forwarding_Request");
            row("ctra", "prefetch_lead_time_min_ms", fmt(leadSt.min, 2), "ms", "Min token pre-fetch lead time");
            row("ctra", "prefetch_lead_time_max_ms", fmt(leadSt.max, 2), "ms", "Max token pre-fetch lead time");
            row("ctra", "backhaul_signaling_reduction_pct", fmt(backhaulReductionPct, 2), "%", "Backhaul notice reduction vs flooding all N-1 neighbor RSUs");

            row("5g_nr", "nr_radio_handovers", std::to_string(mNrHandovers.size()), "count", "Simu5G 5G NR X2 gNodeB radio handovers");
            row("5g_nr", "nr_sinr_dl_mean_db", fmt(sinrDlSt.mean, 3), "dB", "Mean 5G NR downlink SINR");
            row("5g_nr", "nr_sinr_ul_mean_db", fmt(sinrUlSt.mean, 3), "dB", "Mean 5G NR uplink SINR");
            row("5g_nr", "nr_cqi_dl_mean", fmt(cqiDlSt.mean, 3), "-", "Mean 5G NR downlink CQI");
            row("5g_nr", "nr_cqi_ul_mean", fmt(cqiUlSt.mean, 3), "-", "Mean 5G NR uplink CQI");
        }
    }

    // 2. Write per-handover CSV
    {
        std::ofstream out(handoversPath);
        if (out) {
            out << "handover_id,from_rsu,to_rsu,ctra_predict_time_s,ctra_accurate,prefetch_ready_time_s,"
                << "nr_x2_handover_time_s,nr_from_gnb,nr_to_gnb,fwd_req_time_s,fwd_granted_time_s,"
                << "prefetch_lead_time_ms,handover_e2e_delay_ms,handover_interruption_time_ms,handover_dist_m\n";
            for (const auto& h : mHandoverRecords) {
                out << h.id << "," << h.fromRsu << "," << h.toRsu << ","
                    << fmt(h.ctraPredictTimeSec, 4) << "," << (h.ctraAccurate ? 1 : 0) << ","
                    << fmt(h.prefetchReadyTimeSec, 4) << ","
                    << fmt(h.nrX2HandoverTimeSec, 5) << "," << h.nrFromGnb << "," << h.nrToGnb << ","
                    << fmt(h.fwdReqTimeSec, 4) << "," << fmt(h.fwdGrantedTimeSec, 4) << ","
                    << fmt(h.prefetchLeadTimeMs, 2) << "," << fmt(h.handoverE2EDelayMs, 3) << ","
                    << fmt(h.interruptionTimeMs, 3) << "," << fmt(h.handoverDistM, 2) << "\n";
            }
        }
    }

    // 3. Write per-packet time-series CSV
    {
        std::ofstream out(packetsPath);
        if (out) {
            out << "seq,tx_time_s,rsu_rx_time_s,cloud_rx_time_s,rsu,serving_gnb,"
                << "ot_bytes,it_json_bytes,nr_uplink_ms,rsu_ta_ms,e2e_latency_ms,jitter_ms\n";
            for (const auto& p : mPacketRecords) {
                out << p.seq << "," << fmt(p.txTimeSec, 6) << "," << fmt(p.rsuRxTimeSec, 6) << ","
                    << fmt(p.cloudRxTimeSec, 6) << "," << p.rsu << "," << p.servingGnb << ","
                    << p.otBytes << "," << p.itJsonBytes << ","
                    << fmt(p.nrUplinkMs, 3) << "," << fmt(p.rsuTaMs, 3) << ","
                    << fmt(p.e2eLatencyMs, 3) << "," << fmt(p.jitterMs, 3) << "\n";
            }
        }
    }

    // 4. Print focused academic evaluation report to stdout
    std::printf("\n==============================================================================\n");
    std::printf("  V2X 5G NR + OP-TEE EVALUATION REPORT (%s | %s | OTP=%s)\n",
        configName.c_str(), mHilMode ? "HIL RPi3/VM" : "HOST_SIM", algoName.c_str());
    std::printf("==============================================================================\n");
    std::printf("  [Reliability & Delivery]\n");
    std::printf("    OT PDR (Vehicle -> RSU)          : %6.2f%%  (%ld / %ld pkts)\n", otPdrPct, mRsuSecureDataRx, mSecureDataSent);
    std::printf("    E2E Cloud PDR (Vehicle -> Cloud) : %6.2f%%  (%ld / %ld pkts, PLR=%.2f%%)\n", e2ePdrPct, mCloudStored, mSecureDataSent, e2ePlrPct);
    std::printf("    TA Acceptance / Cloud Integrity  : %6.2f%%  (marshalRefused=%ld, cloudRefused=%ld)\n", taAcceptPct, mMarshalRefusedTotal, mCloudRefused);
    std::printf("  [Throughput & Signaling Overhead]\n");
    std::printf("    OT / Cloud Goodput               : %.2f kbps (OT) | %.2f kbps (Cloud JSON)\n", otGoodputKbps, cloudGoodputKbps);
    std::printf("    Protocol Control Overhead        : %.3f%%  (%zu B ctrl / %zu B data, %ld backhaul msgs)\n",
        ctrlOverheadPct, mControlBytesSent, mDataBytesSent, mDelivered);
    std::printf("  [End-to-End Latency & Jitter (OT -> 5G NR -> OP-TEE TA -> Cloud)]\n");
    std::printf("    E2E Latency (ms)                 : mean=%.2f  std=%.2f  p50=%.2f  p95=%.2f  p99=%.2f  max=%.2f\n",
        e2eSt.mean, e2eSt.stddev, e2eSt.p50, e2eSt.p95, e2eSt.p99, e2eSt.max);
    std::printf("    5G NR Uplink / RSU TA Turnaround : uplink mean=%.2f ms (p95=%.2f) | TA mean=%.2f ms (p95=%.2f, max=%.2f)\n",
        upSt.mean, upSt.p95, taSt.mean, taSt.p95, taSt.max);
    std::printf("    Latency Jitter / IPDV (ms)       : mean=%.2f  p95=%.2f  max=%.2f\n",
        jitSt.mean, jitSt.p95, jitSt.max);
    std::printf("  [Bootstrap, CTRA Prediction & Secrecy Forwarding Handover]\n");
    std::printf("    Bootstrap / Operator E2E Delay   : %.2f ms (OT) | %.2f ms (Operator Active_03)\n",
        bootstrapMs, operatorConfirmMs);
    std::printf("    CTRA Prediction Accuracy         : %.1f%%  (%ld / %ld) | pre-fetch lead=%.0f ms | backhaul reduction=%.1f%%\n",
        ctraAccPct, mCtraPredictionsAccurate, mCtraPredictionsSent, leadSt.mean, backhaulReductionPct);
    std::printf("    Secrecy Forwarding Handovers     : %ld / %ld (%.1f%%) | delay mean=%.2f ms (min=%.2f, max=%.2f)\n",
        mHandoversCompleted, mHandoversAttempted, hoSuccessPct, hoSt.mean, hoSt.min, hoSt.max);
    std::printf("    Handover Interruption Time (HIT) : mean=%.2f ms  max=%.2f ms\n", hitSt.mean, hitSt.max);
    std::printf("  [5G NR Radio Layer (Simu5G)]\n");
    std::printf("    5G NR X2 Radio Handovers         : %zu\n", mNrHandovers.size());
    std::printf("    5G NR SINR / CQI (mean)          : DL=%.2f dB (CQI=%.2f) | UL=%.2f dB (CQI=%.2f)\n",
        sinrDlSt.mean, cqiDlSt.mean, sinrUlSt.mean, cqiUlSt.mean);
    std::printf("  [CSV Outputs]\n");
    std::printf("    Summary   : %s\n", summaryPath.c_str());
    std::printf("    Handovers : %s\n", handoversPath.c_str());
    std::printf("    Packets   : %s\n", packetsPath.c_str());
    std::printf("==============================================================================\n\n");
    std::fflush(stdout);
}

void BackhaulBroker::finish()
{
    recordScalar("backhaulDelivered", mDelivered);
    recordScalar("backhaulUndeliverable", mUndeliverable);
    recordScalar("operatorConfirmations", mOperator ? mOperator->confirmationsReceived() : 0);
    recordScalar("cloudStored", mCloudStored);
    recordScalar("cloudRefused", mCloudRefused);
    exportMetricsAndReport();
}
