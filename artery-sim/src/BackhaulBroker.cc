#include "BackhaulBroker.h"
#include "MessageType.h"
#include "SmartData.h"
#include "V2xFrame.h"
#include <omnetpp.h>
#include <optional>
#include <stdexcept>

Define_Module(BackhaulBroker)

BackhaulBroker::BackhaulBroker()
{
    mCloudJsonSignal = registerSignal("cloudJsonBytes");
}

BackhaulBroker::~BackhaulBroker() = default;

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
    const Bytes& gatewayPublicKey, RsuCallback onMessage)
{
    Enter_Method_Silent();
    const Bytes gwCert = ca().issue(gatewayPublicKey, rsuName);
    if (!esa().registerRsu(rsuName, gwCert)) {
        throw omnetpp::cRuntimeError("BackhaulBroker: ESA rejected certificate for RSU '%s'", rsuName.c_str());
    }
    mRsus[rsuName] = std::move(onMessage);
    mGatewayKeys[rsuName] = gatewayPublicKey;
    return RsuRegistration{ ca().publicKeyDer, gwCert, esa().certificate() };
}

void BackhaulBroker::requestActivation(const std::string& rsuName, simtime_t t0, simtime_t tf,
    const Uuid& uuid, const Sha256& firmwareHash)
{
    Enter_Method_Silent();
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
        humanOperator().handleMessage(msg);
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
    emit(mCloudJsonSignal, static_cast<long>(json->size()));
    return true;
}

void BackhaulBroker::finish()
{
    recordScalar("backhaulDelivered", mDelivered);
    recordScalar("backhaulUndeliverable", mUndeliverable);
    recordScalar("operatorConfirmations", mOperator ? mOperator->confirmationsReceived() : 0);
    recordScalar("cloudStored", mCloudStored);
    recordScalar("cloudRefused", mCloudRefused);
}
