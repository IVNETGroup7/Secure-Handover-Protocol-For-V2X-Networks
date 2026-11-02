#include "BackhaulBroker.h"
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

ExternalSecurityAgent& BackhaulBroker::esa()
{
    if (!mEsa) {
        mEsa = std::make_unique<ExternalSecurityAgent>(par("esaName").stdstringValue());
        // the ESA's replies (Activation_Token) go back over the backhaul to the RSU they name
        mEsa->setTransport([this](const BootstrapMsg& msg) { sendBackhaul(msg); });
    }
    return *mEsa;
}

CloudIdentity& BackhaulBroker::cloud()
{
    if (!mCloud) {
        mCloud = std::make_unique<CloudIdentity>(newCloudIdentity(kCloudAddress));
    }
    return *mCloud;
}

Bytes BackhaulBroker::registerRsu(const std::string& rsuName, const std::string& sessionKey,
    const Bytes& gatewayPublicKey, RsuCallback onMessage)
{
    Enter_Method_Silent();
    esa().registerRsu(rsuName, sessionKey, gatewayPublicKey);
    mRsus[rsuName] = std::move(onMessage);
    mGatewayKeys[rsuName] = gatewayPublicKey;
    return esa().publicKey(); // CY_e
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

void BackhaulBroker::sendBackhaul(const BootstrapMsg& msg)
{
    Enter_Method_Silent();
    // the frame waits here for the latency of the HTTPS session (a self-message: no gates to wire)
    auto frame = new V2xFrame(msg);
    frame->setKind(kBackhaulMsgKind);
    scheduleAt(omnetpp::simTime() + par("latency"), frame);
}

void BackhaulBroker::register5gNode(const std::string& name, RadioCallback onMessage, PositionGetter getX)
{
    Enter_Method_Silent();
    m5gNodes[name] = Node5G{std::move(onMessage), std::move(getX)};
}

void BackhaulBroker::send5gRadio(const std::string& sender, const BootstrapMsg& msg, double posX)
{
    Enter_Method_Silent();
    const double radius = par("nrCellRadius").doubleValue();
    const double gnb0 = par("gnb0X").doubleValue();
    const double gnb1 = par("gnb1X").doubleValue();

    bool inCoverage = false;
    const std::string& dest = msg.getDestination();
    if (dest == "rsu[0]" || sender == "rsu[0]") {
        inCoverage = (std::abs(posX - gnb0) <= radius);
    } else if (dest == "rsu[1]" || sender == "rsu[1]") {
        inCoverage = (std::abs(posX - gnb1) <= radius);
    } else {
        inCoverage = (std::abs(posX - gnb0) <= radius) || (std::abs(posX - gnb1) <= radius);
    }

    if (!inCoverage) {
        EV_WARN << "Simu5G NR: frame from " << sender << " at x=" << posX << " m dropped: out of 5G cell coverage\n";
        ++mNr5gDropped;
        return;
    }

    ++mNr5gTransmitted;
    auto frame = new V2xFrame(msg);
    frame->setKind(k5gRadioMsgKind);
    scheduleAt(omnetpp::simTime() + par("nr5gLatency"), frame);
}

void BackhaulBroker::handleMessage(omnetpp::cMessage* message)
{
    auto frame = dynamic_cast<V2xFrame*>(message);
    if (frame) {
        try {
            if (frame->getKind() == k5gRadioMsgKind) {
                deliver5gRadio(frame->msg());
            } else {
                deliver(frame->msg());
            }
        } catch (const std::runtime_error& e) {
            EV_ERROR << "frame dropped: " << e.what() << "\n";
            ++mUndeliverable;
        }
    }
    delete message;
}

void BackhaulBroker::deliver5gRadio(const BootstrapMsg& msg)
{
    const std::string& dest = msg.getDestination();
    if (dest == "broadcast") {
        for (const auto& [name, node] : m5gNodes) {
            if (name != msg.getSender() && node.callback) {
                node.callback(msg);
            }
        }
        return;
    }
    auto it = m5gNodes.find(dest);
    if (it != m5gNodes.end() && it->second.callback) {
        it->second.callback(msg);
        return;
    }
    auto vIt = m5gNodes.find(msg.getVehicle());
    if (vIt != m5gNodes.end() && vIt->second.callback) {
        vIt->second.callback(msg);
        return;
    }
    EV_WARN << "Simu5G NR: no recipient found for destination " << dest << "\n";
    ++mNr5gDropped;
}

void BackhaulBroker::deliver(const BootstrapMsg& msg)
{
    const std::string& destination = msg.getDestination();
    if (destination == esa().getFullName()) {
        ++mDelivered;
        esa().handleMessage(msg);
        return;
    }
    const auto rsu = mRsus.find(destination);
    if (rsu == mRsus.end()) {
        // Active_03 goes to the vehicle's user ("user"), outside the scenario
        EV_INFO << stageName(msg.getType()) << " for " << destination << ": not in the scenario\n";
        ++mUndeliverable;
        return;
    }
    ++mDelivered;
    rsu->second(msg);
}

void BackhaulBroker::postToCloud(const std::string& rsuName, const Bytes& itPacket)
{
    Enter_Method_Silent();
    // HTTPS Header | AES(K_eg, JSON): K_eg = SHA256(ECDH(X_e, Y_s)), Y_s from the header (common/SmartData.h)
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
                json.reset(); // Y_s is no key
            }
        }
    }
    if (!json) {
        EV_WARN << "cloud: IT packet of " << rsuName << " does not open with K_eg\n";
        ++mCloudRefused;
        return;
    }
    ++mCloudStored;
    emit(mCloudJsonSignal, static_cast<long>(json->size()));
}

void BackhaulBroker::finish()
{
    recordScalar("backhaulDelivered", mDelivered);
    recordScalar("backhaulUndeliverable", mUndeliverable);
    recordScalar("cloudStored", mCloudStored);
    recordScalar("cloudRefused", mCloudRefused);
    recordScalar("nr5gTransmitted", mNr5gTransmitted);
    recordScalar("nr5gDropped", mNr5gDropped);
}
