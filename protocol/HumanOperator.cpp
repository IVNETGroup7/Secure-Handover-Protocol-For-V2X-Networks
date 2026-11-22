#include "HumanOperator.h"
#include "BootstrapPayload.h"
#include "MessageType.h"
#include "ProtocolMsg.h"
#include "Trace.h"
#include <algorithm>
#include <stdexcept>

HumanOperator::HumanOperator(std::string name) : mName(std::move(name))
{
}

void HumanOperator::requestActivation(const Bytes& gatewayPublicKey, simtime_t t0, simtime_t tf,
    const Uuid& uuid, const Sha256& firmwareHash)
{
    if (!mTransport) {
        throw std::runtime_error(mName + ": no IT/HTTPS transport to ESA");
    }

    trace::step(mName, "ActivationRequest (IT -> ESA)");

    ActivationRequestPayload m;
    m.type = Activation_Request;
    m.gatewayPublicKey = gatewayPublicKey;
    m.t0 = t0;
    m.tf = tf;
    m.uuid = uuid;
    m.firmwareHash = firmwareHash;
    for (const std::string& line : describe(m)) {
        trace::detail(mName, line);
    }

    mPending.push_back(DeviceRecord{ uuid, firmwareHash });

    ProtocolMsg msg;
    msg.setType(Activation_Request);
    msg.setSender(mName);
    msg.setDestination("esa");
    msg.setVehicle(""); // Anonymous: no OT device network label carried in IT activation
    msg.setSeqNum(mRequestsSent);
    msg.setAckNum(0);
    setPayload(msg, pack(m));
    ++mRequestsSent;

    mTransport(msg);
}

void HumanOperator::handleMessage(const ProtocolMsg& msg)
{
    if (msg.getDestination() != mName || msg.getType() != Active_03) {
        return;
    }

    trace::step(mName, "Active03 (ESA -> Operator)", messageTypeName(msg.getType()), msg.getSender());

    const Active03Payload done = unpackActive03(getPayload(msg));
    for (const std::string& line : describe(done)) {
        trace::detail(mName, line);
    }

    auto it = std::find_if(mPending.begin(), mPending.end(), [&](const DeviceRecord& r) {
        return r.uuid == done.uuid && r.firmwareHash == done.firmwareHash;
    });
    if (it == mPending.end()) {
        trace::check(mName, false, "Active_03 for unknown or unrequested (UUID, SHA256(f_w)): ignored");
        return;
    }

    trace::check(mName, true, "device " + toString(done.uuid) + " confirmed active and authenticated");
    mConfirmed.push_back(*it);
    mPending.erase(it);
    ++mConfirmationsReceived;
    trace::end(mName, "activation acknowledged (" + toString(done.uuid) + ")");

    if (mOnConfirmed) {
        mOnConfirmed(done.uuid, done.firmwareHash);
    }
}

bool HumanOperator::isConfirmed(const Uuid& uuid) const
{
    return std::any_of(mConfirmed.begin(), mConfirmed.end(), [&](const DeviceRecord& r) {
        return r.uuid == uuid;
    });
}

