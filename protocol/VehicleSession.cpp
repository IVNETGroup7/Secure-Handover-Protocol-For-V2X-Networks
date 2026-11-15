#include "VehicleSession.h"
#include "ProtocolMsg.h"
#include <cmath>
#include <stdexcept>

VehicleSession::VehicleSession(std::string name, unsigned seed, double initialClockOffset) :
    mName(std::move(name)),
    mRng(seed),
    mTraits(manufactureVehicle(mRng)),
    mClockOffset(initialClockOffset)
{
}

simtime_t VehicleSession::localClock() const
{
    return simTime() + mClockOffset;
}

uint64_t VehicleSession::otpSlot(simtime_t clock)
{
    return static_cast<uint64_t>(std::floor(clock.dbl() / kOtpTimeStep));
}

void VehicleSession::activateWithRsu(std::string rsu, Bytes kG, Bytes kDg, uint64_t authSlot)
{
    mCurrentRsu = std::move(rsu);
    mGroupKey = std::move(kG);
    mKdg = std::move(kDg);
    mLastAuthSlot = authSlot;
}

void VehicleSession::clearActiveKeys()
{
    mKdg.clear();
    mEcdhKey.reset();
}

void VehicleSession::send(int type, const std::string& destination, int seqNum, int ackNum,
    const std::string& vehicle, const Bytes& payload)
{
    if (!mTransport) {
        throw std::runtime_error(mName + ": no radio transport configured");
    }

    ProtocolMsg msg;
    msg.setType(type);
    msg.setSender(mName);
    msg.setDestination(destination);
    msg.setVehicle(!vehicle.empty() ? vehicle : mName);
    msg.setSeqNum(seqNum);
    msg.setAckNum(ackNum);
    setPayload(msg, payload);
    ++mSent;

    if (mOnBeforeSend) {
        mOnBeforeSend(type);
    }
    mTransport(msg);
}

