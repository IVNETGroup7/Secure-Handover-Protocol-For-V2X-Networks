#include "VehicleSession.h"
#include "ProtocolMsg.h"
#include <algorithm>
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

Block VehicleSession::otpNonce(const Bytes& authD, uint64_t t)
{
    Block nonce{};
    if (authD.size() < nonce.size()) {
        throw std::runtime_error("OTP: Auth_d shorter than one block");
    }
    std::copy_n(authD.begin(), nonce.size(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[15 - i] ^= static_cast<uint8_t>(t >> (8 * i));
    }
    return nonce;
}

void VehicleSession::activateWithRsu(std::string rsu, Bytes kG, Bytes kDg, uint64_t authSlot)
{
    mCurrentRsu = std::move(rsu);
    mGroupKey = std::move(kG);
    mKdg = std::move(kDg);
    mLastAuthSlot = authSlot;
}

void VehicleSession::setNeighborRsus(const std::vector<NeighborRsuKey>& neighbors)
{
    mNeighborRsus.clear();
    for (const NeighborRsuKey& nb : neighbors) {
        if (!nb.name.empty() && !nb.publicKeyDer.empty()) {
            mNeighborRsus[nb.name] = nb.publicKeyDer;
        }
    }
}

std::optional<Bytes> VehicleSession::neighborKey(const std::string& rsuName) const
{
    const auto it = mNeighborRsus.find(rsuName);
    if (it == mNeighborRsus.end()) {
        return std::nullopt;
    }
    return it->second;
}

void VehicleSession::clearActiveKeys()
{
    mKdg.clear();
    mNeighborRsus.clear();
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

