#ifndef PROTOCOL_VEHICLESESSION_H_
#define PROTOCOL_VEHICLESESSION_H_

// Shared per-vehicle security context, active RSU association, PTP-adjusted clock, and radio transport.
// Used across distinct protocol phases (BootstrapClient, HandoverClient, SecureDataClient) without
// embedding any phase-specific state machine.

#include "Crypto.h"
#include "SimTime.h"
#include "Traits.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <openssl/evp.h>

class ProtocolMsg;

class VehicleSession
{
    public:
        using Transport = std::function<void(const ProtocolMsg&)>;

        VehicleSession(std::string name, unsigned seed, double initialClockOffset = 0.0);

        void setTransport(Transport transport) { mTransport = std::move(transport); }
        void send(int type, const std::string& destination, int seqNum, int ackNum,
            const std::string& vehicle = "", const Bytes& payload = {});
        void recordReceived() { ++mReceived; }

        const std::string& name() const { return mName; }
        const VehicleTraits& traits() const { return mTraits; }

        // Synchronized local clock (simulation/wall clock + PTP offset)
        simtime_t localClock() const;
        void adjustClock(simtime_t offsetDelta) { mClockOffset -= offsetDelta; }

        // Ephemeral ECDH keypair (X_V, Y_V) established at bootstrap and retained for Secrecy Forwarding handovers
        EVP_PKEY* ecdhKey() const { return mEcdhKey.get(); }
        void setEcdhKey(std::shared_ptr<EVP_PKEY> key) { mEcdhKey = std::move(key); }
        void clearEcdhKey() { mEcdhKey.reset(); }

        // Active RSU association (set on initial bootstrap SaveVehicle and updated on handover ForwardingGranted)
        bool isActivated() const { return !mCurrentRsu.empty() && !mKdg.empty(); }
        const std::string& currentRsu() const { return mCurrentRsu; }
        const Bytes& groupKey() const { return mGroupKey; }
        const Bytes& kDg() const { return mKdg; }
        uint64_t lastAuthSlot() const { return mLastAuthSlot; }

        void activateWithRsu(std::string rsu, Bytes kG, Bytes kDg, uint64_t authSlot);
        void clearActiveKeys();

        // Optional callback invoked before a PTP_Delay_Request leaves over the air
        void setOnBeforeSend(std::function<void(int)> hook) { mOnBeforeSend = std::move(hook); }

        int sent() const { return mSent; }
        int received() const { return mReceived; }

        static uint64_t otpSlot(simtime_t clock);

    private:
        std::string mName;
        std::mt19937 mRng;
        VehicleTraits mTraits;
        Transport mTransport;
        std::function<void(int)> mOnBeforeSend;

        simtime_t mClockOffset;
        std::shared_ptr<EVP_PKEY> mEcdhKey;
        std::string mCurrentRsu;
        Bytes mGroupKey;
        Bytes mKdg;
        uint64_t mLastAuthSlot = 0;

        int mSent = 0;
        int mReceived = 0;
};

#endif /* PROTOCOL_VEHICLESESSION_H_ */

