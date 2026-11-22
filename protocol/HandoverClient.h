#ifndef PROTOCOL_HANDOVERCLIENT_H_
#define PROTOCOL_HANDOVERCLIENT_H_

// Vehicle-side RSU-to-RSU Secrecy Forwarding handover & selective CTRA pre-fetch client.
// Completely independent of the initial bootstrap / ESA flow:
//   pre-loaded Y_G_{i+2} -> encrypted Handover_Predict -> Forwarding_Request -> Forwarding_Granted.

#include "Crypto.h"
#include "Handover.h"
#include "VehicleSession.h"
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

class ProtocolMsg;

struct HandoverResult
{
    std::string vehicle;
    std::string rsu;    // the new target RSU (G_{i+2})
    Bytes kDg;          // K_dh_i promoted as K_dg with the new RSU
    Bytes kG;           // K_G_{i+2}: the new RSU's group key
    Bytes authD;
};

using HandoverCallback = std::function<void(const HandoverResult&)>;
using PrefetchCallback = std::function<void(const std::string& targetRsu)>;

class HandoverClient
{
    public:
        explicit HandoverClient(VehicleSession& session);

        void setPrefetchCallback(PrefetchCallback onPrefetch) { mOnPrefetchReady = std::move(onPrefetch); }
        void setHandoverCallback(HandoverCallback onHandover) { mOnHandoverCompleted = std::move(onHandover); }

        // CTRA predictor: pre-compute keys with targetRsu's pre-loaded Y_G and notify current RSU
        void requestPrediction(const std::string& targetRsu);
        // Re-send encrypted Handover_Predict if an OT/backhaul frame may have been lost
        void resendPrediction();
        // Send Forwarding_Request to the pre-computed target RSU
        void requestForwarding();

        void handleMessage(const ProtocolMsg& msg);

        bool pending() const { return mPending && !mPending->requested; }
        bool inFlight() const { return mPending && mPending->requested; }
        const std::string& targetRsu() const;

    private:
        void sendEncryptedPredict(const std::string& targetRsu);
        void onForwardingGranted(const ProtocolMsg& received);

        void printStep(const char* step, const ProtocolMsg* received = nullptr) const;
        void printDetail(const std::string& text) const;
        void printCheck(bool ok, const std::string& text) const;

        struct PendingHandover
        {
            std::string target;     // G_{i+2}
            HandoverKeys keys;      // K_dh_i, KT_i, KT_i^32, auth_{i+2}
            bool requested = false; // Forwarding_Request sent
            Block otp{};            // OTP echoed by Forwarding_Granted
            uint64_t slot = 0;      // t_c: becomes mLastAuthSlot on completion
        };

        VehicleSession& mSession;
        PrefetchCallback mOnPrefetchReady;
        HandoverCallback mOnHandoverCompleted;
        std::optional<PendingHandover> mPending;
};

#endif /* PROTOCOL_HANDOVERCLIENT_H_ */

