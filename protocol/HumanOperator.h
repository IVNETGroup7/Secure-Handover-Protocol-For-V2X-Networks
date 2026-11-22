#ifndef PROTOCOL_HUMANOPERATOR_H_
#define PROTOCOL_HUMANOPERATOR_H_

// Trusted Human Operator operating in the IT domain (Spec Section 1.1, Step 1 & Step 12).
// Possesses out-of-band knowledge of each device's (UUID_d, SHA256(fw_d)), initiates
// Activation_Request directly to the ESA over IT/HTTPS (never over OT radio), and receives
// Active_03 confirmation from the ESA upon device activation.

#include "Crypto.h"
#include "SimTime.h"
#include "Traits.h"
#include <functional>
#include <string>
#include <vector>

class ProtocolMsg;

class HumanOperator
{
    public:
        using HttpsTransport = std::function<void(const ProtocolMsg&)>;
        using ConfirmationCallback = std::function<void(const Uuid&, const Sha256&)>;

        explicit HumanOperator(std::string name = "operator");

        void setTransport(HttpsTransport transport) { mTransport = std::move(transport); }
        void setConfirmationCallback(ConfirmationCallback onConfirmed) { mOnConfirmed = std::move(onConfirmed); }

        // Step 1 (Operator -> ESA over IT/HTTPS):
        //   Activation_Request(CY_g, t_0, t_f, UUID_d, SHA256(fw_d))
        void requestActivation(const Bytes& gatewayPublicKey, simtime_t t0, simtime_t tf,
            const Uuid& uuid, const Sha256& firmwareHash);

        // Step 12 (ESA -> Operator over IT/HTTPS):
        //   Active_03(UUID_d, SHA256(fw_d))
        void handleMessage(const ProtocolMsg& msg);

        const std::string& name() const { return mName; }
        bool isConfirmed(const Uuid& uuid) const;
        int requestsSent() const { return mRequestsSent; }
        int confirmationsReceived() const { return mConfirmationsReceived; }

    private:
        struct DeviceRecord
        {
            Uuid uuid;
            Sha256 firmwareHash;
        };

        std::string mName;
        HttpsTransport mTransport;
        ConfirmationCallback mOnConfirmed;
        std::vector<DeviceRecord> mPending;
        std::vector<DeviceRecord> mConfirmed;
        int mRequestsSent = 0;
        int mConfirmationsReceived = 0;
};

#endif /* PROTOCOL_HUMANOPERATOR_H_ */

