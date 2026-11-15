#ifndef BOOTSTRAP_BOOTSTRAPSERVICE_H_
#define BOOTSTRAP_BOOTSTRAPSERVICE_H_

#include "Bootstrap.h"
#include "Handover.h"
#include "SimTime.h"
#include "SmartData.h"
#include "Traits.h"
#include <functional>
#include <map>
#include <optional>
#include <random>
#include <string>
#include <vector>
#include <openssl/ecdh.h>

class BootstrapMsg;

// Vehicle-side Secure Bootstrap and Secrecy Forwarding handover client.
// RSU logic runs inside Arm TrustZone (rsu-optee-gateway).
class BootstrapService
{
    public:
        struct Config
        {
            std::string name;               // node name, e.g. "node[0]"
            bool autoStart = true;          // false = wait for initBootstrap()
            double clockOffset = 0.0;       // s: initial error of the vehicle clock (PTP corrects it)
            Bytes gatewayPublicKey;         // CY_g, the certificate key of the target RSU
            bool deferHandover = false;     // a Handover_Command waits for requestForwarding()
                                            // (e.g. until the vehicle reaches the target RSU's area)
            unsigned seed = 0;              // RNG of the UUID / session key (reproducible)
        };

        using Transport = std::function<void(const BootstrapMsg&)>;

        explicit BootstrapService(const Config&);
        void setTransport(Transport transport) { mTransport = std::move(transport); }

        // incoming message over the radio (filtered by destination)
        void indicate(const BootstrapMsg&);

        // autoStart: starts the bootstrap when the vehicle enters the network
        void trigger();

        // starts the bootstrap (see initBootstrap)
        void start(BootstrapCallback onCompleted = nullptr);

        std::string myName() const;
        const Bytes& groupKey() const { return mGroupKey; }                        // K_g (after SaveVehicle)

        // Secrecy Forwarding (common/Handover.h) to the RSU a Handover_Command names
        // onHandover runs when a Forwarding_Granted is accepted (result.rsu: the new RSU)
        void setHandoverCallback(BootstrapCallback onHandover) { mOnHandoverCompleted = std::move(onHandover); }
        // a Handover_Command arrived and its Forwarding_Request was not sent yet (deferHandover)
        bool handoverPending() const { return mHandover && !mHandover->requested; }
        const std::string& handoverTarget() const;          // G_{i+2} of the last Handover_Command ("": none)
        void requestForwarding();                           // sends the Forwarding_Request to G_{i+2}
        const std::string& currentRsu() const { return mCurrentRsu; }   // the RSU I am activated with ("": none)

        // vehicle, once bootstrapped: one SmartData (common/SmartData.h) to the RSU I am activated with, as the OT
        // packet Message(AES(K_G, Data), Auth_d, OTP_dt) of a Secure_Data message; returns the Data sent
        SmartData sendSecureData(const Bytes& value, uint32_t location = 0, uint32_t metadata = 0);
        int sent() const { return mSent; }
        int received() const { return mReceived; }

    private:
        bool isForMe(const BootstrapMsg&) const;
        void dispatch(const BootstrapMsg&);

        // secure bootstrap protocol
        // "received" is the message that triggered the step
        void activationRequest();
        void PTPDelayRequest(const BootstrapMsg& received);
        void ECDHRequest(const BootstrapMsg& received);
        void AuthRequest(const BootstrapMsg& received);
        void SaveVehicle(const BootstrapMsg& received);
        void Active01(const BootstrapMsg& received);
        // Secrecy Forwarding: requestForwarding() sends the Forwarding_Request in between
        void HandoverCommand(const BootstrapMsg& received);
        void ForwardingGranted(const BootstrapMsg& received);

        void sendBootstrap(int type, const std::string& destination, int seqNum, int ackNum,
            const std::string& vehicle = "", const Bytes& payload = {});
        // output (Trace.h): a step, a line under it, a validation, a value kept (for "vehicle")
        void printStep(const char* step, const BootstrapMsg* received = nullptr);
        void printDetail(const std::string& text) const;
        void printCheck(bool ok, const std::string& text) const;
        void printKeep(const std::string& name, const Bytes& value, const std::string& vehicle) const;
        void notifyCompleted(const std::string& vehicle, const std::string& rsu);
        BootstrapResult result(const std::string& vehicle, const std::string& rsu);
        bool withinWindow(const std::string& vehicle);
        void correct_clock(simtime_t t1, simtime_t t2, simtime_t t3, simtime_t t4);
        simtime_t localClock() const;               // simTime() + mClockOffset

        std::string mName;
        Transport mTransport;
        std::mt19937 mRng;
        Bytes mGroupKey;                            // K_g: received from RSU
        Bytes mEsaPublicKey;                        // CY_e (DER SubjectPublicKeyInfo): received in Auth_Granted

        bool mAutoStart = true;
        bool mStarted = false;                      // trigger() may run many times: send Activation_Request once
        bool mDeferHandover = false;                // Config::deferHandover
        BootstrapCallback mOnCompleted;
        BootstrapCallback mOnHandoverCompleted;
        VehicleTraits mTraits;                      // manufacturing data (Traits.h)
        Bytes mGatewayPublicKey;                    // CY_g of the target RSU (Config::gatewayPublicKey)
        simtime_t mClockOffset;                     // error of the vehicle clock (see localClock)
        simtime_t mPtpT1;                           // PTP: Sync sent by the RSU (kept for correct_clock)
        simtime_t mPtpT2;                           // PTP: Sync received
        simtime_t mPtpT3;                           // PTP: Delay_Request sent
        std::shared_ptr<EVP_PKEY> mEcdhKey;         // ECDH: X_d = X_V (private) / Y_d = Y_V, kept after the bootstrap:
                                                    // K_dh_i = ECDH(X_V, Y_G_{i+2}) of every handover
        Block mOtpSent{};                           // OTP_dt sent in Auth_Request, checked in SaveVehicle
        uint64_t mOtpSlot = 0;                      // its t
        Bytes mAuthDe;                              // Auth_de (SaveVehicle), sent in Active_01
        Bytes mKde;                                 // K_de: vehicle <-> ESA key (SaveVehicle)
        std::string mCurrentRsu;                    // the RSU I am activated with (SaveVehicle, ForwardingGranted)
        uint64_t mLastAuthSlot = 0;                 // t_i: slot of the OTP that activated me with it (the OTP_dt
                                                    // the RSU echoed, or the last Forwarding_Request's): tau_{i+2}

        // Secrecy Forwarding in progress: from the Handover_Command to the Forwarding_Granted
        struct Handover
        {
            std::string target;                     // G_{i+2}
            HandoverKeys keys;                      // K_dh_i, KT_i, KT_i^32, auth_{i+2}
            bool requested = false;                 // Forwarding_Request sent
            Block otp{};                            // its OTP, echoed by the Forwarding_Granted
            uint64_t slot = 0;                      // its t_c
        };
        std::optional<Handover> mHandover;

        // activation window [t_0, t_f] per vehicle: from ECDH on, every step must happen inside it
        // (vehicle: its own entry; RSU: from the token)
        struct ActivationWindow
        {
            simtime_t t0;
            simtime_t tf;
        };
        std::map<std::string, ActivationWindow> mWindows;

        // K_dg per vehicle, kept after the bootstrap
        std::map<std::string, Bytes> mKdg;

        // statistics
        int mSent = 0;
        int mReceived = 0;
};

const char* stageName(int type);

#endif /* BOOTSTRAP_BOOTSTRAPSERVICE_H_ */
