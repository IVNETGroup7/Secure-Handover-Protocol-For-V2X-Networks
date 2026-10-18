#ifndef BOOTSTRAP_BOOTSTRAPSERVICE_H_
#define BOOTSTRAP_BOOTSTRAPSERVICE_H_

#include "Bootstrap.h"
#include "SimTime.h"
#include "Traits.h"
#include <functional>
#include <map>
#include <random>
#include <string>
#include <vector>
#include <openssl/ecdh.h>

class BootstrapMsg;

// RSU: one activation the ESA authorized (Activation_Token), waiting for the vehicle's Auth_Request
struct PendingVehicles{
    Bytes authD;        // Auth_d

    simtime_t t0;       // t_0

    simtime_t tf;       // t_f

    Bytes authEg;       // Auth_eg
};

// Secure bootstrap between vehicle, RSU and ESA.
// Stateless and reactive: each message says who it is for (logical unicast) and its type
// says which step to run (see dispatch). Everything a step needs comes in the message.
// Applications use it through Bootstrap.h
class BootstrapService
{
    public:
        enum class Role { Vehicle, Rsu };

        struct Config
        {
            std::string name;               // node name, e.g. "node[0]" or "rsu[0]"
            Role role = Role::Vehicle;
            bool autoStart = true;          // vehicle only: false = wait for initBootstrap()
            double clockOffset = 0.0;       // s, vehicle only: initial error of the vehicle clock (PTP corrects it)
            std::string httpsSessionKey;    // RSU only: "" = random key
            Bytes groupKey;                 // RSU only: K_g (kGroupKeySize bytes), empty = random key
            unsigned seed = 0;              // RNG of the UUID / session key (reproducible)
        };

        // how a message leaves the node (e.g. a socket); set by whoever owns the node
        struct Transport
        {
            std::function<void(const BootstrapMsg&)> radio;     // vehicle <-> RSU: receivers filter by destination
            std::function<void(const BootstrapMsg&)> https;     // RSU -> ESA: pre-established HTTPS session
        };

        explicit BootstrapService(const Config&);
        void setTransport(Transport transport) { mTransport = std::move(transport); }

        // incoming messages: over the radio (filtered by destination) or over HTTPS (from the ESA)
        void indicate(const BootstrapMsg&);
        void handleHttps(const BootstrapMsg&);

        // autoStart: starts the bootstrap of a vehicle when it enters the network
        void trigger();

        // vehicle: starts the bootstrap (see initBootstrap)
        void start(BootstrapCallback onCompleted = nullptr);

        std::string myName() const;
        const std::string& httpsSessionKey() const { return mHttpsSessionKey; }   // RSU only
        const Bytes& groupKey() const { return mGroupKey; }                        // K_g (vehicle: after SaveVehicle)

        // RSU only: CY_e, the ESA public key, received when the HTTPS session is established
        void setEsaPublicKey(const Bytes& der) { mEsaPublicKey = der; }
        int sent() const { return mSent; }
        int received() const { return mReceived; }

    private:
        bool isForMe(const BootstrapMsg&) const;
        void dispatch(const BootstrapMsg&);

        // secure bootstrap protocol
        // "received" is the message that triggered the step
        void activationRequest();
        void HTTPSEstablishment(const BootstrapMsg& received);
        void PTP(const BootstrapMsg& received);
        void PTPSync(const BootstrapMsg& received);
        void PTPDelayRequest(const BootstrapMsg& received);
        void PTPDelayResponse(const BootstrapMsg& received);
        void ECDHRequest(const BootstrapMsg& received);
        void ECDHResponse(const BootstrapMsg& received);
        void AuthRequest(const BootstrapMsg& received);
        void SaveRSU(const BootstrapMsg& received);
        void AuthGranted(const BootstrapMsg& received);
        void SaveVehicle(const BootstrapMsg& received);
        void Active01(const BootstrapMsg& received);
        void Active02(const BootstrapMsg& received);
        void HandoverCommand(const BootstrapMsg& received);
        void ForwardingGranted(const BootstrapMsg& received);
        // activationToken() and active03() live in ExternalSecurityAgent

        // destination "esa" goes over HTTPS, anything else over the radio
        // empty vehicle: me (vehicle) or destination (RSU)
        void sendBootstrap(int type, const std::string& destination, int seqNum, int ackNum,
            const std::string& vehicle = "", const Bytes& payload = {});
        // output (Trace.h): a step, a line under it, a validation, a value kept (for "vehicle")
        void printStep(const char* step, const BootstrapMsg* received = nullptr);
        void printDetail(const std::string& text) const;
        void printCheck(bool ok, const std::string& text) const;
        void printKeep(const std::string& name, const Bytes& value, const std::string& vehicle) const;
        void notifyCompleted(const std::string& vehicle, const std::string& rsu);
        void stampTransmission(BootstrapMsg&);
        bool withinDeadline(const std::string& vehicle);
        void correct_clock(simtime_t t1, simtime_t t2, simtime_t t3, simtime_t t4);
        simtime_t localClock() const;               // vehicle: simTime() + mClockOffset; RSU: simTime() (PTP master)

        std::string mName;
        Role mRole;
        Transport mTransport;
        std::mt19937 mRng;
        std::string mHttpsSessionKey;               // RSU only: HTTPS session key
        Bytes mGroupKey;                            // K_g: RSU, handed to every vehicle it activates; vehicle, received
        Bytes mEsaPublicKey;                        // CY_e (DER SubjectPublicKeyInfo): RSU, from the ESA; vehicle, received

        // vehicle only (not protocol state: the flow is driven by the messages)
        bool mAutoStart = true;
        bool mStarted = false;                      // trigger() may run many times: send Activation_Request once
        BootstrapCallback mOnCompleted;
        VehicleTraits mTraits;                      // manufacturing data (Traits.h)
        simtime_t mClockOffset;                     // error of the vehicle clock (see localClock)
        simtime_t mPtpT1;                           // PTP: Sync sent by the RSU (kept for correct_clock)
        simtime_t mPtpT2;                           // PTP: Sync received
        simtime_t mPtpT3;                           // PTP: Delay_Request sent
        std::shared_ptr<EVP_PKEY> mEcdhKey;         // ECDH: X_d (private) / Y_d, kept until ECDH_Response
        Block mOtpSent{};                           // OTP_dt sent in Auth_Request, checked in SaveVehicle
        Bytes mAuthDe;                              // Auth_de (SaveVehicle), sent in Active_01
        Bytes mKde;                                 // K_de: vehicle <-> ESA key (SaveVehicle)
        uint64_t mTi = 0;                           // timestamp of Handover / Forwarding Notice
        Bytes mKt;                                  // handover transient key KT_i

        // t_f per vehicle: after PTP the protocol must end before it (vehicle: its own entry; RSU: from the token)
        std::map<std::string, simtime_t> mDeadlines;

        // K_dg per vehicle, kept after the bootstrap (vehicle: its own entry; RSU: one per vehicle)
        std::map<std::string, Bytes> mKdg;

        // RSU only: activations from the Activation_Token waiting for an OTP (SaveRSU searches all of them),
        // and the ones an OTP matched (status active), indexed by the session (vehicle) they were bound to
        std::map<std::string, PendingVehicles> mPending;
        std::map<std::string, PendingVehicles> mActive;

        // statistics
        int mSent = 0;
        int mReceived = 0;
};

const char* stageName(int type);

#endif /* BOOTSTRAP_BOOTSTRAPSERVICE_H_ */
