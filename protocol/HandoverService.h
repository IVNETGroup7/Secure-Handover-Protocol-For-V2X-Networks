#ifndef PROTOCOL_HANDOVERSERVICE_H_
#define PROTOCOL_HANDOVERSERVICE_H_

#include "Bootstrap.h"
#include "BootstrapMsg.h"
#include "BootstrapPayload.h"
#include "SimTime.h"
#include "Traits.h"
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

// Result of a successful handover / secrecy forwarding
struct HandoverResult
{
    std::string vehicle;
    std::string sourceRsu;
    std::string targetRsu;
    Bytes newKdg;       // KT_i: forward-secret transient key established for this RSU
    Bytes newKg;        // K_g: group key of the target RSU
};

using HandoverCallback = std::function<void(const HandoverResult&)>;

// Handover & Secrecy Forwarding Service:
// Completely decoupled from initial bootstrap. Manages the mobility phase:
// Forwarding_Notice, Handover_Command, Forwarding_Request, Forwarding_Granted.
class HandoverService
{
    public:
        enum class Role { Vehicle, Rsu };

        struct Config
        {
            std::string name;                   // Node name ("node[0]", "rsu[0]")
            Role role = Role::Vehicle;
            Bytes groupKey;                     // RSU group key (K_g)
        };

        struct Transport
        {
            std::function<void(const BootstrapMsg&)> radio;     // Wireless channel
            std::function<void(const BootstrapMsg&)> https;     // Inter-RSU backhaul
        };

        explicit HandoverService(const Config& config);

        void setTransport(const Transport& transport) { mTransport = transport; }
        void onCompleted(HandoverCallback cb) { mOnCompleted = cb; }

        // --- Vehicle API ---
        // Initialize vehicle with security context established during bootstrap
        void initVehicle(const BootstrapResult& context);

        // --- RSU API ---
        // Register an active vehicle session established after bootstrap
        void registerVehicle(const std::string& vehicle, const Bytes& kDg, const Bytes& yV);
        // Trigger handover of an active vehicle to a target RSU
        void triggerHandover(const std::string& vehicle, const std::string& nextRsu, const Bytes& nextRsuPublicKey = {});

        // --- Network Event Dispatchers ---
        void indicate(const BootstrapMsg& msg);    // Incoming wireless frame
        void handleHttps(const BootstrapMsg& msg); // Incoming backhaul frame

        std::string myName() const { return mName; }
        const Bytes& kDg(const std::string& vehicle = "") const;
        const Bytes& groupKey() const { return mGroupKey; }

    private:
        bool isForMe(const BootstrapMsg& msg) const;
        void dispatch(const BootstrapMsg& msg);

        // Protocol message handlers
        void handleHandoverCommand(const BootstrapMsg& received);
        void handleForwardingNotice(const BootstrapMsg& received);
        void handleForwardingRequest(const BootstrapMsg& received);
        void handleForwardingGranted(const BootstrapMsg& received);

        void sendBootstrap(int type, const std::string& destination, int seqNum, int ackNum,
            const std::string& vehicle = "", const Bytes& payload = {});

        void printStep(const char* step, const BootstrapMsg* received = nullptr);
        void printDetail(const std::string& text) const;
        void printCheck(bool ok, const std::string& text) const;
        void printKeep(const std::string& name, const Bytes& value, const std::string& vehicle, bool echo = true) const;
        void notifyCompleted(const std::string& vehicle, const std::string& targetRsu);

        std::string mName;
        Role mRole;
        Transport mTransport;
        HandoverCallback mOnCompleted;

        // Vehicle security state
        std::string mCurrentRsu;
        Bytes mKdg;                                 // Active master secret K_dg
        Bytes mGroupKey;                            // Current K_G
        std::shared_ptr<EVP_PKEY> mEcdhKey;         // Vehicle EC keypair (X_V, Y_V)
        Bytes mAuthD;                               // Vehicle token Auth_d
        uint64_t mTi = 0;                           // Handover timestamp
        Bytes mKt;                                  // Transient key KT_i

        // RSU security state
        struct VehicleSession
        {
            std::string id;
            Bytes kDg;
            Bytes yV;
        };
        std::map<std::string, VehicleSession> mSessions;

        struct HandoverTicket
        {
            Sha256 auth;
            Bytes vehiclePublicKey;
            std::string pseudonym;
            Bytes kG;
            Bytes kt;
            simtime_t expiry = 0;
        };
        std::map<Sha256, HandoverTicket> mTickets;

        int mSent = 0;
        int mReceived = 0;
};

#endif /* PROTOCOL_HANDOVERSERVICE_H_ */
