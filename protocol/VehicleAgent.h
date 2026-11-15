#ifndef PROTOCOL_VEHICLEAGENT_H_
#define PROTOCOL_VEHICLEAGENT_H_

// Top-level vehicle protocol stack composing the separated protocol phases:
//   - session():   VehicleSession (shared identity, clock, active RSU keys, transport)
//   - bootstrap(): BootstrapClient (initial authentication with first RSU + ESA)
//   - handover():  HandoverClient (CTRA predictive pre-fetch + Secrecy Forwarding handover)
//   - data():      SecureDataClient (authenticated OT SmartData transmission)

#include "BootstrapClient.h"
#include "HandoverClient.h"
#include "SecureDataClient.h"
#include "VehicleSession.h"
#include <string>

class ProtocolMsg;

class VehicleAgent
{
    public:
        struct Config
        {
            std::string name;               // e.g. "node[0]"
            bool autoStart = true;          // false = wait for bootstrap().start()
            double clockOffset = 0.0;       // s: initial clock skew before PTP correction
            Bytes gatewayPublicKey;         // CY_g of initial target RSU
            bool deferHandover = false;     // true = Handover_Command pre-fetches keys until requestForwarding()
            unsigned seed = 0;              // PRNG seed for UUID & keys
        };

        explicit VehicleAgent(const Config& config);

        void setTransport(VehicleSession::Transport transport);
        void indicate(const ProtocolMsg& msg);

        VehicleSession& session() { return mSession; }
        const VehicleSession& session() const { return mSession; }

        BootstrapClient& bootstrap() { return mBootstrap; }
        const BootstrapClient& bootstrap() const { return mBootstrap; }

        HandoverClient& handover() { return mHandover; }
        const HandoverClient& handover() const { return mHandover; }

        SecureDataClient& data() { return mData; }
        const SecureDataClient& data() const { return mData; }

    private:
        VehicleSession mSession;
        BootstrapClient mBootstrap;
        HandoverClient mHandover;
        SecureDataClient mData;
};

#endif /* PROTOCOL_VEHICLEAGENT_H_ */

