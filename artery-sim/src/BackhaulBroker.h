#ifndef TEE_V2X_BACKHAULBROKER_H_
#define TEE_V2X_BACKHAULBROKER_H_

// The wired side of the scenario, one module: the pre-established HTTPS sessions of the RSUs with the ESA and with
// each other (Secrecy Forwarding), each message delivered after "latency". It also plays the ESA (the repository's
// protocol/ExternalSecurityAgent, as an object) and the cloud the RSUs' OP-TEE TAs marshal SmartData for (Fig. 5 of
// the paper: it opens each IT packet with its K_eg, as the cloud of ../main.cpp).
// Messages go by destination: "esa" to the ESA, an RSU's name (e.g. "rsu[1]") to the callback it registered.
// The ESA and the cloud are made on first use: the RSUs register in their own initialize(), which may run first.

#include "BootstrapMsg.h"
#include "ExternalSecurityAgent.h"
#include "Https.h"
#include <omnetpp/csimplemodule.h>
#include <functional>
#include <map>
#include <memory>
#include <string>

class BackhaulBroker : public omnetpp::cSimpleModule
{
    public:
        using RsuCallback = std::function<void(const BootstrapMsg&)>;
        using RadioCallback = std::function<void(const BootstrapMsg&)>;
        using PositionGetter = std::function<double()>;

        static constexpr short kBackhaulMsgKind = 1;
        static constexpr short k5gRadioMsgKind = 2;

        BackhaulBroker();
        ~BackhaulBroker() override;

        // an RSU's HTTPS session with the ESA (registerRsu of ExternalSecurityAgent): its certificate key CY_g and
        // "onMessage", which gets what reaches it over the backhaul; returns CY_e (the ESA's Session_Ack)
        Bytes registerRsu(const std::string& rsuName, const std::string& sessionKey, const Bytes& gatewayPublicKey,
            RsuCallback onMessage);
        // CY_g of a registered RSU: what the operator names in a vehicle's Activation_Request (throws if unknown)
        const Bytes& gatewayPublicKey(const std::string& rsuName) const;

        // over the backhaul, to msg.getDestination(), "latency" later
        void sendBackhaul(const BootstrapMsg& msg);

        // the cloud: its certificate (PEM), pinned by the OP-TEE TAs (TA_GATEWAY_CMD_INIT_CLOUD_SESSION)
        std::string cloudCertificate();
        // an IT packet (HTTPS Header | AES(K_eg, JSON)) the OP-TEE TA of "rsuName" made: opened with the cloud's key
        void postToCloud(const std::string& rsuName, const Bytes& itPacket);

        // Simu5G: 5G New Radio registration and transmission for the scenario
        void register5gNode(const std::string& name, RadioCallback onMessage, PositionGetter getX = nullptr);
        void send5gRadio(const std::string& sender, const BootstrapMsg& msg, double posX);

    protected:
        void handleMessage(omnetpp::cMessage*) override;
        void finish() override;

    private:
        struct Node5G {
            RadioCallback callback;
            PositionGetter getX;
        };

        ExternalSecurityAgent& esa();
        CloudIdentity& cloud();
        void deliver(const BootstrapMsg& msg);
        void deliver5gRadio(const BootstrapMsg& msg);

        std::unique_ptr<ExternalSecurityAgent> mEsa;
        std::unique_ptr<CloudIdentity> mCloud;
        std::map<std::string, RsuCallback> mRsus;           // RSU -> what reaches it
        std::map<std::string, Bytes> mGatewayKeys;          // RSU -> CY_g
        std::map<std::string, Node5G> m5gNodes;             // Node name -> 5G callback & position

        // statistics (results/*.sca)
        long mDelivered = 0;
        long mUndeliverable = 0;    // no such destination (e.g. Active_03: to the vehicle's user, not modeled)
        long mCloudStored = 0;      // IT packets the cloud opened with its K_eg
        long mCloudRefused = 0;     // IT packets it could not open
        long mNr5gTransmitted = 0;  // 5G NR packets transmitted over the air
        long mNr5gDropped = 0;      // 5G NR packets dropped (out of cell coverage or unreachable)
        omnetpp::simsignal_t mCloudJsonSignal;
};

#endif /* TEE_V2X_BACKHAULBROKER_H_ */
