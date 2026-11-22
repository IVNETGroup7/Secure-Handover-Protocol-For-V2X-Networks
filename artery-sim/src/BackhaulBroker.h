#ifndef TEE_V2X_BACKHAULBROKER_H_
#define TEE_V2X_BACKHAULBROKER_H_

// The IT/wired domain of the scenario: hosts the Root CA, Human Operator, External Security Agent (ESA),
// Cloud sink, and pre-established mutually-authenticated HTTPS backhaul sessions between RSUs, ESA, and peers.
// Each backhaul message is delivered after "latency".

#include "Crypto.h"
#include "ExternalSecurityAgent.h"
#include "HumanOperator.h"
#include "ProtocolMsg.h"
#include "SimTime.h"
#include "SmartData.h"
#include "Traits.h"
#include <omnetpp/csimplemodule.h>
#include <functional>
#include <map>
#include <memory>
#include <string>

class BackhaulBroker : public omnetpp::cSimpleModule
{
    public:
        using RsuCallback = std::function<void(const ProtocolMsg&)>;
        using PeerCertCallback = std::function<void(const std::string& peerName, const Bytes& peerCertDer)>;

        struct RsuRegistration
        {
            Bytes caPublicKey;      // Root CA public key (DER SPKI) pinned in each RSU's TA
            Bytes gatewayCert;      // CA-signed X.509 certificate for this RSU's TEE-generated CY_g
            Bytes esaCert;          // CA-signed X.509 certificate for ESA's CY_e
        };

        BackhaulBroker();
        ~BackhaulBroker() override;

        // Step 2: CA issues X.509 certificate for RSU's TEE-generated CY_g, ESA verifies it against CA
        // and derives K_esa, and RSU receives { caPublicKey, gatewayCert, esaCert }. Also exchanges
        // CA-signed peer certificates among registered RSUs so each TA derives symmetric K_rsu keys.
        RsuRegistration registerRsu(const std::string& rsuName, const Bytes& gatewayPublicKey,
            RsuCallback onMessage, PeerCertCallback onPeerCert = nullptr);

        // Step 1 (IT Domain): Human Operator sends Activation_Request(CY_g, t_0, t_f, UUID_d, SHA256(fw_d))
        // directly to ESA over IT/HTTPS (NEVER over OT radio!).
        void requestActivation(const std::string& rsuName, simtime_t t0, simtime_t tf,
            const Uuid& uuid, const Sha256& firmwareHash);

        // CY_g of a registered RSU (throws if unknown)
        const Bytes& gatewayPublicKey(const std::string& rsuName) const;

        // Over the backhaul, to msg.getDestination(), "latency" later
        void sendBackhaul(const ProtocolMsg& msg);

        // Cloud CA-signed certificate (PEM), verified against Root CA inside each RSU's OP-TEE TA
        std::string cloudCertificate();
        // IT packet (HTTPS Header | AES(K_eg, JSON)) from an RSU's OP-TEE TA: opened with Cloud's key
        bool postToCloud(const std::string& rsuName, const Bytes& itPacket);

    protected:
        void handleMessage(omnetpp::cMessage*) override;
        void finish() override;

    private:
        CertificateAuthority& ca();
        ExternalSecurityAgent& esa();
        HumanOperator& humanOperator();
        CloudIdentity& cloud();
        void deliver(const ProtocolMsg& msg);

        std::unique_ptr<CertificateAuthority> mCa;
        std::unique_ptr<ExternalSecurityAgent> mEsa;
        std::unique_ptr<HumanOperator> mOperator;
        std::unique_ptr<CloudIdentity> mCloud;
        std::map<std::string, RsuCallback> mRsus;           // RSU -> what reaches it
        std::map<std::string, Bytes> mGatewayKeys;          // RSU -> CY_g
        std::map<std::string, Bytes> mGatewayCerts;         // RSU -> CA-signed DER X.509 certificate
        std::map<std::string, PeerCertCallback> mPeerCertCallbacks;

        // statistics (results/*.sca)
        long mDelivered = 0;
        long mUndeliverable = 0;
        long mCloudStored = 0;      // IT packets the cloud opened with its K_eg
        long mCloudRefused = 0;     // IT packets it could not open
        omnetpp::simsignal_t mCloudJsonSignal;
};

#endif /* TEE_V2X_BACKHAULBROKER_H_ */
