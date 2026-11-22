#ifndef PROTOCOL_EXTERNALSECURITYAGENT_H_
#define PROTOCOL_EXTERNALSECURITYAGENT_H_

#include "Crypto.h"
#include "Traits.h"
#include <functional>
#include <map>
#include <optional>
#include <string>

class ProtocolMsg;

// External Security Agent (ESA): resides in the IT domain.
//   - Authenticates Gateways using CA-signed X.509 certificates and derives a mutually
//     authenticated per-gateway AES-256-GCM HTTPS channel key K_esa (terminated in each RSU's TEE).
//   - Accepts Step 1 Activation_Request strictly from the IT Human Operator ("operator"), never from OT/RSU.
//   - Sends Step 3 Activation_Token encrypted under K_esa so Gateway REE never sees Auth_d or Auth_eg.
//   - Decrypts Step 11 Active_02 under K_esa, verifies Auth_d/Auth_de, derives K_de, and sends Step 12 Active_03
//     to the Human Operator ("operator").
class ExternalSecurityAgent
{
    public:
        // How a reply leaves the ESA: IT/HTTPS transport to msg.getDestination()
        using HttpsTransport = std::function<void(const ProtocolMsg&)>;

        explicit ExternalSecurityAgent(const CertificateAuthority& ca, const std::string& name = "esa");
        void setTransport(HttpsTransport transport) { mTransport = std::move(transport); }

        // Step 2: verify Gateway's CA-signed X.509 certificate, pin CY_g, and derive mutually-authenticated K_esa.
        // Returns false if gatewayCertDer is not signed by the trusted CA.
        bool registerRsu(const std::string& rsu, const Bytes& gatewayCertDer);

        // Incoming IT message (Activation_Request from "operator", Active_02 from a registered RSU)
        void handleMessage(const ProtocolMsg&);

        const std::string& getFullName() const { return mName; }
        const Bytes& publicKey() const { return mPublicKey; }       // CY_e (DER SPKI)
        const Bytes& certificate() const { return mCertificate; }   // ESA CA-signed X.509 certificate (DER)
        const Bytes& caPublicKey() const { return mCaPublicKey; }   // Root CA public key (DER SPKI)
        std::optional<Bytes> deviceKey(const Bytes& authD) const;   // K_de derived for an activated device
        int sent() const { return mSent; }
        int received() const { return mReceived; }

    private:
        void activationToken(const ProtocolMsg& received);
        void active03(const ProtocolMsg& received);

        void sendToRsu(int type, const std::string& rsu, int seqNum, int ackNum, const Bytes& payload = {});
        void sendToOperator(int type, int seqNum, int ackNum, const Bytes& payload = {});
        void send(int type, const std::string& destination, int seqNum, int ackNum, const Bytes& payload);
        void printDetail(const std::string& text) const;
        void printCheck(bool ok, const std::string& text) const;

        // Pending activation authorized by the Human Operator until Active_02 completes
        struct Activation
        {
            Sha256 idD;                 // Id_d
            Uuid uuid;                  // UUID_d
            Sha256 firmwareHash;        // SHA256(fw_d)
            std::string rsu;            // Authorized target gateway
        };

        struct Gateway
        {
            Bytes publicKey;            // CY_g (verified from CA-signed certificate)
            Bytes sessionKey;           // K_esa = SHA256(ECDH(X_e, CY_g) || CY_g || CY_e)
        };

        std::string mName;
        HttpsTransport mTransport;
        std::shared_ptr<EVP_PKEY> mKey;             // ESA P-256 keypair (X_e, CY_e)
        Bytes mPublicKey;                           // CY_e (DER SPKI)
        Bytes mCertificate;                         // ESA CA-signed X.509 DER certificate
        Bytes mCaPublicKey;                         // Pinned Root CA public key (DER SPKI)
        std::map<std::string, Gateway> mGateways;   // RSU -> verified CA identity & K_esa
        std::map<Bytes, Activation> mActivations;   // Auth_d -> pending activation
        std::map<Bytes, Bytes> mKde;                // Auth_d -> K_de (Device <-> ESA key)

        int mSent = 0;
        int mReceived = 0;
};

#endif /* PROTOCOL_EXTERNALSECURITYAGENT_H_ */
