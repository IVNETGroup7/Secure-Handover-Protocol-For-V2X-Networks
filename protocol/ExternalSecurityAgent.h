#ifndef BOOTSTRAP_EXTERNALSECURITYAGENT_H_
#define BOOTSTRAP_EXTERNALSECURITYAGENT_H_

#include "Crypto.h"
#include "Traits.h"
#include <functional>
#include <map>
#include <string>

class BootstrapMsg;

// ESA: talks to RSUs over HTTPS (ignores RSUs without a session); the Active_03 goes to the vehicle's user,
// over the HTTPS connection the user already has with the ESA
class ExternalSecurityAgent
{
    public:
        // how a reply leaves the ESA: HTTPS session of msg.getDestination() (e.g. a socket)
        using HttpsTransport = std::function<void(const BootstrapMsg&)>;

        explicit ExternalSecurityAgent(const std::string& name = "esa");
        void setTransport(HttpsTransport transport) { mTransport = std::move(transport); }

        // called once per RSU when its HTTPS session is established (pre-established session); "gatewayPublicKey":
        // CY_g, the key of the RSU's certificate, verified when the session was established (the paper's arrow 2:
        // the gateway and the ESA keep each other's certificate key, CY_g and CY_e)
        void registerRsu(const std::string& rsu, const std::string& sessionKey, const Bytes& gatewayPublicKey);

        // incoming message over HTTPS
        void handleMessage(const BootstrapMsg&);

        const std::string& getFullName() const { return mName; }
        const Bytes& publicKey() const { return mPublicKey; }  // CY_e: presented to each RSU with its HTTPS session
        int sent() const { return mSent; }
        int received() const { return mReceived; }

    private:
        // secure bootstrap protocol
        void activationToken(const BootstrapMsg& received);
        void active03(const BootstrapMsg& received);

        // sends over the HTTPS session of "rsu" (e.g. "rsu[0]")
        void sendToRsu(int type, const std::string& rsu, const std::string& vehicle, int seqNum, int ackNum,
            const Bytes& payload = {});
        // sends over the HTTPS connection of the vehicle's user (destination "user")
        void sendToUser(int type, const std::string& vehicle, int seqNum, int ackNum, const Bytes& payload = {});
        void send(int type, const std::string& destination, const std::string& vehicle, int seqNum, int ackNum,
            const Bytes& payload);
        void printDetail(const std::string& text) const;
        void printCheck(bool ok, const std::string& text) const;

        // an activation the ESA authorized (Activation_Request), until its Active_02
        struct Activation
        {
            Sha256 idD;                 // Id_d
            Uuid uuid;                  // UUID
            Sha256 firmwareHash;        // SHA256(f_w)
        };

        std::string mName;
        HttpsTransport mTransport;
        std::shared_ptr<EVP_PKEY> mKey;                         // ESA key pair (P-256)
        Bytes mPublicKey;                                       // CY_e: ESA public key (DER SubjectPublicKeyInfo)
        struct Gateway
        {
            std::string sessionKey;     // HTTPS session key
            Bytes publicKey;            // CY_g
        };
        std::map<std::string, Gateway> mGateways;               // RSU -> its HTTPS session
        std::map<Bytes, Activation> mActivations;               // Auth_d -> activation, kept when the token is issued:
                                                                // the Active_02 carries Auth_d, K_de needs Id_d
        std::map<std::string, Bytes> mKde;                      // K_de per vehicle (vehicle <-> ESA key)

        int mSent = 0;
        int mReceived = 0;
};

#endif /* BOOTSTRAP_EXTERNALSECURITYAGENT_H_ */
