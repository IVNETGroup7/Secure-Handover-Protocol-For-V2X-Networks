#ifndef TA_GATEWAY_SESSION_H_
#define TA_GATEWAY_SESSION_H_

// Per-session Trusted Application state and command handlers inside the Arm TrustZone OP-TEE TA.
// Each RSU opens its own TEEC_Session, which allocates an isolated GatewayTaSession in Secure World memory.

#include "Crypto.h"
#include "Handover.h"
#include "MessageType.h"
#include "SmartData.h"
#include "Traits.h"
#include "codec.h"
#include "crypto_tee.h"
#include "gateway_ta.h"
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

class GatewayTaSession
{
    public:
        GatewayTaSession() = default;
        ~GatewayTaSession();

        // Configure OP-TEE Secure Storage object ID (and optionally delete existing state)
        void setStorageId(const std::string& storageId, bool deleteExisting);

        // Drain trace lines accumulated during the current command invocation
        std::string takeLogs();

        // TA Command Handlers (corresponding 1-to-1 with TaGatewayCommand in gateway_ta.h)
        int initIdentity(Bytes& outGatewayPubKey);
        int initGateway(const Bytes& caPubKey, const Bytes& gwCertDer, const Bytes& esaCertDer, const Bytes& groupKey);
        int initCloudSession(const std::string& cloudCertPem, const std::string& host, const std::string& gateway);
        int registerPeerRsu(const std::string& peerName, const Bytes& peerCertDer);
        int addActivationToken(const Bytes& encryptedToken, uint64_t currentPtpTime);
        int handleBootstrap(int msgType, const std::string& session, const Bytes& inPkt, uint64_t currentPtpTime,
            Bytes& outPkt, int& outType);
        int handleHandoverPredict(const Bytes& inPkt, uint64_t currentPtpTime, std::string& outTargetRsu,
            Bytes& outSealedNotice);
        int handleForwardingRequest(const std::string& session, const Bytes& inPkt, uint64_t currentPtpTime,
            Bytes& outPkt);
        int secureMarshalOtToIt(const Bytes& otPkt, uint64_t currentPtpTime, Bytes& outItPkt);
        int triggerHandover(const std::string& session, const std::string& targetRsu, uint64_t ti,
            Bytes& outSealedNotice);
        int receiveForwardingNotice(const std::string& senderRsu, const Bytes& sealedNotice, uint64_t currentPtpTime);

    private:
        struct PendingActivation
        {
            Bytes authD;
            uint64_t t0 = 0;
            uint64_t tf = 0;
            Bytes authEg;
        };

        struct PendingEcdh
        {
            Bytes kDg;
            Bytes yV;
            std::string peerLabel;  // Unauthenticated OT sender hint (routing/logging only, never trusted)
        };

        struct ActiveSession
        {
            std::string session;    // OT peer label bound on successful OTP match
            Bytes authD;
            Bytes authEg;
            uint64_t t0 = 0;
            uint64_t tf = 0;
            Bytes kDg;
            Bytes yV;
            uint64_t authTime = 0;  // Volatile t_i in TA RAM (never persisted to flash)
            bool confirmed = false; // true after Active_01 verified & relayed as Active_02
            uint32_t forwardingNoticesSent = 0;
        };

        struct PeerRsu
        {
            std::string name;
            Bytes publicKeyDer;
            Bytes kRsu;             // Mutually-authenticated RSU <-> RSU AES-256-GCM key
        };

        struct HandoverSession
        {
            std::string session;
            Bytes yv;
            Block tau{};
            HandoverKeys keys;
            Bytes authD;
            uint64_t createdAt = 0; // For TTL expiration
        };

        struct RateBucket
        {
            uint64_t windowStartNs = 0;
            uint32_t count = 0;
        };

        struct VehicleKeys
        {
            std::string session;
            Bytes kDg;
            Bytes kG;
        };

        struct CloudState
        {
            bool ready = false;
            Bytes cloudPublicKeyDer;
            std::string host;
            std::string gateway;
            Bytes kEg;
            std::string ys;
            int messages = 0;
            int number = 0;
        };

        void print(const std::string& text);
        void check(bool ok, const std::string& text);

        void saveState();
        bool loadState(bool keepGroupKey);
        void purgeExpiredActivations(uint64_t now);
        void purgeExpiredHandovers(uint64_t now);
        bool isCompromisedAuthD(const Bytes& authD) const;
        bool isActiveAuthD(const Bytes& authD) const;
        std::optional<VehicleKeys> findVehicleKeys(const Bytes& authD) const;
        std::vector<NeighborRsuKey> neighborRsuList() const;
        int sealForwardingNoticeForPeer(ActiveSession& active, const std::string& targetRsu, uint64_t slot,
            Bytes& outSealedNotice);
        void newCloudSession();

        // Protocol step handlers inside the TA
        Bytes ecdhResponse(const std::string& session, const Bytes& in);
        std::optional<Bytes> authGranted(const std::string& session, const Bytes& in, uint64_t now);
        std::optional<Bytes> active02(const std::string& session, const Bytes& in, uint64_t now);
        std::optional<Bytes> forwardingGranted(const std::string& session, const Bytes& in, uint64_t now);
        int marshal(const Bytes& otPacket, uint64_t now, Bytes& outItPkt);

        // Secrecy Forwarding equations inside the TA (using ta_crypto)
        static Block computeForwardingToken(const Bytes& kDg, uint64_t authSlot);
        static HandoverKeys computeHandoverKeys(const Bytes& kDh, const Block& tau);
        static Block computeForwardingOtp(const HandoverKeys& keys, uint64_t slot);
        static Block computeForwardingGrantedOtp(const HandoverKeys& keys, uint64_t slot,
            const wire::ForwardingGranted& m);

        bool mReady = false;
        std::string mStorageId = "gateway.sealed";
        ta_crypto::EcdhKeyPair mGatewayKey;         // X_gw / CY_g held strictly inside Secure World
        Bytes mCaPublicKey;                         // Pinned Root CA public key (DER SPKI)
        Bytes mGatewayCert;                         // Gateway's CA-signed X.509 certificate (DER)
        Bytes mEsaPublicKey;                        // Verified CY_e from ESA's CA-signed certificate
        Bytes mEsaSessionKey;                       // Mutually-authenticated K_esa (AES-256-GCM)
        Bytes mGroupKey;                            // K_G (AES-128-GCM)
        std::map<std::string, PeerRsu> mPeerRsus;   // CA-verified peer RSUs & K_rsu
        std::vector<PendingActivation> mPendingActivations; // Anonymous pending Activation_Tokens
        std::vector<PendingEcdh> mPendingEcdh;              // Unauthenticated ECDH secrets pool
        std::map<Bytes, ActiveSession> mActiveSessions;     // Auth_d -> active session
        std::set<Bytes> mCompromisedAuthD;                  // Expired (unactivated past t_f) Auth_d blocklist
        std::map<Sha256, HandoverSession> mHandovers;       // auth_{i+2} -> pending handover
        std::map<std::string, RateBucket> mForwardingRate;  // DoS rate-limiting on Forwarding_Request
        CloudState mCloud;
        std::set<size_t> mTracedSizes;
        std::string mLogs;
};

#endif /* TA_GATEWAY_SESSION_H_ */
