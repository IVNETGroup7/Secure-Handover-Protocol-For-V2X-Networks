#ifndef TA_GATEWAY_SESSION_H_
#define TA_GATEWAY_SESSION_H_

// Per-session Trusted Application state and command handlers inside the Arm TrustZone OP-TEE TA.
// Each RSU opens its own TEEC_Session, which allocates an isolated GatewayTaSession in Secure World memory.

#include "BootstrapType.h"
#include "Crypto.h"
#include "Handover.h"
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
        int initGateway(const Bytes& gwCert, const Bytes& esaPubKey, const Bytes& groupKey);
        int initCloudSession(const std::string& cloudCertPem, const std::string& host, const std::string& gateway);
        int addActivationToken(const std::string& session, uint64_t t0, uint64_t tf, const Bytes& authD,
            const Bytes& authEg);
        int handleBootstrap(int msgType, const std::string& session, const Bytes& inPkt, uint64_t currentPtpTime,
            Bytes& outPkt, int& outType);
        int secureMarshalOtToIt(const Bytes& otPkt, uint64_t currentPtpTime, Bytes& outItPkt);
        int triggerHandover(const std::string& session, uint64_t ti, Block& outTau, Bytes& outYv, Bytes& outAuthD);
        int receiveForwardingNotice(const std::string& session, const Bytes& yv, const Block& tau, const Bytes& authD,
            Bytes& outYg);

    private:
        struct Activation
        {
            Bytes authD;
            uint64_t t0 = 0;
            uint64_t tf = 0;
            Bytes authEg;
        };

        struct HandoverSession
        {
            std::string session;
            Bytes yv;
            Block tau{};
            HandoverKeys keys;
            Bytes authD;
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
        bool withinWindow(const std::string& session, uint64_t now);
        std::optional<VehicleKeys> findVehicleKeys(const Bytes& authD) const;
        void newCloudSession();

        // Protocol step handlers inside the TA
        Bytes ecdhResponse(const std::string& session, const Bytes& in);
        std::optional<Bytes> authGranted(const std::string& session, const Bytes& in, uint64_t now);
        std::optional<Bytes> active02(const std::string& session, const Bytes& in);
        std::optional<Bytes> forwardingGranted(const std::string& session, const Bytes& in, uint64_t now);
        int marshal(const Bytes& otPacket, uint64_t now, Bytes& outItPkt);

        // Secrecy Forwarding equations inside the TA (using ta_crypto)
        static Block computeForwardingToken(const Bytes& kDg, uint64_t authSlot);
        static HandoverKeys computeHandoverKeys(const Bytes& kDh, const Block& tau);
        static Block computeForwardingOtp(const HandoverKeys& keys, uint64_t slot);

        bool mReady = false;
        std::string mStorageId = "gateway.sealed";
        Bytes mGatewayCert;
        Bytes mEsaPublicKey;
        Bytes mGroupKey;
        std::map<std::string, Activation> mPending;
        std::map<std::string, Activation> mActive;
        std::map<std::string, Bytes> mKdg;
        std::map<std::string, Bytes> mYv;
        std::map<std::string, uint64_t> mAuthTime;
        std::map<std::string, HandoverSession> mHandovers;
        CloudState mCloud;
        std::set<size_t> mTracedSizes;
        std::string mLogs;
};

#endif /* TA_GATEWAY_SESSION_H_ */

