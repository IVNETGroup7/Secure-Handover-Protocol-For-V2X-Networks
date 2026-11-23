#ifndef HOST_TEE_SESSION_H_
#define HOST_TEE_SESSION_H_

// Normal World Client Application interface to the Arm TrustZone OP-TEE RSU Gateway TA.
//
// In OP-TEE mode (USE_OPTEE=1, physical Raspberry Pi 3 Cortex-A53 or QEMU ARMv8-A):
//   Uses the GlobalPlatform TEE Client API (<tee_client_api.h>, libteec):
//   TEEC_InitializeContext, TEEC_OpenSession, TEEC_InvokeCommand, TEEC_CloseSession, TEEC_FinalizeContext.
//
// In Host Simulation mode (default on x86_64 host PC for self-tests and Artery simulation):
//   Instantiates an isolated GatewayTaSession per TeeSession instance in-process,
//   executing the exact same TA session logic and command IDs without hardware /dev/tee0.

#include "Crypto.h"
#include "Otp.h"
#include "gateway_ta.h"
#include <cstdint>
#include <memory>
#include <string>

class TeeSession
{
    public:
        // Opens a new session with the RSU Gateway TA (TA_GATEWAY_UUID) and configures its Secure Storage ID & OTP algo
        explicit TeeSession(const std::string& storageId = "gateway.sealed", bool freshState = false,
            OtpAlgo otpAlgo = otpAlgorithm());
        ~TeeSession();

        TeeSession(const TeeSession&) = delete;
        TeeSession& operator=(const TeeSession&) = delete;

        uint64_t sessionId() const { return mSessionId; }
        const std::string& storageId() const { return mStorageId; }

        // TA Commands (TA_GATEWAY_CMD_*)
        int setStorageId(const std::string& storageId, bool deleteExisting = false,
            OtpAlgo otpAlgo = otpAlgorithm());
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
        struct Impl;
        std::unique_ptr<Impl> mImpl;
        uint64_t mSessionId = 0;
        std::string mStorageId;
};

#endif /* HOST_TEE_SESSION_H_ */

