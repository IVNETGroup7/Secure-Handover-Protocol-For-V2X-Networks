#ifndef TEE_V2X_BACKHAULBROKER_H_
#define TEE_V2X_BACKHAULBROKER_H_

// The IT/wired domain of the scenario: hosts the Root CA, Human Operator, External Security Agent (ESA),
// Cloud sink, pre-established mutually-authenticated HTTPS backhaul sessions between RSUs, ESA, and peers,
// and the V2X academic evaluation metrics collector + CSV exporter.

#include "Crypto.h"
#include "ExternalSecurityAgent.h"
#include "HumanOperator.h"
#include "MessageType.h"
#include "Otp.h"
#include "ProtocolMsg.h"
#include "SimTime.h"
#include "SmartData.h"
#include "Traits.h"
#include <omnetpp/csimplemodule.h>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

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

        // Active OTP/MAC algorithm for the whole scenario (ascon or poly1305, never mixed)
        OtpAlgo otpAlgo();
        bool quietTrace() const { return mQuietTrace; }

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

        // =====================================================================
        // Academic V2X & TEE Evaluation Instrumentation Hooks
        // =====================================================================
        void setHilMode(bool hil) { mHilMode = mHilMode || hil; }
        void recordVehicleTx(MessageType type, size_t wireBytes, int servingGnbId);
        void recordBootstrapTiming(double startSec, double readySec);
        void recordCtraPrediction(double tSec, const std::string& fromRsu, const std::string& predictedRsu,
            double currDistM, double minDistM, double ttcSec);
        void recordPrefetchReady(double tSec, const std::string& targetRsu, double rttMs);
        void recordHandoverRequest(double tSec, const std::string& fromRsu, const std::string& targetRsu,
            double distM);
        void recordHandoverComplete(double tSec, const std::string& fromRsu, const std::string& targetRsu,
            double e2eDelayMs, double leadTimeMs);
        void recordNrRadioHandover(double tSec, int fromGnb, int toGnb);
        void recordNrRadioSample(double sinrDlDb, double sinrUlDb, double cqiDl, double cqiUl);
        void recordRsuSecureDataRx(const std::string& rsuName, int64_t rsuRxNs, size_t wireBytes);
        void recordRsuMarshalRefused(const std::string& rsuName);
        void recordRsuTaWallUs(const std::string& rsuName, double wallUs);

    protected:
        void initialize() override;
        void handleMessage(omnetpp::cMessage*) override;
        void finish() override;

    private:
        struct RsuRxEntry
        {
            int64_t rxNs = 0;
            size_t wireBytes = 0;
        };

        struct PacketRecord
        {
            long seq = 0;
            double txTimeSec = 0.0;
            double rsuRxTimeSec = 0.0;
            double cloudRxTimeSec = 0.0;
            std::string rsu;
            int servingGnb = 0;
            size_t otBytes = 0;
            size_t itJsonBytes = 0;
            double nrUplinkMs = 0.0;
            double rsuTaMs = 0.0;
            double e2eLatencyMs = 0.0;
            double jitterMs = 0.0;
        };

        struct HandoverRecord
        {
            int id = 0;
            std::string fromRsu;
            std::string toRsu;
            double ctraPredictTimeSec = -1.0;
            bool ctraAccurate = false;
            double prefetchReadyTimeSec = -1.0;
            double nrX2HandoverTimeSec = -1.0;
            int nrFromGnb = 0;
            int nrToGnb = 0;
            double fwdReqTimeSec = -1.0;
            double fwdGrantedTimeSec = -1.0;
            double prefetchLeadTimeMs = -1.0;
            double handoverE2EDelayMs = -1.0;
            double interruptionTimeMs = -1.0;
            double handoverDistM = -1.0;
        };

        struct NrHandoverEvent
        {
            double timeSec = 0.0;
            int fromGnb = 0;
            int toGnb = 0;
            bool matched = false;
        };

        CertificateAuthority& ca();
        ExternalSecurityAgent& esa();
        HumanOperator& humanOperator();
        CloudIdentity& cloud();
        void deliver(const ProtocolMsg& msg);
        std::string resolveCsvPrefix() const;
        void exportMetricsAndReport();

        std::unique_ptr<CertificateAuthority> mCa;
        std::unique_ptr<ExternalSecurityAgent> mEsa;
        std::unique_ptr<HumanOperator> mOperator;
        std::unique_ptr<CloudIdentity> mCloud;
        std::optional<OtpAlgo> mOtpAlgo;
        bool mQuietTrace = false;
        bool mHilMode = false;
        std::map<std::string, RsuCallback> mRsus;           // RSU -> what reaches it
        std::map<std::string, Bytes> mGatewayKeys;          // RSU -> CY_g
        std::map<std::string, Bytes> mGatewayCerts;         // RSU -> CA-signed DER X.509 certificate
        std::map<std::string, PeerCertCallback> mPeerCertCallbacks;

        // Core counters (results/*.sca)
        long mDelivered = 0;
        long mUndeliverable = 0;
        long mCloudStored = 0;
        long mCloudRefused = 0;
        omnetpp::simsignal_t mCloudJsonSignal;

        // Academic V2X evaluation state
        long mSecureDataSent = 0;
        long mRsuSecureDataRx = 0;
        long mMarshalRefusedTotal = 0;
        long mControlPacketsSent = 0;
        size_t mControlBytesSent = 0;
        size_t mDataBytesSent = 0;
        size_t mCloudJsonBytesTotal = 0;
        int mCurrentServingGnb = 0;

        bool mBootstrapped = false;
        double mActivationReqSec = -1.0;
        double mOperatorConfirmSec = -1.0;
        double mBootstrapStartSec = -1.0;
        double mBootstrapReadySec = -1.0;
        double mFirstDataTxSec = -1.0;
        double mLastDataTxSec = -1.0;
        double mFirstCloudRxSec = -1.0;
        double mLastCloudRxSec = -1.0;

        long mCtraPredictionsSent = 0;
        long mCtraPredictionsAccurate = 0;
        long mHandoversAttempted = 0;
        long mHandoversCompleted = 0;

        std::map<std::string, std::deque<RsuRxEntry>> mRsuRxQueues;
        std::map<std::string, long> mCloudStoredPerRsu;
        std::map<std::string, long> mMarshalRefusedPerRsu;
        std::vector<double> mTaWallUs;
        std::vector<double> mSinrDlSamples;
        std::vector<double> mSinrUlSamples;
        std::vector<double> mCqiDlSamples;
        std::vector<double> mCqiUlSamples;

        std::string mLastCloudRsu;
        int64_t mLastCloudRxNs = -1;
        bool mHasPrevE2e = false;
        double mPrevE2eMs = 0.0;

        std::vector<PacketRecord> mPacketRecords;
        std::vector<HandoverRecord> mHandoverRecords;
        std::vector<NrHandoverEvent> mNrHandovers;

        // Pending CTRA prediction / handover state awaiting completion
        std::string mPendingPredFrom;
        std::string mPendingPredTarget;
        double mPendingPredTimeSec = -1.0;
        double mPendingPrefetchReadySec = -1.0;
        double mPendingFwdReqSec = -1.0;
        double mPendingHandoverDistM = -1.0;
};

#endif /* TEE_V2X_BACKHAULBROKER_H_ */
