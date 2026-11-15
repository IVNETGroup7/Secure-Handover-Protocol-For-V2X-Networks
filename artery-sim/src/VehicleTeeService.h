#ifndef TEE_V2X_VEHICLETEESERVICE_H_
#define TEE_V2X_VEHICLETEESERVICE_H_

// A vehicle (OBU) running the repository's protocol stack (protocol/VehicleAgent) as an Artery ITS-G5
// service, over BTP port 2025:
//   1. "startDelay" after it enters the road, the secure bootstrap with "firstRsu" (Activation_Request ... Active_01)
//   2. once ready, a Secure_Data every "dataInterval" (10 Hz, as CAMs): a SmartData sealed with its K_g and K_dg
//      (OTP_dt), to the RSU it is activated with
//   3. CTRA Trajectory Prediction + Secrecy Forwarding: CtraPredictor continuously integrates the vehicle's
//      [x, y, v, psi, a, omega] state over "predictionHorizon" against all candidate RSUs in the network, selects
//      the single most likely next RSU, sends Handover_Predict to the current RSU so ONLY that candidate RSU is
//      notified via Forwarding_Notice, pre-fetches its Handover_Command (deriving tau_{i+2}, K_dh_i, KT_i, auth_{i+2}
//      in advance), and executes Forwarding_Request -> Forwarding_Granted upon entering "handoverRadius".

#include "CtraPredictor.h"
#include "ProtocolMsg.h"
#include "VehicleAgent.h"
#include "artery/application/ItsG5Service.h"
#include <map>
#include <memory>
#include <string>

class BackhaulBroker;

class VehicleTeeService : public artery::ItsG5Service
{
    public:
        ~VehicleTeeService() override;

    protected:
        void initialize() override;
        void handleMessage(omnetpp::cMessage*) override;
        void finish() override;
        void indicate(const vanetza::btp::DataIndication&, omnetpp::cPacket*, const artery::NetworkInterface&) override;

    private:
        void discoverRsus();
        void updateKinematics();
        void startBootstrap();
        void sendSecureData();
        void checkPrediction();     // CTRA trajectory prediction -> single-RSU Handover_Predict pre-fetch
        void checkHandover();       // executes pre-fetched Forwarding_Request once inside target RSU zone
        void sendRadio(const ProtocolMsg&);
        double positionX() const;

        std::string mName;                                  // "node[0]"
        std::unique_ptr<VehicleAgent> mAgent;
        BackhaulBroker* mBroker = nullptr;
        CtraPredictor mPredictor;
        omnetpp::cMessage* mStartTimer = nullptr;
        omnetpp::cMessage* mDataTimer = nullptr;
        bool mEnableCtra = true;
        double mPredictionHorizon = 8.0;
        double mPredictionStep = 0.1;
        double mPredictRadius = 80.0;
        double mHandoverRadius = 160.0;
        double mHandoverX = -1.0;
        bool mReady = false;
        std::string mPredictedRsu;
        omnetpp::simtime_t mStartedAt;
        omnetpp::simtime_t mPredictSentAt;
        omnetpp::simtime_t mPrefetchReadyAt;
        omnetpp::simtime_t mRequestSentAt;

        // statistics (results/*.sca, *.vec)
        long mSecureDataSent = 0;
        long mPredictionsSent = 0;
        long mPrefetchesCompleted = 0;
        long mHandovers = 0;
        std::map<std::string, long> mSentTo;                // RSU -> Secure_Data sent to it
        omnetpp::simsignal_t mBootstrapDelaySignal;
        omnetpp::simsignal_t mHandoverDelaySignal;
        omnetpp::simsignal_t mPrefetchLeadTimeSignal;
        omnetpp::simsignal_t mCtraPredictionSignal;
        omnetpp::simsignal_t mSecureDataSignal;
};

#endif /* TEE_V2X_VEHICLETEESERVICE_H_ */
