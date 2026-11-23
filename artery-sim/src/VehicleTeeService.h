#ifndef TEE_V2X_VEHICLETEESERVICE_H_
#define TEE_V2X_VEHICLETEESERVICE_H_

// A 5G NR connected vehicle (CrowNet ApplicationLayerVehicle = Simu5G NrNicUe + Artery VehicleMiddleware)
// running the repository's protocol stack (protocol/VehicleAgent) over 5G NR IPv4/UDP port 2025:
//   1. "startDelay" after entering the road, Phase A IT Activation_Request (Human Operator -> ESA -> firstRsu TEE)
//      followed by Phase B/C OT bootstrap over 5G NR (PTP, ECDH, Auth, Active_01)
//   2. once ready, a Secure_Data every "dataInterval" (10 Hz, as CAMs): SmartData sealed with K_g and K_dg (OTP_dt)
//   3. Purely kinematic CTRA Trajectory Prediction + Secrecy Forwarding: CtraPredictor integrates [x, y, v, psi, a, omega]
//      from Artery's MovingNodeDataProvider over "predictionHorizon" against all candidate RSUs, selects the single most
//      likely next RSU, sends encrypted Handover_Predict to the current RSU so ONLY that target RSU receives
//      E_{K_rsu}(Forwarding_Notice), and executes Forwarding_Request -> Forwarding_Granted at "handoverRadius".

#include <inet/common/InitStages.h>
#include <inet/networklayer/common/L3Address.h>
#include <inet/transportlayer/contract/udp/UdpSocket.h>
#include <omnetpp/clistener.h>
#include <omnetpp/csimplemodule.h>
#include "CtraPredictor.h"
#include "ProtocolMsg.h"
#include "VehicleAgent.h"
#include <map>
#include <memory>
#include <string>

class BackhaulBroker;

class VehicleTeeService : public omnetpp::cSimpleModule, public inet::UdpSocket::ICallback, public omnetpp::cListener
{
    public:
        ~VehicleTeeService() override;

    protected:
        int numInitStages() const override { return inet::NUM_INIT_STAGES; }
        void initialize(int stage) override;
        void handleMessage(omnetpp::cMessage*) override;
        void finish() override;
        void receiveSignal(omnetpp::cComponent* source, omnetpp::simsignal_t signalID, long value,
            omnetpp::cObject* details) override;

        // inet::UdpSocket::ICallback
        void socketDataArrived(inet::UdpSocket* socket, inet::Packet* packet) override;
        void socketErrorArrived(inet::UdpSocket* socket, inet::Indication* indication) override;
        void socketClosed(inet::UdpSocket* socket) override;

    private:
        void ensureDefaultCellularRoute();
        void subscribeNrServingCell();
        void unsubscribeNrServingCell();
        void discoverRsus();
        void updateKinematics();
        void onNrServingCellChanged(int cellId);
        void startBootstrap();
        void launchOtBootstrap();
        void sendSecureData();
        void checkPrediction();     // CTRA trajectory prediction -> single-RSU Handover_Predict pre-fetch
        void checkHandover();       // executes pre-fetched Forwarding_Request once inside target RSU zone
        void sendRadio(const ProtocolMsg&);
        inet::L3Address resolveRsuAddress(const std::string& rsuName);
        double positionX() const;

        std::string mName;                                  // "node[0]"
        int mLocalPort = 2025;
        int mDestPort = 2025;
        inet::UdpSocket mSocket;
        std::map<std::string, inet::L3Address> mRsuAddresses;
        std::unique_ptr<VehicleAgent> mAgent;
        BackhaulBroker* mBroker = nullptr;
        CtraPredictor mPredictor;
        omnetpp::cMessage* mStartTimer = nullptr;
        omnetpp::cMessage* mBootstrapLaunchTimer = nullptr;
        omnetpp::cMessage* mBootstrapTimeoutTimer = nullptr;
        omnetpp::cMessage* mDataTimer = nullptr;
        bool mEnableCtra = true;
        double mPredictionHorizon = 8.0;
        double mPredictionStep = 0.1;
        double mPredictRadius = 80.0;
        double mHandoverRadius = 160.0;
        bool mReady = false;
        std::string mPredictedRsu;
        int mLastNrServingCellId = 0;
        omnetpp::cModule* mNrPhyModule = nullptr;
        omnetpp::simsignal_t mServingCellSignal = SIMSIGNAL_NULL;
        omnetpp::simtime_t mStartedAt;
        omnetpp::simtime_t mPredictSentAt;
        omnetpp::simtime_t mPrefetchReadyAt;
        omnetpp::simtime_t mRequestSentAt;

        // statistics (results/*.sca, *.vec)
        long mSecureDataSent = 0;
        long mPredictionsSent = 0;
        long mPrefetchesCompleted = 0;
        long mHandovers = 0;
        long mNrRadioHandovers = 0;
        std::map<std::string, long> mSentTo;                // RSU -> Secure_Data sent to it
        omnetpp::simsignal_t mBootstrapDelaySignal;
        omnetpp::simsignal_t mHandoverDelaySignal;
        omnetpp::simsignal_t mPrefetchLeadTimeSignal;
        omnetpp::simsignal_t mCtraPredictionSignal;
        omnetpp::simsignal_t mSecureDataSignal;
        omnetpp::simsignal_t mNrServingCellSignal;
        omnetpp::simsignal_t mNrRadioHandoversSignal;
};

#endif /* TEE_V2X_VEHICLETEESERVICE_H_ */
