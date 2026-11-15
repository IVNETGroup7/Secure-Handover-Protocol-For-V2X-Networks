#ifndef TEE_V2X_VEHICLETEESERVICE_H_
#define TEE_V2X_VEHICLETEESERVICE_H_

// A vehicle (OBU) running the repository's protocol (protocol/BootstrapService, role vehicle) as an Artery ITS-G5
// service, over BTP port 2025:
//   1. "startDelay" after it enters the road, the secure bootstrap with "firstRsu" (Activation_Request ... Active_01)
//   2. once ready, a Secure_Data every "dataInterval" (10 Hz, as CAMs): a SmartData sealed with its K_g and K_dg
//      (OTP_dt), to the RSU it is activated with
//   3. Secrecy Forwarding: its RSU's Handover_Command names the next RSU; the Forwarding_Request goes once the
//      vehicle reaches x >= "handoverX" (or right away, handoverX < 0); after the Forwarding_Granted its
//      Secure_Data goes to the new RSU, with that RSU's K_g, with no new bootstrap
// Statistics: bootstrapDelay, handoverE2EDelayMs (Forwarding_Request sent -> Forwarding_Granted accepted),
// secureDataSent per RSU.

#include "BootstrapMsg.h"
#include "BootstrapService.h"
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
        void startBootstrap();
        void sendSecureData();
        void checkHandover();       // the held Forwarding_Request, once at handoverX
        void sendRadio(const BootstrapMsg&);
        double positionX() const;   // m, the scenario's x axis (the highway)

        std::string mName;                                  // "node[0]"
        std::unique_ptr<BootstrapService> mBootstrap;
        BackhaulBroker* mBroker = nullptr;
        omnetpp::cMessage* mStartTimer = nullptr;
        omnetpp::cMessage* mDataTimer = nullptr;
        double mHandoverX = 0;
        bool mReady = false;
        omnetpp::simtime_t mStartedAt;
        omnetpp::simtime_t mRequestSentAt;

        // statistics (results/*.sca, *.vec)
        long mSecureDataSent = 0;
        long mHandovers = 0;
        std::map<std::string, long> mSentTo;                // RSU -> Secure_Data sent to it
        omnetpp::simsignal_t mBootstrapDelaySignal;
        omnetpp::simsignal_t mHandoverDelaySignal;
        omnetpp::simsignal_t mSecureDataSignal;
};

#endif /* TEE_V2X_VEHICLETEESERVICE_H_ */
