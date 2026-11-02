#ifndef TEE_V2X_TEERSUSERVICE_H_
#define TEE_V2X_TEERSUSERVICE_H_

// An RSU whose secrets live in an Arm TrustZone OP-TEE Trusted Application (TA): the OP-TEE gateway of
// rsu-optee-gateway/ (its PacketManager and TeeSession) as an Artery ITS-G5 service. Each RSU opens its own
// TA session in this process (TeeSession: its own isolated TA session state, K_g and Secure Storage object),
// so RSUs share nothing but the backhaul.
//   radio (BTP port 2025, SHB, TC0)    bootstrap and Secrecy Forwarding messages -> PacketManager -> OP-TEE TA;
//                                      Secure_Data -> Secure Marshaling in the TA -> the cloud (BackhaulBroker)
//   backhaul (BackhaulBroker)          the ESA (Activation_Token) and the other RSUs (Forwarding_Notice,
//                                      Handover_Command)
// Only the Activation_Requests that name this RSU (their CY_g) are relayed to the ESA: every RSU in range hears
// them, and a second relay would start a second bootstrap.
// With "nextRsu" set, a vehicle activated here (Active_02 sent) is announced to that RSU right away (Secrecy
// Forwarding, common/Handover.h): it hands over to it with no new bootstrap when it gets there.

#include "BootstrapMsg.h"
#include "packet_manager.h"
#include "tee_session.h"
#include "artery/application/ItsG5Service.h"
#include <memory>
#include <string>

class BackhaulBroker;

class TeeRsuService : public artery::ItsG5Service
{
    public:
        ~TeeRsuService() override;

    protected:
        void initialize() override;
        void handleMessage(omnetpp::cMessage*) override;
        void finish() override;
        void indicate(const vanetza::btp::DataIndication&, omnetpp::cPacket*, const artery::NetworkInterface&) override;

    private:
        void sendRadio(const BootstrapMsg&);
        void sendHttps(const BootstrapMsg&);
        void onBackhaul(const BootstrapMsg&);
        void secureData(const BootstrapMsg&);

        std::string mName;                                  // "rsu[0]"
        Bytes mGatewayPublicKey;                            // CY_g: the key of my certificate
        std::unique_ptr<TeeSession> mTee;
        std::unique_ptr<PacketManager> mGateway;
        BackhaulBroker* mBroker = nullptr;
        std::string mNextRsu;                               // Secrecy Forwarding target ("": none)
        omnetpp::simtime_t mHandoverDelay;

        // statistics (results/*.sca, *.vec)
        long mMarshaled = 0;
        long mMarshalRefused = 0;
        long mHandoversTriggered = 0;
        long mHandoversGranted = 0;
        omnetpp::simsignal_t mMarshalLatencySignal;
        omnetpp::simsignal_t mHandoverGrantedSignal;
};

#endif /* TEE_V2X_TEERSUSERVICE_H_ */
