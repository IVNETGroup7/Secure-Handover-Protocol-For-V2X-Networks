#ifndef TEE_V2X_TEERSUSERVICE_H_
#define TEE_V2X_TEERSUSERVICE_H_

// A 5G NR Edge RSU Gateway whose secrets live in an Arm TrustZone OP-TEE Trusted Application (TA):
// the OP-TEE gateway of rsu-optee-gateway/ (PacketManager and TeeSession) running as an INET 4 UDP
// application (IApp) behind the 5G NR UPF/Router (co-located with gNB[i]). Each RSU opens its own
// isolated TA session (or bridges over AF_PACKET 0x88b5/0x88b6 to physical RPi3/VM OP-TEE TrustZone):
//   5G NR UDP (port 2025): bootstrap & Secrecy Forwarding -> PacketManager -> OP-TEE TA;
//                          Secure_Data -> Secure Marshaling in the TA -> Cloud (BackhaulBroker)
//   backhaul (BackhaulBroker): ESA (Activation_Token) and peer RSUs (E_{K_rsu}(Forwarding_Notice))

#include <inet/common/InitStages.h>
#include <inet/networklayer/common/L3Address.h>
#include <inet/transportlayer/contract/udp/UdpSocket.h>
#include <omnetpp/csimplemodule.h>
#include "ProtocolMsg.h"
#include "packet_manager.h"
#include "tee_session.h"
#include "RawSocket.h"
#include "Link.h"
#include <chrono>
#include <map>
#include <memory>
#include <string>

class BackhaulBroker;

class TeeRsuService : public omnetpp::cSimpleModule, public inet::UdpSocket::ICallback
{
    public:
        ~TeeRsuService() override;
        void syncHilPeers();

    protected:
        int numInitStages() const override { return inet::NUM_INIT_STAGES; }
        void initialize(int stage) override;
        void handleMessage(omnetpp::cMessage*) override;
        void finish() override;

        // inet::UdpSocket::ICallback
        void socketDataArrived(inet::UdpSocket* socket, inet::Packet* packet) override;
        void socketErrorArrived(inet::UdpSocket* socket, inet::Indication* indication) override;
        void socketClosed(inet::UdpSocket* socket) override;

    private:
        struct PeerEndpoint
        {
            inet::L3Address addr;
            int port = 2025;
        };

        void initHil();
        void initLocalTee();
        void sendRadio(const ProtocolMsg&);
        void sendHttps(const ProtocolMsg&);
        void onBackhaul(const ProtocolMsg&);
        void onRadioRx(const ProtocolMsg&, size_t wireBytes);
        void secureData(const ProtocolMsg&);
        void maybeSyncHilClock();
        void sendHilClockAnchor();
        void maybeSendHilCloudCert();
        void sendHilSessionAck();
        void pollHil();
        void shutdownHil();
        void flushLocalPendingPeers();

        int mLocalPort = 2025;
        int mVehiclePort = 2025;
        inet::UdpSocket mSocket;
        std::map<std::string, PeerEndpoint> mPeerEndpoints;

        bool mEnableHil = false;
        std::string mHilIface;
        std::unique_ptr<RawSocket> mHilRadio;
        std::unique_ptr<RawSocket> mHilBackhaul;
        Reassembler mHilBackhaulReassembler;
        omnetpp::cMessage* mHilPollMsg = nullptr;
        Bytes mCaPublicKey;
        Bytes mGatewayCert;
        Bytes mEsaCert;
        bool mHilCloudReady = false;
        bool mHilPeersSynced = false;
        std::map<std::string, Bytes> mPendingPeers;
        bool mLocalGatewayReady = false;
        omnetpp::simtime_t mLastCloudCertSent = -1;
        bool mHilClockSent = false;
        std::chrono::steady_clock::time_point mHilClockRefWall{};
        omnetpp::simtime_t mHilClockRefSim;
        std::unique_ptr<omnetpp::cISimulationLifecycleListener> mHilSyncListener;

        std::string mName;                                  // "rsu[0]"
        Bytes mGatewayPublicKey;                            // CY_g: the key of my certificate
        std::unique_ptr<TeeSession> mTee;
        std::unique_ptr<PacketManager> mGateway;
        BackhaulBroker* mBroker = nullptr;

        // statistics (results/*.sca, *.vec)
        long mMarshaled = 0;
        long mMarshalRefused = 0;
        long mHandoversTriggered = 0;
        long mHandoversGranted = 0;
        omnetpp::simsignal_t mMarshalLatencySignal;
        omnetpp::simsignal_t mHandoverGrantedSignal;
};

#endif /* TEE_V2X_TEERSUSERVICE_H_ */
