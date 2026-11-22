#ifndef PACKET_MANAGER_H_
#define PACKET_MANAGER_H_

#include "BootstrapPayload.h"
#include "HandoverPayload.h"
#include "ProtocolMsg.h"
#include "benchmark.h"
#include "packet_queue.h"
#include "tee_session.h"
#include <functional>
#include <set>
#include <string>

// what a TA command invocation gave back: status (gateway_ta.h) and, for GW_OK, the packet to send and its MessageType
struct Reply
{
    int status;
    int type = -1;
    Bytes payload;
};

class PacketManager
{
    public:
        // how a message leaves the RSU (e.g. a socket)
        struct Transport
        {
            std::function<void(const ProtocolMsg&)> radio;      // to the vehicles
            std::function<void(const ProtocolMsg&)> https;      // to the ESA or another RSU (destination): the
                                                                // pre-established HTTPS sessions of the backhaul
            std::function<void(ItPacket)> cloud;                // marshaled SmartData, to the cloud (IT queue)
            std::function<void()> cloudRefused;                 // optional notification when TA refuses SmartData
        };

        PacketManager(TeeSession& tee, std::string name) : mTee(tee), mName(std::move(name)) {}
        void setTransport(Transport transport) { mTransport = std::move(transport); }
        void setClock(std::function<uint64_t()> clock) { mClock = std::move(clock); }
        const std::string& name() const { return mName; }

        // a packet of the OT queue: protocol message or SmartData, by its kind
        void onOtPacket(const OtPacket&);
        // incoming protocol messages: over the radio (filtered by destination) or over HTTPS (from the ESA:
        // encrypted Activation_Token; from another RSU: encrypted Forwarding_Notice)
        void onRadio(const ProtocolMsg&);
        void onHttps(const ProtocolMsg&);

        // the TA commands (gateway_ta.h)
        int initIdentity(Bytes& outGatewayPubKey);
        int initGateway(const Bytes& caPubKey, const Bytes& gatewayCert, const Bytes& esaCert,
            const Bytes& groupKey = {});
        // CA-signed neighbor RSU registration (derives symmetric K_rsu inside TA)
        int registerPeerRsu(const std::string& peerName, const Bytes& peerCertDer);
        // the HTTPS Session of the Secure Marshaling: CA-signed cloud certificate (PEM) verified inside TA
        int initCloudSession(const std::string& certificatePem, const std::string& host);
        int addActivationToken(const Bytes& encryptedToken, uint64_t ptpTimeNs);
        Reply handleBootstrap(int type, const std::string& session, const Bytes& payload, uint64_t ptpTimeNs);
        int handleHandoverPredict(const Bytes& payload, uint64_t ptpTimeNs, std::string& outTargetRsu,
            Bytes& outSealedNotice);
        Reply handleForwardingRequest(const std::string& session, const Bytes& payload, uint64_t ptpTimeNs);
        Reply marshal(const Bytes& otPacket, uint64_t ptpTimeNs);
        // Secrecy Forwarding (E_K_rsu sealed inside TA)
        int triggerHandover(const std::string& session, const std::string& targetRsu, uint64_t authSlot,
            Bytes& outSealedNotice);
        int receiveForwardingNotice(const std::string& senderRsu, const Bytes& sealedNotice, uint64_t ptpTimeNs);

        int ignored() const { return mIgnored; }    // messages the TA refused (a validation failed)
        Benchmark& benchmark() { return mBenchmark; }

    private:
        void onBootstrapStep(const char* step, const ProtocolMsg& received);
        void onHandoverPredict(const ProtocolMsg& received);
        void onForwardingRequest(const ProtocolMsg& received);
        void onSmartData(const OtPacket&);
        void activationToken(const ProtocolMsg& received);
        void forwardingNotice(const ProtocolMsg& received);
        // over the HTTPS sessions (the ESA, another RSU) or over the radio (the vehicles)
        enum class Via { Radio, Https };
        void send(int type, const std::string& destination, int seqNum, int ackNum, const std::string& vehicle,
            const Bytes& payload, Via via);
        uint64_t now() const;

        TeeSession& mTee;
        std::string mName;
        Transport mTransport;
        std::function<uint64_t()> mClock;
        int mIgnored = 0;
        Benchmark mBenchmark;
        std::set<size_t> mTracedSizes;      // SmartData: the first packet of each size is traced, the others counted
};

// "GW_OK", "GW_IGNORED"... (gateway_ta.h)
const char* statusName(int status);

#endif /* PACKET_MANAGER_H_ */

