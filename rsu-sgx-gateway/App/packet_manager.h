#ifndef PACKET_MANAGER_H_
#define PACKET_MANAGER_H_

#include "BootstrapMsg.h"
#include "BootstrapPayload.h"
#include "benchmark.h"
#include "packet_queue.h"
#include <sgx_eid.h>
#include <functional>
#include <set>
#include <string>

// what an ECALL gave back: status (gateway.h) and, for GW_OK, the packet to send and its BootstrapType
struct Reply
{
    int status;
    int type = -1;
    Bytes payload;
};

class PacketManager
{
    public:
        // how a message leaves the RSU (e.g. a socket), as BootstrapService::Transport
        struct Transport
        {
            std::function<void(const BootstrapMsg&)> radio;     // to the vehicles
            std::function<void(const BootstrapMsg&)> https;     // to the ESA or another RSU (destination): the
                                                                // pre-established HTTPS sessions of the backhaul
            std::function<void(ItPacket)> cloud;                // marshaled SmartData, to the cloud (IT queue)
        };

        PacketManager(sgx_enclave_id_t eid, std::string name) : mEid(eid), mName(std::move(name)) {}
        void setTransport(Transport transport) { mTransport = std::move(transport); }
        const std::string& name() const { return mName; }

        // a packet of the OT queue: bootstrap message or SmartData, by its kind
        void onOtPacket(const OtPacket&);
        // incoming bootstrap messages: over the radio (filtered by destination) or over HTTPS (from the ESA:
        // Activation_Token; from another RSU: Forwarding_Notice, Handover_Command)
        void onRadio(const BootstrapMsg&);
        void onHttps(const BootstrapMsg&);

        // Secrecy Forwarding, source RSU: the Forwarding_Notice of an activated "session" to "targetRsu";
        // false: the enclave refused it (no such active session)
        bool startHandover(const std::string& session, const std::string& targetRsu);

        // the ECALLs (Enclave.edl)
        int initGateway(const Bytes& gatewayCert, const Bytes& esaPublicKey, const Bytes& groupKey = {});
        // the HTTPS Session of the Secure Marshaling: the cloud's certificate (PEM) into the enclave
        int initCloudSession(const std::string& certificatePem, const std::string& host);
        int addActivationToken(const std::string& session, uint64_t t0, uint64_t tf, const Bytes& authD,
            const Bytes& authEg);
        Reply handleBootstrap(int type, const std::string& session, const Bytes& payload, uint64_t ptpTimeNs);
        Reply marshal(const Bytes& otPacket, uint64_t ptpTimeNs);
        // Secrecy Forwarding: the source's Forwarding_Notice (authSlot: t_i, 0 = the enclave's own) and the target's
        // answer to it (GW_OK: payload = Y_G_{i+2})
        int triggerHandover(const std::string& session, uint64_t authSlot, ForwardingNoticePayload& notice);
        Reply receiveForwardingNotice(const std::string& session, const ForwardingNoticePayload& notice);

        int ignored() const { return mIgnored; }    // messages the enclave refused (a validation failed)
        Benchmark& benchmark() { return mBenchmark; }

    private:
        void enclaveStep(const char* step, const BootstrapMsg& received);
        void onSmartData(const OtPacket&);
        void activationToken(const BootstrapMsg& received);
        void forwardingNotice(const BootstrapMsg& received);
        // over the HTTPS sessions (the ESA, another RSU) or over the radio (the vehicles)
        enum class Via { Radio, Https };
        void send(int type, const std::string& destination, int seqNum, int ackNum, const std::string& vehicle,
            const Bytes& payload, Via via);

        sgx_enclave_id_t mEid;
        std::string mName;
        Transport mTransport;
        int mIgnored = 0;
        Benchmark mBenchmark;
        std::set<size_t> mTracedSizes;      // SmartData: the first packet of each size is traced, the others counted
};

// "GW_OK", "GW_IGNORED"... (gateway.h)
const char* statusName(int status);

#endif /* PACKET_MANAGER_H_ */
