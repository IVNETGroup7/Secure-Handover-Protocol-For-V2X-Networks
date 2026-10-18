#ifndef PACKET_MANAGER_H_
#define PACKET_MANAGER_H_

// Packet Manager (Non-Secure World, Fig. 5 of the paper): takes the packets of the OT queue and, by their
// header (tee.pdf step 3.3), hands them to the enclave
//   bootstrap messages   the RSU side of the bootstrap with the secrets moved into the enclave
//                        here (no secrets): relay of the Activation_Request to the ESA, PTP (master), routing
//                        in the enclave (Enclave/control.cpp): ECDH, OTP search, Auth_Granted, Active_02
//   SmartData            ecall_secure_marshal_ot_to_it (Enclave/marshaling.cpp): what it returns, HTTPS Header |
//                        AES(K_eg, JSON) made in the enclave, goes into the IT queue, for the cloud
// It never sees the keys, only what an ECALL copies out.

#include "BootstrapMsg.h"
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
            std::function<void(const BootstrapMsg&)> https;     // to the ESA (pre-established HTTPS session)
            std::function<void(ItPacket)> cloud;                // marshaled SmartData, to the cloud (IT queue)
        };

        PacketManager(sgx_enclave_id_t eid, std::string name) : mEid(eid), mName(std::move(name)) {}
        void setTransport(Transport transport) { mTransport = std::move(transport); }
        const std::string& name() const { return mName; }

        // a packet of the OT queue: bootstrap message or SmartData, by its kind
        void onOtPacket(const OtPacket&);
        // incoming bootstrap messages: over the radio (filtered by destination) or over HTTPS (from the ESA)
        void onRadio(const BootstrapMsg&);
        void onHttps(const BootstrapMsg&);

        // the ECALLs (Enclave.edl)
        int initGateway(const Bytes& gatewayCert, const Bytes& esaPublicKey, const Bytes& groupKey = {});
        // the HTTPS Session of the Secure Marshaling: the cloud's certificate (PEM) into the enclave
        int initCloudSession(const std::string& certificatePem, const std::string& host);
        int addActivationToken(const std::string& session, uint64_t t0, uint64_t tf, const Bytes& authD,
            const Bytes& authEg);
        Reply handleBootstrap(int type, const std::string& session, const Bytes& payload, uint64_t ptpTimeNs);
        Reply marshal(const Bytes& otPacket, uint64_t ptpTimeNs);

        int ignored() const { return mIgnored; }    // messages the enclave refused (a validation failed)
        Benchmark& benchmark() { return mBenchmark; }

    private:
        void enclaveStep(const char* step, const BootstrapMsg& received);
        void onSmartData(const OtPacket&);
        void send(int type, const std::string& destination, int seqNum, int ackNum, const std::string& vehicle,
            const Bytes& payload);

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
