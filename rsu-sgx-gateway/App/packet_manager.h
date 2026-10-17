#ifndef PACKET_MANAGER_H_
#define PACKET_MANAGER_H_

// Packet Manager (Non-Secure World): the RSU side of the bootstrap with the secrets moved into the enclave.
//   here (no secrets): relay of the Activation_Request to the ESA, PTP (master), routing of every reply
//   in the enclave, through the ECALLs of Enclave.edl: ECDH, OTP search, Auth_Granted, Active_02 (Enclave/control.cpp)
// It never sees the keys, only what an ECALL copies out.

#include "BootstrapMsg.h"
#include "packet_queue.h"
#include <sgx_eid.h>
#include <functional>
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
        };

        PacketManager(sgx_enclave_id_t eid, std::string name) : mEid(eid), mName(std::move(name)) {}
        void setTransport(Transport transport) { mTransport = std::move(transport); }
        const std::string& name() const { return mName; }

        // incoming bootstrap messages: over the radio (filtered by destination) or over HTTPS (from the ESA)
        void onRadio(const BootstrapMsg&);
        void onHttps(const BootstrapMsg&);

        // the ECALLs (Enclave.edl)
        int initGateway(const Bytes& gatewayCert, const Bytes& esaPublicKey, const Bytes& groupKey = {});
        int addActivationToken(const std::string& session, uint64_t t0, uint64_t tf, const Bytes& authD,
            const Bytes& authEg);
        Reply handleBootstrap(int type, const std::string& session, const Bytes& payload, uint64_t ptpTimeNs);
        Reply marshal(const Bytes& otPacket, uint64_t ptpTimeNs);

        int ignored() const { return mIgnored; }    // messages the enclave refused (a validation failed)

    private:
        void enclaveStep(const char* step, const BootstrapMsg& received);
        void send(int type, const std::string& destination, int seqNum, int ackNum, const std::string& vehicle,
            const Bytes& payload);

        sgx_enclave_id_t mEid;
        std::string mName;
        Transport mTransport;
        int mIgnored = 0;
};

// "GW_OK", "GW_ERR_NOT_IMPLEMENTED"... (gateway.h)
const char* statusName(int status);

#endif /* PACKET_MANAGER_H_ */
