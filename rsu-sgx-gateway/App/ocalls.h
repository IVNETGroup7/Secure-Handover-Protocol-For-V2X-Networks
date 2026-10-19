#ifndef GATEWAY_OCALLS_H_
#define GATEWAY_OCALLS_H_

// Where ocall_save_sealed_state / ocall_load_sealed_state keep the sealed state (App/ocalls.cpp).
// An OCALL does not say which enclave made it: with several enclaves in one process (one per RSU, each
// sgx_create_enclave its own memory: the self-test's Secrecy Forwarding, artery-sim/), each enclave gets its own
// file by its eid, and an EnclaveScope around each ECALL tells the OCALLs which enclave the calling thread is in
// (PacketManager does it for every ECALL)

#include <sgx_eid.h>
#include <string>

// the file of the enclaves without one of their own (default: gateway.sealed)
void setSealedStatePath(const std::string& path);
// the file of enclave "eid"
void setSealedStatePath(sgx_enclave_id_t eid, const std::string& path);

class EnclaveScope
{
    public:
        explicit EnclaveScope(sgx_enclave_id_t eid);
        ~EnclaveScope();
        EnclaveScope(const EnclaveScope&) = delete;
        EnclaveScope& operator=(const EnclaveScope&) = delete;

    private:
        sgx_enclave_id_t mPrevious;
};

#endif /* GATEWAY_OCALLS_H_ */
