#ifndef GATEWAY_OCALLS_H_
#define GATEWAY_OCALLS_H_

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
