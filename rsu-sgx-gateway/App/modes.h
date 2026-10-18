#ifndef GATEWAY_MODES_H_
#define GATEWAY_MODES_H_

// What ./app runs, once the enclave exists (App/main.cpp)

#include "Https.h"
#include <sgx_eid.h>
#include <cstdint>
#include <string>

// in-memory bootstrap against the repository's own vehicle and ESA (App/selftest.cpp)
int runSelfTest(sgx_enclave_id_t eid);

// the gateway as the RSU node on the raw sockets, with the frames of net/Link.h (App/rsu_node.cpp)
struct RsuOptions
{
    std::string iface = "lo";
    std::string name = "rsu[0]";
    int readyFd = -1;           // fork mode of ../bootstrap: written once the node is ready
    std::string cloudCertificate;   // the cloud's certificate (PEM) we trust; empty: no cloud
    std::string cloudAddress = kCloudAddress;
    uint16_t cloudPort = kCloudPort;
};
int runRsuNode(sgx_enclave_id_t eid, const RsuOptions& options);

// where ocall_save_sealed_state / ocall_load_sealed_state keep the sealed state (App/ocalls.cpp)
void setSealedStatePath(const std::string& path);

#endif /* GATEWAY_MODES_H_ */
