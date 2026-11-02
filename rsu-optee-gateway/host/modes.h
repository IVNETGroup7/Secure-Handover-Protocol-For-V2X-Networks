#ifndef GATEWAY_MODES_H_
#define GATEWAY_MODES_H_

// What ./app runs once the OP-TEE TA session is opened (host/main.cpp)

#include "Https.h"
#include "tee_session.h"
#include <cstdint>
#include <string>

// in-memory bootstrap against the repository's own vehicle and ESA (host/selftest.cpp);
// "storageId": Secure Storage object ID prefix for the second RSU (another TA session) of Secrecy Forwarding
int runSelfTest(TeeSession& tee, const std::string& storageId);

// the gateway as the RSU node on the raw sockets, with the frames of net/Link.h (host/rsu_node.cpp)
struct RsuOptions
{
    std::string iface = "lo";
    std::string name = "rsu[0]";
    int readyFd = -1;               // fork mode of ../bootstrap: written once the node is ready
    std::string cloudCertificate;   // the cloud's certificate (PEM) we trust; empty: no cloud
    std::string cloudAddress = kCloudAddress;
    uint16_t cloudPort = kCloudPort;
};
int runRsuNode(TeeSession& tee, const RsuOptions& options);

#endif /* GATEWAY_MODES_H_ */

