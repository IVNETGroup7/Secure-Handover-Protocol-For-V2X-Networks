#ifndef GATEWAY_MODES_H_
#define GATEWAY_MODES_H_

// What ./app runs once the OP-TEE TA session is opened (host/main.cpp)

#include "Otp.h"
#include "tee_session.h"
#include <optional>
#include <string>

// in-memory bootstrap against the repository's own vehicle and ESA (host/selftest.cpp);
// "storageId": Secure Storage object ID prefix for the second RSU (another TA session) of Secrecy Forwarding
int runSelfTest(TeeSession& tee, const std::string& storageId);

// the gateway as an HIL RSU node on raw Ethernet sockets (0x88b5 radio, 0x88b6 backhaul)
struct RsuOptions
{
    std::string iface = "eth0";
    std::string name = "rsu[0]";
    unsigned sessionTimeoutSeconds = 120;
    std::optional<OtpAlgo> otpAlgo;     // nullopt = adopt Session_Ack otpAlgo from backhaul
};
int runRsuNode(TeeSession& tee, const RsuOptions& options);

#endif /* GATEWAY_MODES_H_ */

