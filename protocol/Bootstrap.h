#ifndef BOOTSTRAP_BOOTSTRAP_H_
#define BOOTSTRAP_BOOTSTRAP_H_

// Public API of the secure bootstrap library

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

class BootstrapService;

struct BootstrapResult
{
    std::string vehicle;
    std::string rsu;
    std::vector<uint8_t> kDg;   // K_dg: ECDH key shared by the vehicle and the RSU
    std::vector<uint8_t> kG;    // K_g: group key (AES-128-GCM) for vehicle <-> vehicle messages
    std::vector<uint8_t> kDe;   // K_de: vehicle <-> ESA key (vehicle only)
    // add protocol outputs here (token, keys, certificates...)
};

using BootstrapCallback = std::function<void(const BootstrapResult&)>;

// Starts the bootstrap of the vehicle that owns "service" (role vehicle).
// onCompleted runs when the vehicle finishes the bootstrap.
void initBootstrap(BootstrapService& service, BootstrapCallback onCompleted = nullptr);

#endif /* BOOTSTRAP_BOOTSTRAP_H_ */
