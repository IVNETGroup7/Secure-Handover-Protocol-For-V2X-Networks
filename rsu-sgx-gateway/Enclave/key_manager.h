#ifndef GATEWAY_KEY_MANAGER_H_
#define GATEWAY_KEY_MANAGER_H_

// OT Key Manager (Fig. 5 of the paper), inside the enclave: the keys the control component (control.cpp) set up
// for each vehicle it activated, as the Secure Marshaling (marshaling.cpp) needs them. The state stays in
// control.cpp; this is the only way in for the rest of the enclave

#include "Crypto.h"
#include <optional>
#include <string>

struct VehicleKeys
{
    std::string session;    // the vehicle (BootstrapMsg.vehicle of its bootstrap)
    Bytes kDg;              // K_dg: its ECDH key with this RSU
    Bytes kG;               // K_G: its group key (the one Auth_Granted gave it)
};

// ecall_init_gateway done
bool gatewayReady();

// the activated vehicle whose Auth_d is "authD" (compared in constant time); nullopt: none
std::optional<VehicleKeys> findVehicleKeys(const Bytes& authD);

// ocall_print; a validation goes with the kCheckOk / kCheckFailed prefix (App/ocalls.cpp shows it as one)
void enclavePrint(const std::string& text);
void enclaveCheck(bool ok, const std::string& text);

#endif /* GATEWAY_KEY_MANAGER_H_ */
