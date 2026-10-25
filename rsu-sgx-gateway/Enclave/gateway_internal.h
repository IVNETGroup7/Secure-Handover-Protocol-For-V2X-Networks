#ifndef GATEWAY_INTERNAL_H_
#define GATEWAY_INTERNAL_H_

// Internal Enclave interface between Control (control.cpp) and Marshaling (marshaling.cpp).
// Lives exclusively in trusted Enclave memory.

#include "Crypto.h"
#include <string>

// Looks up active vehicle session keys by Auth_d (used by Secure Marshaling to decrypt SmartData)
bool gatewayFindVehicleKeys(const Bytes& authD, Bytes& outKdg, Bytes& outKg);

// Checks if the gateway is initialized and ready
bool gatewayIsReady();

#endif /* GATEWAY_INTERNAL_H_ */
