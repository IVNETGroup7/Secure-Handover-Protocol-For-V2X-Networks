#ifndef PROTOCOL_SECUREDATACLIENT_H_
#define PROTOCOL_SECUREDATACLIENT_H_

// Authenticated vehicle-to-RSU telemetry client (Secure_Data OT packets sealed with K_G and K_dg).

#include "Crypto.h"
#include "SmartData.h"
#include "VehicleSession.h"
#include <cstdint>

class SecureDataClient
{
    public:
        explicit SecureDataClient(VehicleSession& session) : mSession(session) {}

        // Seals SmartData under K_G and Poly1305 OTP_dt under K_dg, and sends Secure_Data to session.currentRsu().
        SmartData send(const Bytes& value, uint32_t location = 0, uint32_t metadata = 0);

    private:
        VehicleSession& mSession;
};

#endif /* PROTOCOL_SECUREDATACLIENT_H_ */

