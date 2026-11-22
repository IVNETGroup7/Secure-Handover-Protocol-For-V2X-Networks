#ifndef COMMON_HANDOVERPAYLOAD_H_
#define COMMON_HANDOVERPAYLOAD_H_

// Wire payloads of the Secrecy Forwarding handover and CTRA predictive pre-fetch messages.

#include "Crypto.h"
#include <cstdint>
#include <string>
#include <vector>

// M = { Handover_Predict, Auth_d, G_{i+2}, OTP_dt } encrypted under K_dg (CTRA -> current RSU)
struct HandoverPredictPayload
{
    uint8_t type;
    Bytes authD;                // Auth_d
    std::string targetRsu;      // G_{i+2}: the single most likely RSU predicted by CTRA
    Block otp{};                // OTP_dt = Poly1305(K_dg, Auth_d xor t_c, Handover_Predict || targetRsu)
};

Bytes pack(const HandoverPredictPayload&);
HandoverPredictPayload unpackHandoverPredict(const Bytes&);
std::vector<std::string> describe(const HandoverPredictPayload&);

// M = { Forwarding_Request, auth_{i+2}, OTP }
struct ForwardingRequestPayload
{
    uint8_t type;
    Sha256 auth;                // auth_{i+2} = SHA256(tau_{i+2})
    Block otp;                  // OTP = Poly1305(KT_i^32, auth_{i+2} xor t_c, Forwarding_Request || auth_{i+2})
};

Bytes pack(const ForwardingRequestPayload&);
std::vector<std::string> describe(const ForwardingRequestPayload&);

// M = { Forwarding_Granted, nextRsus, auth'_{i+2}, K_G_{i+2}, OTP' } encrypted under KT_i
struct ForwardingGrantedPayload
{
    uint8_t type;
    std::vector<NeighborRsuKey> nextRsus;   // Y_{G_{i+3}}: CA-verified neighbor RSU public keys
    Sha256 authPrime;                       // auth'_{i+2} = SHA256(KT_i || auth_{i+2})
    Bytes kG;                               // K_G_{i+2}: G_{i+2}'s group key
    Block otp;                              // OTP': fresh Poly1305(KT_i^32, auth'_{i+2} xor t_c, ...)
};

ForwardingGrantedPayload unpackForwardingGranted(const Bytes&);
std::vector<std::string> describe(const ForwardingGrantedPayload&);

#endif /* COMMON_HANDOVERPAYLOAD_H_ */

