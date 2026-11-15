#ifndef COMMON_HANDOVERPAYLOAD_H_
#define COMMON_HANDOVERPAYLOAD_H_

// Wire payloads of the Secrecy Forwarding handover and CTRA predictive pre-fetch messages.

#include "Crypto.h"
#include <cstdint>
#include <string>
#include <vector>

// M = { Handover_Predict, G_{i+2} } (CTRA trajectory predictor -> current RSU: pre-fetch only for G_{i+2})
struct HandoverPredictPayload
{
    uint8_t type;
    std::string targetRsu;      // G_{i+2}: the single most likely RSU predicted by CTRA
};

Bytes pack(const HandoverPredictPayload&);
HandoverPredictPayload unpackHandoverPredict(const Bytes&);
std::vector<std::string> describe(const HandoverPredictPayload&);

// M = { Forwarding_Notice, Y_V, tau_{i+2}, Auth_d }
struct ForwardingNoticePayload
{
    uint8_t type;
    Bytes vehiclePublicKey;     // Y_V: the vehicle's ECDH public key of its bootstrap (DER, curve kEcdhCurve)
    Block tau;                  // tau_{i+2} = Poly1305(K_dg, t_i, m)
    Bytes authD;                // Auth_d: lets G_{i+2} marshal the vehicle's SmartData afterwards
};

Bytes pack(const ForwardingNoticePayload&);
ForwardingNoticePayload unpackForwardingNotice(const Bytes&);
std::vector<std::string> describe(const ForwardingNoticePayload&);

// M = { Handover_Command, G_{i+2}, Y_G_{i+2} }
struct HandoverCommandPayload
{
    uint8_t type;
    std::string targetRsu;      // G_{i+2}: where the Forwarding_Request goes
    Bytes targetRsuPublicKey;   // Y_G_{i+2}: G_{i+2}'s ECDH public key for this handover (DER)
};

Bytes pack(const HandoverCommandPayload&);
HandoverCommandPayload unpackHandoverCommand(const Bytes&);
std::vector<std::string> describe(const HandoverCommandPayload&);

// M = { Forwarding_Request, auth_{i+2}, OTP }
struct ForwardingRequestPayload
{
    uint8_t type;
    Sha256 auth;                // auth_{i+2} = SHA256(tau_{i+2})
    Block otp;                  // OTP = Poly1305(KT_i^32, auth_{i+2} xor t_c, m)
};

Bytes pack(const ForwardingRequestPayload&);
std::vector<std::string> describe(const ForwardingRequestPayload&);

// M = { Forwarding_Granted, Y_G_{i+3}, auth'_{i+2}, K_G_{i+2}, OTP }
struct ForwardingGrantedPayload
{
    uint8_t type;
    Bytes nextRsuPublicKey;     // Y_G_{i+3}: the next RSU's key, pre-loaded (empty: none yet)
    Sha256 authPrime;           // auth'_{i+2} = SHA256(auth_{i+2})
    Bytes kG;                   // K_G_{i+2}: G_{i+2}'s group key
    Block otp;                  // OTP: the one of the Forwarding_Request, echoed (freshness)
};

ForwardingGrantedPayload unpackForwardingGranted(const Bytes&);
std::vector<std::string> describe(const ForwardingGrantedPayload&);

#endif /* COMMON_HANDOVERPAYLOAD_H_ */

