#ifndef BOOTSTRAP_HANDOVER_H_
#define BOOTSTRAP_HANDOVER_H_

#include "Crypto.h"
#include <cstdint>

// what G_{i+2} (and V) derive from K_dh_i and tau_{i+2}
struct HandoverKeys
{
    Bytes kDh;                  // K_dh_i: the ECDH secret of V and G_{i+2}, V's K_dg with G_{i+2} afterwards
    Block kt{};                 // KT_i: AES-128-GCM key of the Forwarding_Granted
    Bytes kt32;                 // KT_i^32 = SHA256(KT_i || K_dh_i): Poly1305-AES key of the OTP
    Sha256 auth{};              // auth_{i+2} = SHA256(tau_{i+2})
};

// tau_{i+2} = Poly1305(K_dg, t_i, m)
Block forwardingToken(const Bytes& kDg, uint64_t authSlot);

// KT_i, KT_i^32 and auth_{i+2} of K_dh_i and tau_{i+2}
HandoverKeys handoverKeys(const Bytes& kDh, const Block& tau);

// OTP = Poly1305(KT_i^32, auth_{i+2} xor t, m)
Block forwardingOtp(const HandoverKeys& keys, uint64_t slot);

#endif /* BOOTSTRAP_HANDOVER_H_ */
