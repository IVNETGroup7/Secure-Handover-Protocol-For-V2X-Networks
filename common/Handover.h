#ifndef BOOTSTRAP_HANDOVER_H_
#define BOOTSTRAP_HANDOVER_H_

// Secrecy Forwarding: the handover of an activated vehicle V from RSU G_{i+1} (the one it bootstrapped with) to the
// next RSU G_{i+2}, with no ESA and no new bootstrap. The equations, the same on both sides: the vehicle
// (protocol/BootstrapService.cpp) and the RSUs' enclaves (rsu-sgx-gateway/Enclave/control.cpp). No I/O and no
// clock: compiled into the vehicle, the App and the enclave (as common/SmartData.cpp).
//
//   G_{i+1}  tau_{i+2}    = Poly1305(K_dg, t_i, m)          t_i: the slot of the OTP that activated V with G_{i+1},
//                                                           big endian in the last 8 bytes of the nonce (rest 0)
//            Forwarding_Notice { Y_V, tau_{i+2}, Auth_d }   -> G_{i+2}, over the HTTPS backhaul
//   G_{i+2}  K_dh_i       = ECDH(X_G_{i+2}, Y_V)            (V: ECDH(X_V, Y_G_{i+2}), the X_V of its bootstrap)
//            KT_i         = Poly1305(K_dh_i, K_dh_i xor tau_{i+2}, m)     16 bytes: the AES-128-GCM key
//            KT_i^32      = SHA256(KT_i || K_dh_i)                         32 bytes: the Poly1305-AES key
//            auth_{i+2}   = SHA256(tau_{i+2})
//            Handover_Command { G_{i+2}, Y_G_{i+2} }        -> V
//   V        Forwarding_Request { auth_{i+2}, OTP }         OTP = Poly1305(KT_i^32, auth_{i+2} xor t_c, m)
//   G_{i+2}  Forwarding_Granted E_KT_i({ Y_G_{i+3}, auth'_{i+2}, K_G_{i+2}, OTP })
//                                                           auth'_{i+2} = SHA256(auth_{i+2}); AES-128-GCM with KT_i
// Afterwards K_dh_i is V's K_dg with G_{i+2}, and t_c its t_i for the next handover.
// m and the slots: as the OTP_dt of the bootstrap (kOtpMessage, kOtpTimeStep, kOtpWindow of Traits.h)

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
