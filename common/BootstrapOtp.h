#ifndef COMMON_BOOTSTRAPOTP_H_
#define COMMON_BOOTSTRAPOTP_H_

#include "Crypto.h"

enum class BootstrapOtp : uint8_t
{
    AuthRequest,    // vehicle -> RSU: OTP_dt over m (kOtpMessage)
    AuthGranted,    // RSU -> vehicle: OTP_dt over { Auth_Granted, K_g, CY_e, Auth_eg, nextRsus }
    Active01,       // vehicle -> RSU: OTP_dt over { Active_01, Auth_d, Auth_de }
};

using OtpKey = std::array<uint8_t, 16>;

// K_otp of one OTP, derived from K_dg (32-byte ECDH secret); derive once and reuse it across slots t
OtpKey bootstrapOtpKey(const Bytes& kDg, BootstrapOtp which);

// OTP_dt = Ascon-AEAD128 tag of m under (K_otp, nonce = Auth_d xor t)
Block bootstrapOtp(const OtpKey& key, const Block& nonce, const Bytes& m);

#endif /* COMMON_BOOTSTRAPOTP_H_ */
