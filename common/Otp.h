#ifndef COMMON_OTP_H_
#define COMMON_OTP_H_

// Unified OTP / MAC primitive shared by host (vehicle, tests, Artery) and OP-TEE TA.
// Every OTP and MAC across initial bootstrap, SmartData marshaling, and Secrecy Forwarding
// runs under a single selected algorithm (Ascon-AEAD128 or Poly1305-AES) — never mixed.

#include "Ascon.h"
#include "Crypto.h"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

enum class OtpAlgo : uint8_t
{
    Poly1305 = 0,
    Ascon    = 1,
};

enum class OtpPurpose : uint8_t
{
    AuthRequest       = 0,  // Bootstrap Step 6: Auth_Request OTP_dt
    AuthGranted       = 1,  // Bootstrap Step 8: Auth_Granted OTP_dt
    Active01          = 2,  // Bootstrap Step 9/10: Active_01 OTP_dt
    SecureData        = 3,  // OT SmartData OTP_dt
    HandoverPredict   = 4,  // CTRA Handover_Predict OTP_dt
    ForwardingToken   = 5,  // Secrecy Forwarding tau_{i+2}
    HandoverKey       = 6,  // Secrecy Forwarding KT_i
    ForwardingRequest = 7,  // Secrecy Forwarding Forwarding_Request OTP
    ForwardingGranted = 8,  // Secrecy Forwarding Forwarding_Granted OTP'
};

const char* otpAlgoName(OtpAlgo algo);
std::optional<OtpAlgo> parseOtpAlgo(const std::string& name);

// Compiler-safe memory zeroing (works in both host and freestanding OP-TEE TA)
void volatileWipe(void* ptr, size_t len);

// Domain-separated 16-byte Ascon-AEAD128 key derived from a 32-byte shared secret:
//   K_otp = Ascon-Hash256(label(purpose) || 0x00 || key32)[0..16]
ascon::Key deriveAsconOtpKey(const Bytes& key32, OtpPurpose purpose);

// Stack-allocated RAII wrapper wiping derived Ascon K_otp on scope exit (zero heap allocation)
struct ScopedAsconKey
{
    ascon::Key key{};

    ScopedAsconKey(const Bytes& key32, OtpPurpose purpose) : key(deriveAsconOtpKey(key32, purpose)) {}
    ScopedAsconKey(const ScopedAsconKey&) = delete;
    ScopedAsconKey& operator=(const ScopedAsconKey&) = delete;
    ~ScopedAsconKey() { volatileWipe(key.data(), key.size()); }
};

inline Block computeAsconOtp(const ascon::Key& key, const Block& nonce, const Bytes& m)
{
    return ascon::aead128Tag(key, nonce, m.data(), m.size());
}

#ifndef __OPTEE_TA__
// Process-wide host OTP algorithm (default: Ascon; configured via --otp / OTP_ALGO)
OtpAlgo otpAlgorithm();
void setOtpAlgorithm(OtpAlgo algo);

// Compute a 16-byte OTP/MAC under the selected algorithm (host/vehicle side)
Block computeOtp(const Bytes& key32, OtpPurpose purpose, const Block& nonce, const Bytes& m,
    OtpAlgo algo = otpAlgorithm());
#endif

#endif /* COMMON_OTP_H_ */

