#include "Handover.h"
#include "Traits.h"
#include <algorithm>
#include <stdexcept>
#include <string>

namespace
{

// m: the same public message as the OTP_dt of the bootstrap
const Bytes& otpMessage()
{
    static const Bytes m(kOtpMessage, kOtpMessage + std::char_traits<char>::length(kOtpMessage));
    return m;
}

} // namespace

Block forwardingToken(const Bytes& kDg, uint64_t authSlot)
{
    // t_i, big endian, into the last 8 bytes of an all-zero nonce
    Block nonce{};
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] = static_cast<uint8_t>(authSlot >> (8 * i));
    }
    return poly1305Aes(kDg, nonce, otpMessage());
}

HandoverKeys handoverKeys(const Bytes& kDh, const Block& tau)
{
    if (kDh.size() != 32) {
        throw std::runtime_error("Secrecy Forwarding: K_dh needs 32 bytes (got " + std::to_string(kDh.size()) + ")");
    }
    HandoverKeys keys;
    keys.kDh = kDh;

    // KT_i = Poly1305(K_dh_i, K_dh_i xor tau_{i+2}, m)
    Block nonce;
    for (size_t j = 0; j < nonce.size(); ++j) {
        nonce[j] = static_cast<uint8_t>(kDh[j] ^ tau[j]);
    }
    keys.kt = poly1305Aes(kDh, nonce, otpMessage());

    // KT_i^32 = SHA256(KT_i || K_dh_i): Poly1305-AES takes a 32-byte key
    Bytes material(keys.kt.begin(), keys.kt.end());
    material.insert(material.end(), kDh.begin(), kDh.end());
    const Sha256 kt32 = sha256(material);
    keys.kt32.assign(kt32.begin(), kt32.end());

    // auth_{i+2} = SHA256(tau_{i+2})
    keys.auth = sha256(Bytes(tau.begin(), tau.end()));
    return keys;
}

Block forwardingOtp(const HandoverKeys& keys, uint64_t slot)
{
    // auth_{i+2} xor t: t, big endian, into the last 8 bytes of the first 16 bytes of auth_{i+2} (as Auth_d xor t)
    Block nonce;
    std::copy_n(keys.auth.begin(), nonce.size(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] ^= static_cast<uint8_t>(slot >> (8 * i));
    }
    return poly1305Aes(keys.kt32, nonce, otpMessage());
}
