#include "Handover.h"
#include "MessageType.h"
#include "Otp.h"
#include "Traits.h"
#include "WireCodec.h"
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

Block slottedNonce(const uint8_t* prefix16, uint64_t slot)
{
    Block nonce{};
    std::copy_n(prefix16, nonce.size(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] ^= static_cast<uint8_t>(slot >> (8 * i));
    }
    return nonce;
}

} // namespace

Block forwardingToken(const Bytes& kDg, uint64_t authSlot)
{
    // t_i, big endian, into the last 8 bytes of an all-zero nonce
    Block nonce{};
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] = static_cast<uint8_t>(authSlot >> (8 * i));
    }
    return computeOtp(kDg, OtpPurpose::ForwardingToken, nonce, otpMessage());
}

HandoverKeys handoverKeys(const Bytes& kDh, const Block& tau)
{
    if (kDh.size() != 32) {
        throw std::runtime_error("Secrecy Forwarding: K_dh needs 32 bytes (got " + std::to_string(kDh.size()) + ")");
    }
    HandoverKeys keys;
    keys.kDh = kDh;

    // KT_i = MAC(K_dh_i, K_dh_i xor tau_{i+2}, m)
    Block nonce;
    for (size_t j = 0; j < nonce.size(); ++j) {
        nonce[j] = static_cast<uint8_t>(kDh[j] ^ tau[j]);
    }
    keys.kt = computeOtp(kDh, OtpPurpose::HandoverKey, nonce, otpMessage());

    // KT_i^32 = SHA256(KT_i || K_dh_i): 32-byte key material for Forwarding OTPs
    Bytes material(keys.kt.begin(), keys.kt.end());
    material.insert(material.end(), kDh.begin(), kDh.end());
    const Sha256 kt32 = sha256(material);
    keys.kt32.assign(kt32.begin(), kt32.end());

    // auth_{i+2} = SHA256(tau_{i+2}), auth'_{i+2} = SHA256(KT_i || auth_{i+2})
    keys.auth = sha256(Bytes(tau.begin(), tau.end()));
    Bytes primeMaterial(keys.kt.begin(), keys.kt.end());
    primeMaterial.insert(primeMaterial.end(), keys.auth.begin(), keys.auth.end());
    keys.authPrime = sha256(primeMaterial);
    return keys;
}

Bytes handoverPredictOtpData(const std::string& targetRsu)
{
    Bytes out;
    wire_codec::putUint(out, Handover_Predict, 1);
    wire_codec::putString(out, targetRsu);
    return out;
}

Bytes forwardingRequestOtpData(const Sha256& auth)
{
    Bytes out;
    wire_codec::putUint(out, Forwarding_Request, 1);
    out.insert(out.end(), auth.begin(), auth.end());
    return out;
}

Block forwardingOtp(const HandoverKeys& keys, uint64_t slot)
{
    return computeOtp(keys.kt32, OtpPurpose::ForwardingRequest, slottedNonce(keys.auth.data(), slot),
        forwardingRequestOtpData(keys.auth));
}

Bytes forwardingGrantedOtpData(const std::vector<NeighborRsuKey>& nextRsus, const Sha256& authPrime, const Bytes& kG)
{
    Bytes out;
    wire_codec::putUint(out, Forwarding_Granted, 1);
    wire_codec::putUint(out, nextRsus.size(), 1);
    for (const NeighborRsuKey& nb : nextRsus) {
        wire_codec::putString(out, nb.name);
        wire_codec::putBytes(out, nb.publicKeyDer);
    }
    out.insert(out.end(), authPrime.begin(), authPrime.end());
    wire_codec::putBytes(out, kG);
    return out;
}

Block forwardingGrantedOtp(const HandoverKeys& keys, uint64_t slot, const std::vector<NeighborRsuKey>& nextRsus,
    const Sha256& authPrime, const Bytes& kG)
{
    return computeOtp(keys.kt32, OtpPurpose::ForwardingGranted, slottedNonce(authPrime.data(), slot),
        forwardingGrantedOtpData(nextRsus, authPrime, kG));
}
