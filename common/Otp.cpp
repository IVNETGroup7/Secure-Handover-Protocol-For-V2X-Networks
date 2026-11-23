#include "Otp.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace
{

const char* purposeLabel(OtpPurpose purpose)
{
    switch (purpose) {
        case OtpPurpose::AuthRequest:       return "v2x ascon OTP Auth_Request";
        case OtpPurpose::AuthGranted:       return "v2x ascon OTP Auth_Granted";
        case OtpPurpose::Active01:          return "v2x ascon OTP Active_01";
        case OtpPurpose::SecureData:        return "v2x ascon OTP Secure_Data";
        case OtpPurpose::HandoverPredict:   return "v2x ascon OTP Handover_Predict";
        case OtpPurpose::ForwardingToken:   return "v2x ascon OTP Forwarding_Token";
        case OtpPurpose::HandoverKey:       return "v2x ascon OTP Handover_Key";
        case OtpPurpose::ForwardingRequest: return "v2x ascon OTP Forwarding_Request";
        case OtpPurpose::ForwardingGranted: return "v2x ascon OTP Forwarding_Granted";
    }
    throw std::runtime_error("OTP: unknown purpose");
}

#ifndef __OPTEE_TA__
OtpAlgo gOtpAlgo = OtpAlgo::Ascon;
#endif

} // namespace

const char* otpAlgoName(OtpAlgo algo)
{
    switch (algo) {
        case OtpAlgo::Poly1305: return "poly1305";
        case OtpAlgo::Ascon:    return "ascon";
    }
    return "unknown";
}

std::optional<OtpAlgo> parseOtpAlgo(const std::string& name)
{
    if (name == "ascon") {
        return OtpAlgo::Ascon;
    }
    if (name == "poly1305") {
        return OtpAlgo::Poly1305;
    }
    return std::nullopt;
}

void volatileWipe(void* ptr, size_t len)
{
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

ascon::Key deriveAsconOtpKey(const Bytes& key32, OtpPurpose purpose)
{
    if (key32.empty()) {
        throw std::runtime_error("OTP: empty key material");
    }
    const char* text = purposeLabel(purpose);
    const size_t labelSize = std::strlen(text);

    Bytes material;
    material.reserve(labelSize + 1 + key32.size());
    material.insert(material.end(), text, text + labelSize);
    material.push_back(0x00);
    material.insert(material.end(), key32.begin(), key32.end());

    ascon::Digest digest = ascon::hash256(material.data(), material.size());
    ascon::Key key{};
    std::copy_n(digest.begin(), key.size(), key.begin());
    volatileWipe(material.data(), material.size());
    volatileWipe(digest.data(), digest.size());
    return key;
}

#ifndef __OPTEE_TA__
OtpAlgo otpAlgorithm()
{
    return gOtpAlgo;
}

void setOtpAlgorithm(OtpAlgo algo)
{
    gOtpAlgo = algo;
}

Block computeOtp(const Bytes& key32, OtpPurpose purpose, const Block& nonce, const Bytes& m, OtpAlgo algo)
{
    if (algo == OtpAlgo::Ascon) {
        const ScopedAsconKey key(key32, purpose);
        return computeAsconOtp(key.key, nonce, m);
    }
    return poly1305Aes(key32, nonce, m);
}
#endif

