#include "BootstrapOtp.h"
#include "Ascon.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace
{

const char* label(BootstrapOtp which)
{
    switch (which) {
        case BootstrapOtp::AuthRequest: return "secure-bootstrap ascon OTP_dt Auth_Request";
        case BootstrapOtp::AuthGranted: return "secure-bootstrap ascon OTP_dt Auth_Granted";
        case BootstrapOtp::Active01:    return "secure-bootstrap ascon OTP_dt Active_01";
    }
    throw std::runtime_error("bootstrap OTP: unknown OTP");
}

} // namespace

OtpKey bootstrapOtpKey(const Bytes& kDg, BootstrapOtp which)
{
    if (kDg.empty()) {
        throw std::runtime_error("bootstrap OTP: empty K_dg");
    }
    const char* text = label(which);
    const size_t labelSize = std::strlen(text);

    Bytes material(text, text + labelSize);
    material.push_back(0x00);
    material.insert(material.end(), kDg.begin(), kDg.end());
    ascon::Digest digest = ascon::hash256(material.data(), material.size());

    OtpKey key;
    std::copy_n(digest.begin(), key.size(), key.begin());
    std::fill(material.begin(), material.end(), 0);
    std::fill(digest.begin(), digest.end(), 0);
    return key;
}

Block bootstrapOtp(const OtpKey& key, const Block& nonce, const Bytes& m)
{
    return ascon::aead128Tag(key, nonce, m.data(), m.size());
}
