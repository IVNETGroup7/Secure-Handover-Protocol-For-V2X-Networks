#include "HandoverPayload.h"
#include "MessageType.h"
#include "Traits.h"
#include "WireCodec.h"

Bytes pack(const HandoverPredictPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    wire_codec::putBytes(out, m.authD);
    wire_codec::putString(out, m.targetRsu);
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    return out;
}

HandoverPredictPayload unpackHandoverPredict(const Bytes& in)
{
    wire_codec::Reader reader(in, "handover payload");
    HandoverPredictPayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.authD = reader.field();
    m.targetRsu = reader.str();
    m.otp = reader.array<16>();
    return m;
}

std::vector<std::string> describe(const HandoverPredictPayload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", Auth_d, G_{i+2}, OTP_dt }",
        "G_{i+2} = " + m.targetRsu + " (CTRA most likely target RSU; single-RSU pre-fetch)",
        "OTP_dt  = " + toHex(m.otp.data(), m.otp.size()),
    };
}

Bytes pack(const ForwardingRequestPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    out.insert(out.end(), m.auth.begin(), m.auth.end());
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    return out;
}

std::vector<std::string> describe(const ForwardingRequestPayload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", auth_{i+2}, OTP }",
        "auth_{i+2} = " + toHex(m.auth.data(), m.auth.size()),
        "OTP        = " + toHex(m.otp.data(), m.otp.size()),
    };
}

ForwardingGrantedPayload unpackForwardingGranted(const Bytes& in)
{
    wire_codec::Reader reader(in, "handover payload");
    ForwardingGrantedPayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    const size_t n = static_cast<size_t>(reader.uint(1));
    m.nextRsus.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        NeighborRsuKey nb;
        nb.name = reader.str();
        nb.publicKeyDer = reader.field();
        m.nextRsus.push_back(std::move(nb));
    }
    m.authPrime = reader.array<32>();
    m.kG = reader.field();
    m.otp = reader.array<16>();
    return m;
}

std::vector<std::string> describe(const ForwardingGrantedPayload& m)
{
    std::string names;
    for (size_t i = 0; i < m.nextRsus.size(); ++i) {
        if (i > 0) names += ", ";
        names += m.nextRsus[i].name;
    }
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", nextRsus, auth'_{i+2}, K_G_{i+2}, OTP' }",
        "nextRsus    = " + std::to_string(m.nextRsus.size())
            + (names.empty() ? std::string("") : " [" + names + "]"),
        "auth'_{i+2} = " + toHex(m.authPrime.data(), m.authPrime.size()),
        "K_G_{i+2}   = " + toHex(m.kG.data(), m.kG.size()),
        "OTP'        = " + toHex(m.otp.data(), m.otp.size()),
    };
}

