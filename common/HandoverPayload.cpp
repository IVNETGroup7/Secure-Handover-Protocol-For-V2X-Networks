#include "HandoverPayload.h"
#include "MessageType.h"
#include "Traits.h"
#include "WireCodec.h"

Bytes pack(const HandoverPredictPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    wire_codec::putString(out, m.targetRsu);
    return out;
}

HandoverPredictPayload unpackHandoverPredict(const Bytes& in)
{
    wire_codec::Reader reader(in, "handover payload");
    HandoverPredictPayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.targetRsu = reader.str();
    return m;
}

std::vector<std::string> describe(const HandoverPredictPayload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", G_{i+2} }",
        "G_{i+2} = " + m.targetRsu + " (CTRA most likely target RSU; single-RSU pre-fetch)",
    };
}

Bytes pack(const ForwardingNoticePayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    wire_codec::putBytes(out, m.vehiclePublicKey);
    out.insert(out.end(), m.tau.begin(), m.tau.end());
    wire_codec::putBytes(out, m.authD);
    return out;
}

ForwardingNoticePayload unpackForwardingNotice(const Bytes& in)
{
    wire_codec::Reader reader(in, "handover payload");
    ForwardingNoticePayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.vehiclePublicKey = reader.field();
    m.tau = reader.array<16>();
    m.authD = reader.field();
    return m;
}

std::vector<std::string> describe(const ForwardingNoticePayload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", Y_V, tau_{i+2}, Auth_d }",
        "Y_V    = " + toHex(m.vehiclePublicKey.data(), m.vehiclePublicKey.size()),
        "Auth_d = " + toHex(m.authD.data(), m.authD.size()),
    };
}

Bytes pack(const HandoverCommandPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    wire_codec::putString(out, m.targetRsu);
    wire_codec::putBytes(out, m.targetRsuPublicKey);
    return out;
}

HandoverCommandPayload unpackHandoverCommand(const Bytes& in)
{
    wire_codec::Reader reader(in, "handover payload");
    HandoverCommandPayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.targetRsu = reader.str();
    m.targetRsuPublicKey = reader.field();
    return m;
}

std::vector<std::string> describe(const HandoverCommandPayload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", G_{i+2}, Y_G_{i+2} }",
        "G_{i+2}   = " + m.targetRsu,
        "Y_G_{i+2} = " + toHex(m.targetRsuPublicKey.data(), m.targetRsuPublicKey.size()),
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
    m.nextRsuPublicKey = reader.field();
    m.authPrime = reader.array<32>();
    m.kG = reader.field();
    m.otp = reader.array<16>();
    return m;
}

std::vector<std::string> describe(const ForwardingGrantedPayload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", Y_G_{i+3}, auth'_{i+2}, K_G_{i+2}, OTP }",
        "Y_G_{i+3}   = " + (m.nextRsuPublicKey.empty() ? std::string("(none)")
            : toHex(m.nextRsuPublicKey.data(), m.nextRsuPublicKey.size())),
        "auth'_{i+2} = " + toHex(m.authPrime.data(), m.authPrime.size()),
        "K_G_{i+2}   = " + toHex(m.kG.data(), m.kG.size()),
        "OTP         = " + toHex(m.otp.data(), m.otp.size()),
    };
}

