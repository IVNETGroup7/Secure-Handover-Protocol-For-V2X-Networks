#include "BootstrapPayload.h"
#include "MessageType.h"
#include "WireCodec.h"

Bytes pack(const ActivationRequestPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    wire_codec::putBytes(out, m.gatewayPublicKey);
    wire_codec::putUint(out, m.t0.ns(), 8);
    wire_codec::putUint(out, m.tf.ns(), 8);
    out.insert(out.end(), m.uuid.begin(), m.uuid.end());
    out.insert(out.end(), m.firmwareHash.begin(), m.firmwareHash.end());
    return out;
}

ActivationRequestPayload unpackActivationRequest(const Bytes& in)
{
    wire_codec::Reader reader(in, "bootstrap payload");
    ActivationRequestPayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.gatewayPublicKey = reader.field();
    m.t0 = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    m.tf = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    m.uuid = reader.array<16>();
    m.firmwareHash = reader.array<32>();
    return m;
}

std::vector<std::string> describe(const ActivationRequestPayload& m)
{
    // CY_g is DER SubjectPublicKeyInfo, parsing it also checks that it is a valid key
    const unsigned char* der = m.gatewayPublicKey.data();
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> cyG(
        d2i_PUBKEY(nullptr, &der, m.gatewayPublicKey.size()), EVP_PKEY_free);
    char curve[64] = "invalid key";
    if (cyG) {
        EVP_PKEY_get_group_name(cyG.get(), curve, sizeof(curve), nullptr);
    }

    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", CY_g, t_0, t_f, UUID, SHA256(f_w) }",
        "CY_g        = " + std::string(curve) + " " + toHex(m.gatewayPublicKey.data(), m.gatewayPublicKey.size()),
        "t_0         = " + m.t0.str() + " s",
        "t_f         = " + m.tf.str() + " s",
        "UUID        = " + toString(m.uuid),
        "SHA256(f_w) = " + toHex(m.firmwareHash.data(), m.firmwareHash.size()),
    };
}

Bytes pack(const ActivationTokenPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    wire_codec::putUint(out, m.t0.ns(), 8);
    wire_codec::putUint(out, m.tf.ns(), 8);
    wire_codec::putBytes(out, m.authD);
    wire_codec::putBytes(out, m.authEg);
    return out;
}

ActivationTokenPayload unpackActivationToken(const Bytes& in)
{
    wire_codec::Reader reader(in, "bootstrap payload");
    ActivationTokenPayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.t0 = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    m.tf = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    m.authD = reader.field();
    m.authEg = reader.field();
    return m;
}

std::vector<std::string> describe(const ActivationTokenPayload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", t_0, t_f, Auth_d, Auth_eg }",
        "t_0     = " + m.t0.str() + " s",
        "t_f     = " + m.tf.str() + " s",
        "Auth_d  = " + toHex(m.authD.data(), m.authD.size()),
        "Auth_eg = " + toHex(m.authEg.data(), m.authEg.size()),
    };
}

Bytes pack(const PtpPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    if (m.type != PTP && m.type != PTP_Delay_Request) {
        wire_codec::putUint(out, m.timestamp.ns(), 8);
    }
    return out;
}

PtpPayload unpackPtp(const Bytes& in)
{
    wire_codec::Reader reader(in, "bootstrap payload");
    PtpPayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    if (m.type != PTP && m.type != PTP_Delay_Request) {
        m.timestamp = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    }
    return m;
}

std::vector<std::string> describe(const PtpPayload& m)
{
    const std::string type = messageTypeName(m.type);
    if (m.type == PTP || m.type == PTP_Delay_Request) {
        return { "M = { " + type + " }" };
    }
    const std::string t = m.type == PTP_Sync ? "t_1" : "t_4";
    return {
        "M = { " + type + ", " + t + " }",
        t + " = " + m.timestamp.str() + " s",
    };
}

Bytes pack(const EcdhPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    wire_codec::putBytes(out, m.publicKey);
    return out;
}

EcdhPayload unpackEcdh(const Bytes& in)
{
    wire_codec::Reader reader(in, "bootstrap payload");
    EcdhPayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.publicKey = reader.field();
    return m;
}

std::vector<std::string> describe(const EcdhPayload& m)
{
    const std::string y = m.type == ECDH_Request ? "Y_d" : "Y_g";
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", " + y + " }",
        y + " = " + toHex(m.publicKey.data(), m.publicKey.size()),
    };
}

Bytes pack(const AuthRequestPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    return out;
}

std::vector<std::string> describe(const AuthRequestPayload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", OTP_dt }",
        "OTP_dt = " + toHex(m.otp.data(), m.otp.size()),
    };
}

AuthGrantedPayload unpackAuthGranted(const Bytes& in)
{
    wire_codec::Reader reader(in, "bootstrap payload");
    AuthGrantedPayload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.otp = reader.array<16>();
    m.kG = reader.field();
    m.esaPublicKey = reader.field();
    m.authEg = reader.field();
    return m;
}

Bytes authGrantedOtpData(const AuthGrantedPayload& m)
{
    Bytes out;
    wire_codec::putUint(out, Auth_Granted, 1);
    wire_codec::putBytes(out, m.kG);
    wire_codec::putBytes(out, m.esaPublicKey);
    wire_codec::putBytes(out, m.authEg);
    return out;
}

std::vector<std::string> describe(const AuthGrantedPayload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", OTP_dt, K_g, CY_e, Auth_eg }",
        "OTP_dt  = " + toHex(m.otp.data(), m.otp.size()),
        "K_g     = " + toHex(m.kG.data(), m.kG.size()),
        "CY_e    = " + toHex(m.esaPublicKey.data(), m.esaPublicKey.size()),
        "Auth_eg = " + toHex(m.authEg.data(), m.authEg.size()),
    };
}

Bytes pack(const Active01Payload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    wire_codec::putBytes(out, m.authD);
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    wire_codec::putBytes(out, m.authDe);
    return out;
}

Active01Payload unpackActive01(const Bytes& in)
{
    wire_codec::Reader reader(in, "bootstrap payload");
    Active01Payload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.authD = reader.field();
    m.otp = reader.array<16>();
    m.authDe = reader.field();
    return m;
}

Bytes activeOtpData(const Bytes& authD, const Bytes& authDe)
{
    Bytes out;
    wire_codec::putUint(out, Active_01, 1);
    wire_codec::putBytes(out, authD);
    wire_codec::putBytes(out, authDe);
    return out;
}

std::vector<std::string> describe(const Active01Payload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", Auth_d, OTP_dt, Auth_de }",
        "Auth_d  = " + toHex(m.authD.data(), m.authD.size()),
        "OTP_dt  = " + toHex(m.otp.data(), m.otp.size()),
        "Auth_de = " + toHex(m.authDe.data(), m.authDe.size()),
    };
}

Bytes pack(const Active03Payload& m)
{
    Bytes out;
    wire_codec::putUint(out, m.type, 1);
    out.insert(out.end(), m.uuid.begin(), m.uuid.end());
    out.insert(out.end(), m.firmwareHash.begin(), m.firmwareHash.end());
    return out;
}

Active03Payload unpackActive03(const Bytes& in)
{
    wire_codec::Reader reader(in, "bootstrap payload");
    Active03Payload m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.uuid = reader.array<16>();
    m.firmwareHash = reader.array<32>();
    return m;
}

std::vector<std::string> describe(const Active03Payload& m)
{
    return {
        "M = { " + std::string(messageTypeName(m.type)) + ", UUID, SHA256(f_w) }",
        "UUID        = " + toString(m.uuid),
        "SHA256(f_w) = " + toHex(m.firmwareHash.data(), m.firmwareHash.size()),
    };
}
