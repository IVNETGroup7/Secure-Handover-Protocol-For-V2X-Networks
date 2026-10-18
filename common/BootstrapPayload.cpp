#include "BootstrapPayload.h"
#include "BootstrapMsg.h"
#include "BootstrapService.h"
#include <algorithm>
#include <stdexcept>

static void putUint(Bytes& out, uint64_t value, int size)
{
    for (int i = size - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

// reads the fields of a packed payload in order; throws if the payload is too short
class Reader
{
    public:
        explicit Reader(const Bytes& in) : mIn(in) {}

        uint64_t uint(int size)
        {
            need(size);
            uint64_t value = 0;
            for (int i = 0; i < size; ++i) {
                value = (value << 8) | mIn[mPos++];
            }
            return value;
        }

        template<size_t N>
        std::array<uint8_t, N> array()
        {
            need(N);
            std::array<uint8_t, N> out;
            std::copy_n(mIn.begin() + mPos, N, out.begin());
            mPos += N;
            return out;
        }

        Bytes bytes(size_t size)
        {
            need(size);
            Bytes out(mIn.begin() + mPos, mIn.begin() + mPos + size);
            mPos += size;
            return out;
        }

    private:
        void need(size_t size) const
        {
            if (mPos + size > mIn.size()) {
                throw std::runtime_error("bootstrap payload truncated (" + std::to_string(mIn.size()) + " bytes)");
            }
        }

        const Bytes& mIn;
        size_t mPos = 0;
};

Bytes pack(const ActivationRequestPayload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putUint(out, m.gatewayPublicKey.size(), 2);
    out.insert(out.end(), m.gatewayPublicKey.begin(), m.gatewayPublicKey.end());
    putUint(out, m.t0.ns(), 8);
    putUint(out, m.tf.ns(), 8);
    out.insert(out.end(), m.uuid.begin(), m.uuid.end());
    out.insert(out.end(), m.firmwareHash.begin(), m.firmwareHash.end());
    return out;
}

ActivationRequestPayload unpackActivationRequest(const Bytes& in)
{
    Reader reader(in);
    ActivationRequestPayload m;
    m.type = reader.uint(1);
    m.gatewayPublicKey = reader.bytes(reader.uint(2));
    m.t0 = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    m.tf = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    m.uuid = reader.array<16>();
    m.firmwareHash = reader.array<32>();
    return m;
}

std::vector<std::string> describe(const ActivationRequestPayload& m)
{
    // CY_g is DER SubjectPublicKeyInfo: parsing it also checks that it is a valid key
    const unsigned char* der = m.gatewayPublicKey.data();
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> cyG(
        d2i_PUBKEY(nullptr, &der, m.gatewayPublicKey.size()), EVP_PKEY_free);
    char curve[64] = "invalid key";
    if (cyG) {
        EVP_PKEY_get_group_name(cyG.get(), curve, sizeof(curve), nullptr);
    }

    return {
        "M = { " + std::string(stageName(m.type)) + ", CY_g, t_0, t_f, UUID, SHA256(f_w) }",
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
    putUint(out, m.type, 1);
    putUint(out, m.t0.ns(), 8);
    putUint(out, m.tf.ns(), 8);
    putUint(out, m.authD.size(), 2);
    out.insert(out.end(), m.authD.begin(), m.authD.end());
    putUint(out, m.authEg.size(), 2);
    out.insert(out.end(), m.authEg.begin(), m.authEg.end());
    return out;
}

ActivationTokenPayload unpackActivationToken(const Bytes& in)
{
    Reader reader(in);
    ActivationTokenPayload m;
    m.type = reader.uint(1);
    m.t0 = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    m.tf = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    m.authD = reader.bytes(reader.uint(2));
    m.authEg = reader.bytes(reader.uint(2));
    return m;
}

std::vector<std::string> describe(const ActivationTokenPayload& m)
{
    return {
        "M = { " + std::string(stageName(m.type)) + ", t_0, t_f, Auth_d, Auth_eg }",
        "t_0     = " + m.t0.str() + " s",
        "t_f     = " + m.tf.str() + " s",
        "Auth_d  = " + toHex(m.authD.data(), m.authD.size()),
        "Auth_eg = " + toHex(m.authEg.data(), m.authEg.size()),
    };
}

Bytes pack(const PtpPayload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    if (m.type != PTP_Delay_Request) {
        putUint(out, m.timestamp.ns(), 8);
    }
    return out;
}

PtpPayload unpackPtp(const Bytes& in)
{
    Reader reader(in);
    PtpPayload m;
    m.type = reader.uint(1);
    if (m.type != PTP_Delay_Request) {
        m.timestamp = SimTime::fromNs(static_cast<int64_t>(reader.uint(8)));
    }
    return m;
}

std::vector<std::string> describe(const PtpPayload& m)
{
    const std::string type = stageName(m.type);
    if (m.type == PTP_Delay_Request) {
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
    putUint(out, m.type, 1);
    putUint(out, m.publicKey.size(), 2);
    out.insert(out.end(), m.publicKey.begin(), m.publicKey.end());
    return out;
}

EcdhPayload unpackEcdh(const Bytes& in)
{
    Reader reader(in);
    EcdhPayload m;
    m.type = reader.uint(1);
    m.publicKey = reader.bytes(reader.uint(2));
    return m;
}

std::vector<std::string> describe(const EcdhPayload& m)
{
    const std::string y = m.type == ECDH_Request ? "Y_d" : "Y_g";
    return {
        "M = { " + std::string(stageName(m.type)) + ", " + y + " }",
        y + " = " + toHex(m.publicKey.data(), m.publicKey.size()),
    };
}

Bytes pack(const AuthRequestPayload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    return out;
}

AuthRequestPayload unpackAuthRequest(const Bytes& in)
{
    Reader reader(in);
    AuthRequestPayload m;
    m.type = reader.uint(1);
    m.otp = reader.array<16>();
    return m;
}

std::vector<std::string> describe(const AuthRequestPayload& m)
{
    return {
        "M = { " + std::string(stageName(m.type)) + ", OTP_dt }",
        "OTP_dt = " + toHex(m.otp.data(), m.otp.size()),
    };
}

Bytes pack(const AuthGrantedPayload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    putUint(out, m.kG.size(), 2);
    out.insert(out.end(), m.kG.begin(), m.kG.end());
    putUint(out, m.esaPublicKey.size(), 2);
    out.insert(out.end(), m.esaPublicKey.begin(), m.esaPublicKey.end());
    putUint(out, m.authEg.size(), 2);
    out.insert(out.end(), m.authEg.begin(), m.authEg.end());
    return out;
}

AuthGrantedPayload unpackAuthGranted(const Bytes& in)
{
    Reader reader(in);
    AuthGrantedPayload m;
    m.type = reader.uint(1);
    m.otp = reader.array<16>();
    m.kG = reader.bytes(reader.uint(2));
    m.esaPublicKey = reader.bytes(reader.uint(2));
    m.authEg = reader.bytes(reader.uint(2));
    return m;
}

std::vector<std::string> describe(const AuthGrantedPayload& m)
{
    return {
        "M = { " + std::string(stageName(m.type)) + ", OTP_dt, K_g, CY_e, Auth_eg }",
        "OTP_dt  = " + toHex(m.otp.data(), m.otp.size()),
        "K_g     = " + toHex(m.kG.data(), m.kG.size()),
        "CY_e    = " + toHex(m.esaPublicKey.data(), m.esaPublicKey.size()),
        "Auth_eg = " + toHex(m.authEg.data(), m.authEg.size()),
    };
}

Bytes pack(const Active01Payload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putUint(out, m.authD.size(), 2);
    out.insert(out.end(), m.authD.begin(), m.authD.end());
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    putUint(out, m.authDe.size(), 2);
    out.insert(out.end(), m.authDe.begin(), m.authDe.end());
    return out;
}

Active01Payload unpackActive01(const Bytes& in)
{
    Reader reader(in);
    Active01Payload m;
    m.type = reader.uint(1);
    m.authD = reader.bytes(reader.uint(2));
    m.otp = reader.array<16>();
    m.authDe = reader.bytes(reader.uint(2));
    return m;
}

std::vector<std::string> describe(const Active01Payload& m)
{
    return {
        "M = { " + std::string(stageName(m.type)) + ", Auth_d, OTP_dt, Auth_de }",
        "Auth_d  = " + toHex(m.authD.data(), m.authD.size()),
        "OTP_dt  = " + toHex(m.otp.data(), m.otp.size()),
        "Auth_de = " + toHex(m.authDe.data(), m.authDe.size()),
    };
}

Bytes pack(const Active03Payload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    out.insert(out.end(), m.uuid.begin(), m.uuid.end());
    out.insert(out.end(), m.firmwareHash.begin(), m.firmwareHash.end());
    return out;
}

std::vector<std::string> describe(const Active03Payload& m)
{
    return {
        "M = { " + std::string(stageName(m.type)) + ", UUID, SHA256(f_w) }",
        "UUID        = " + toString(m.uuid),
        "SHA256(f_w) = " + toHex(m.firmwareHash.data(), m.firmwareHash.size()),
    };
}

Bytes pack(const ForwardingNoticePayload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putUint(out, m.vehiclePublicKey.size(), 2);
    out.insert(out.end(), m.vehiclePublicKey.begin(), m.vehiclePublicKey.end());
    out.insert(out.end(), m.tau.begin(), m.tau.end());
    return out;
}

ForwardingNoticePayload unpackForwardingNotice(const Bytes& in)
{
    Reader reader(in);
    ForwardingNoticePayload m;
    m.type = reader.uint(1);
    m.vehiclePublicKey = reader.bytes(reader.uint(2));
    m.tau = reader.array<16>();
    return m;
}

std::vector<std::string> describe(const ForwardingNoticePayload& m)
{
    return {
        "M = { " + std::string(stageName(m.type)) + ", Y_V, tau }",
        "Y_V = " + toHex(m.vehiclePublicKey.data(), m.vehiclePublicKey.size()),
        "tau = " + toHex(m.tau.data(), m.tau.size()),
    };
}

Bytes pack(const HandoverCommandPayload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putUint(out, m.targetRsuPublicKey.size(), 2);
    out.insert(out.end(), m.targetRsuPublicKey.begin(), m.targetRsuPublicKey.end());
    return out;
}

HandoverCommandPayload unpackHandoverCommand(const Bytes& in)
{
    Reader reader(in);
    HandoverCommandPayload m;
    m.type = reader.uint(1);
    m.targetRsuPublicKey = reader.bytes(reader.uint(2));
    return m;
}

std::vector<std::string> describe(const HandoverCommandPayload& m)
{
    return {
        "M = { " + std::string(stageName(m.type)) + ", Y_G_next }",
        "Y_G_next = " + toHex(m.targetRsuPublicKey.data(), m.targetRsuPublicKey.size()),
    };
}

Bytes pack(const ForwardingRequestPayload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    out.insert(out.end(), m.auth.begin(), m.auth.end());
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    return out;
}

ForwardingRequestPayload unpackForwardingRequest(const Bytes& in)
{
    Reader reader(in);
    ForwardingRequestPayload m;
    m.type = reader.uint(1);
    m.auth = reader.array<32>();
    m.otp = reader.array<16>();
    return m;
}

std::vector<std::string> describe(const ForwardingRequestPayload& m)
{
    return {
        "M = { " + std::string(stageName(m.type)) + ", auth, OTP }",
        "auth = " + toHex(m.auth.data(), m.auth.size()),
        "OTP  = " + toHex(m.otp.data(), m.otp.size()),
    };
}

Bytes pack(const ForwardingGrantedPayload& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putUint(out, m.nextRsuPublicKey.size(), 2);
    out.insert(out.end(), m.nextRsuPublicKey.begin(), m.nextRsuPublicKey.end());
    out.insert(out.end(), m.authPrime.begin(), m.authPrime.end());
    putUint(out, m.kG.size(), 2);
    out.insert(out.end(), m.kG.begin(), m.kG.end());
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    return out;
}

ForwardingGrantedPayload unpackForwardingGranted(const Bytes& in)
{
    Reader reader(in);
    ForwardingGrantedPayload m;
    m.type = reader.uint(1);
    m.nextRsuPublicKey = reader.bytes(reader.uint(2));
    m.authPrime = reader.array<32>();
    m.kG = reader.bytes(reader.uint(2));
    m.otp = reader.array<16>();
    return m;
}

std::vector<std::string> describe(const ForwardingGrantedPayload& m)
{
    return {
        "M = { " + std::string(stageName(m.type)) + ", Y_G_next, auth', K_G_next, OTP' }",
        "Y_G_next   = " + toHex(m.nextRsuPublicKey.data(), m.nextRsuPublicKey.size()),
        "auth'      = " + toHex(m.authPrime.data(), m.authPrime.size()),
        "K_G_next   = " + toHex(m.kG.data(), m.kG.size()),
        "OTP'       = " + toHex(m.otp.data(), m.otp.size()),
    };
}

void setPayload(BootstrapMsg& msg, const Bytes& payload)
{
    msg.setPayloadBytes(payload);
}

Bytes getPayload(const BootstrapMsg& msg)
{
    return msg.getPayloadBytes();
}
