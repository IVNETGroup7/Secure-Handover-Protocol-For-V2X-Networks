#include "codec.h"
#include "MessageType.h"
#include "SmartData.h"
#include <algorithm>
#include <stdexcept>
#include <string>

namespace wire
{

void putUint(Bytes& out, uint64_t value, int size)
{
    for (int i = size - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

void putField(Bytes& out, const Bytes& field)
{
    if (field.size() > 0xffff) {
        throw std::runtime_error("TA codec field too large");
    }
    putUint(out, field.size(), 2);
    out.insert(out.end(), field.begin(), field.end());
}

void putString(Bytes& out, const std::string& text)
{
    if (text.size() > 0xffff) {
        throw std::runtime_error("TA codec string too large");
    }
    putUint(out, text.size(), 2);
    out.insert(out.end(), text.begin(), text.end());
}

uint64_t Reader::uint(int size)
{
    need(static_cast<size_t>(size));
    uint64_t value = 0;
    for (int i = 0; i < size; ++i) {
        value = (value << 8) | mIn[mPos++];
    }
    return value;
}

Block Reader::block()
{
    need(16);
    Block out;
    std::copy_n(mIn.begin() + static_cast<long>(mPos), out.size(), out.begin());
    mPos += out.size();
    return out;
}

Bytes Reader::field()
{
    const size_t size = static_cast<size_t>(uint(2));
    need(size);
    Bytes out(mIn.begin() + static_cast<long>(mPos), mIn.begin() + static_cast<long>(mPos + size));
    mPos += size;
    return out;
}

std::string Reader::str()
{
    const Bytes b = field();
    return std::string(b.begin(), b.end());
}

void Reader::need(size_t size) const
{
    if (mPos + size > mIn.size()) {
        throw std::runtime_error("TA payload truncated (" + std::to_string(mIn.size()) + " bytes)");
    }
}

Bytes pack(const Ecdh& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putField(out, m.publicKey);
    return out;
}

Bytes pack(const AuthGranted& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    putField(out, m.kG);
    putField(out, m.esaPublicKey);
    putField(out, m.authEg);
    putUint(out, m.nextRsus.size(), 1);
    for (const NeighborRsuKey& nb : m.nextRsus) {
        putString(out, nb.name);
        putField(out, nb.publicKeyDer);
    }
    return out;
}

Bytes pack(const Active& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putField(out, m.authD);
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    putField(out, m.authDe);
    return out;
}

Bytes authGrantedOtpData(const AuthGranted& m)
{
    Bytes out;
    putUint(out, Auth_Granted, 1);
    putField(out, m.kG);
    putField(out, m.esaPublicKey);
    putField(out, m.authEg);
    putUint(out, m.nextRsus.size(), 1);
    for (const NeighborRsuKey& nb : m.nextRsus) {
        putString(out, nb.name);
        putField(out, nb.publicKeyDer);
    }
    return out;
}

Bytes activeOtpData(const Bytes& authD, const Bytes& authDe)
{
    Bytes out;
    putUint(out, Active_01, 1);
    putField(out, authD);
    putField(out, authDe);
    return out;
}

ActivationToken unpackActivationToken(const Bytes& in)
{
    Reader reader(in);
    ActivationToken m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.t0 = reader.uint(8);
    m.tf = reader.uint(8);
    m.authD = reader.field();
    m.authEg = reader.field();
    return m;
}

Ecdh unpackEcdh(const Bytes& in)
{
    Reader reader(in);
    Ecdh m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.publicKey = reader.field();
    return m;
}

AuthRequest unpackAuthRequest(const Bytes& in)
{
    Reader reader(in);
    AuthRequest m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.otp = reader.block();
    return m;
}

Active unpackActive(const Bytes& in)
{
    Reader reader(in);
    Active m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.authD = reader.field();
    m.otp = reader.block();
    m.authDe = reader.field();
    return m;
}

Bytes handoverPredictOtpData(const std::string& targetRsu)
{
    Bytes out;
    putUint(out, Handover_Predict, 1);
    putString(out, targetRsu);
    return out;
}

HandoverPredict unpackHandoverPredict(const Bytes& in)
{
    Reader reader(in);
    HandoverPredict m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.authD = reader.field();
    m.targetRsu = reader.str();
    m.otp = reader.block();
    return m;
}

Bytes pack(const ForwardingNotice& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putField(out, m.vehiclePublicKey);
    out.insert(out.end(), m.tau.begin(), m.tau.end());
    putField(out, m.authD);
    putString(out, m.vehicleLabel);
    return out;
}

ForwardingNotice unpackForwardingNotice(const Bytes& in)
{
    Reader reader(in);
    ForwardingNotice m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.vehiclePublicKey = reader.field();
    m.tau = reader.block();
    m.authD = reader.field();
    m.vehicleLabel = reader.str();
    return m;
}

Bytes forwardingRequestOtpData(const Sha256& auth)
{
    Bytes out;
    putUint(out, Forwarding_Request, 1);
    out.insert(out.end(), auth.begin(), auth.end());
    return out;
}

Bytes forwardingGrantedOtpData(const ForwardingGranted& m)
{
    Bytes out;
    putUint(out, Forwarding_Granted, 1);
    putUint(out, m.nextRsus.size(), 1);
    for (const NeighborRsuKey& nb : m.nextRsus) {
        putString(out, nb.name);
        putField(out, nb.publicKeyDer);
    }
    out.insert(out.end(), m.authPrime.begin(), m.authPrime.end());
    putField(out, m.kG);
    return out;
}

Bytes pack(const ForwardingGranted& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putUint(out, m.nextRsus.size(), 1);
    for (const NeighborRsuKey& nb : m.nextRsus) {
        putString(out, nb.name);
        putField(out, nb.publicKeyDer);
    }
    out.insert(out.end(), m.authPrime.begin(), m.authPrime.end());
    putField(out, m.kG);
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    return out;
}

ForwardingRequest unpackForwardingRequest(const Bytes& in)
{
    Reader reader(in);
    ForwardingRequest m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.auth = reader.array<32>();
    m.otp = reader.block();
    return m;
}

SecureData unpackSecureData(const Bytes& in)
{
    Reader reader(in);
    SecureData m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    const DataMessage packet = unpackDataMessage(Bytes(in.begin() + 1, in.end()));
    m.cipherData = packet.sealedData;
    m.authD = packet.authD;
    m.otp = packet.otp;
    return m;
}

} // namespace wire

