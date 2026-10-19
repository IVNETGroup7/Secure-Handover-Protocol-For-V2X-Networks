#include "codec.h"
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
        throw std::runtime_error("bootstrap field too large");
    }
    putUint(out, field.size(), 2);
    out.insert(out.end(), field.begin(), field.end());
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

void Reader::need(size_t size) const
{
    if (mPos + size > mIn.size()) {
        throw std::runtime_error("bootstrap payload truncated (" + std::to_string(mIn.size()) + " bytes)");
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

Bytes pack(const ForwardingGranted& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    putField(out, m.nextRsuPublicKey);
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

Bytes pack(const ForwardingRequest& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    out.insert(out.end(), m.auth.begin(), m.auth.end());
    out.insert(out.end(), m.otp.begin(), m.otp.end());
    return out;
}

ForwardingGranted unpackForwardingGranted(const Bytes& in)
{
    Reader reader(in);
    ForwardingGranted m;
    m.type = static_cast<uint8_t>(reader.uint(1));
    m.nextRsuPublicKey = reader.field();
    m.authPrime = reader.array<32>();
    m.kG = reader.field();
    m.otp = reader.block();
    return m;
}

Bytes pack(const SecureData& m)
{
    Bytes out;
    putUint(out, m.type, 1);
    const Bytes packet = packDataMessage(DataMessage{ m.cipherData, m.authD, m.otp });
    out.insert(out.end(), packet.begin(), packet.end());
    return out;
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
