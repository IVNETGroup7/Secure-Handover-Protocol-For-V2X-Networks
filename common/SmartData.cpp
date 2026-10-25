#include "SmartData.h"
#include "ByteWire.h"
#include "Traits.h"
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <string>

Bytes packSmartData(const SmartData& data)
{
    Bytes out;
    wire::putUint(out, data.location, 4);
    wire::putUint(out, data.timing, 8);
    wire::putUint(out, data.metadata, 4);
    wire::putField32(out, data.value);
    wire::putField32(out, data.authD);
    return out;
}

SmartData unpackSmartData(const Bytes& bytes)
{
    wire::Reader reader(bytes, "SmartData");
    SmartData data;
    data.location = static_cast<uint32_t>(reader.uint(4));
    data.timing = reader.uint(8);
    data.metadata = static_cast<uint32_t>(reader.uint(4));
    data.value = reader.field32();
    data.authD = reader.field32();
    reader.checkDone();
    return data;
}

Bytes packDataMessage(const DataMessage& message)
{
    Bytes out;
    wire::putField32(out, message.sealedData);
    wire::putField32(out, message.authD);
    out.insert(out.end(), message.otp.begin(), message.otp.end());
    return out;
}

DataMessage unpackDataMessage(const Bytes& bytes)
{
    wire::Reader reader(bytes, "OT packet");
    DataMessage message;
    message.sealedData = reader.field32();
    message.authD = reader.field32();
    message.otp = reader.block();
    reader.checkDone();
    return message;
}

uint64_t dataOtpSlot(int64_t ns)
{
    return static_cast<uint64_t>(std::floor((ns / 1e9) / kOtpTimeStep));
}

Block dataOtp(const Bytes& kDg, const Bytes& authD, uint64_t slot, const Bytes& m)
{
    // Auth_d xor t: t, big endian, into the last 8 bytes of the first AES block of Auth_d (as the bootstrap)
    Block nonce;
    if (authD.size() < nonce.size()) {
        throw std::runtime_error("OTP: Auth_d shorter than one block");
    }
    std::copy_n(authD.begin(), nonce.size(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] ^= static_cast<uint8_t>(slot >> (8 * i));
    }
    return poly1305Aes(kDg, nonce, m);
}

DataMessage sealSmartData(const SmartData& data, const Bytes& kG, const Bytes& kDg, int64_t nowNs)
{
    if (data.value.size() > kMaxSmartDataValue) {
        throw std::runtime_error("SmartData: value larger than " + std::to_string(kMaxSmartDataValue) + " bytes");
    }
    DataMessage message;
    message.sealedData = aesGcmEncrypt(kG, packSmartData(data));
    message.authD = data.authD;
    message.otp = dataOtp(kDg, data.authD, dataOtpSlot(nowNs), message.sealedData);
    return message;
}

Bytes computeKEg(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey)
{
    const Sha256 key = sha256(ecdh(privateKey, peerPublicKey));
    return Bytes(key.begin(), key.end());
}
