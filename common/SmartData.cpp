#include "SmartData.h"
#include "Traits.h"
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <string>

namespace
{

void putUint(Bytes& out, uint64_t value, int size)
{
    for (int i = size - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

void putField(Bytes& out, const Bytes& field)
{
    putUint(out, field.size(), 4);
    out.insert(out.end(), field.begin(), field.end());
}

class Reader
{
    public:
        Reader(const Bytes& data, const char* what) : mData(data), mWhat(what) {}

        uint64_t uint(int size)
        {
            need(size);
            uint64_t value = 0;
            for (int i = 0; i < size; ++i) {
                value = (value << 8) | mData[mPos++];
            }
            return value;
        }

        Bytes field()
        {
            const size_t size = uint(4);
            need(size);
            Bytes field(mData.begin() + mPos, mData.begin() + mPos + size);
            mPos += size;
            return field;
        }

        Block block()
        {
            need(16);
            Block block;
            std::copy_n(mData.begin() + mPos, block.size(), block.begin());
            mPos += block.size();
            return block;
        }

        void done() const
        {
            if (mPos != mData.size()) {
                throw std::runtime_error(std::string(mWhat) + ": trailing bytes");
            }
        }

    private:
        void need(size_t size) const
        {
            if (mData.size() - mPos < size) {
                throw std::runtime_error(std::string(mWhat) + ": truncated");
            }
        }

        const Bytes& mData;
        const char* mWhat;
        size_t mPos = 0;
};

} // namespace

Bytes packSmartData(const SmartData& data)
{
    Bytes out;
    putUint(out, data.location, 4);
    putUint(out, data.timing, 8);
    putUint(out, data.metadata, 4);
    putField(out, data.value);
    putField(out, data.authD);
    return out;
}

SmartData unpackSmartData(const Bytes& bytes)
{
    Reader reader(bytes, "SmartData");
    SmartData data;
    data.location = static_cast<uint32_t>(reader.uint(4));
    data.timing = reader.uint(8);
    data.metadata = static_cast<uint32_t>(reader.uint(4));
    data.value = reader.field();
    data.authD = reader.field();
    reader.done();
    return data;
}

Bytes packDataMessage(const DataMessage& message)
{
    Bytes out;
    putField(out, message.sealedData);
    putField(out, message.authD);
    out.insert(out.end(), message.otp.begin(), message.otp.end());
    return out;
}

DataMessage unpackDataMessage(const Bytes& bytes)
{
    Reader reader(bytes, "OT packet");
    DataMessage message;
    message.sealedData = reader.field();
    message.authD = reader.field();
    message.otp = reader.block();
    reader.done();
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
