#ifndef COMMON_WIRECODEC_H_
#define COMMON_WIRECODEC_H_

// Lightweight big-endian binary serialization helpers shared by host protocol codecs.

#include "Crypto.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace wire_codec
{

inline void putUint(Bytes& out, uint64_t value, int size)
{
    for (int i = size - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

inline void putBytes(Bytes& out, const Bytes& data)
{
    putUint(out, data.size(), 2);
    out.insert(out.end(), data.begin(), data.end());
}

inline void putString(Bytes& out, const std::string& text)
{
    putUint(out, text.size(), 2);
    out.insert(out.end(), text.begin(), text.end());
}

class Reader
{
    public:
        Reader(const Bytes& in, const char* context) : mIn(in), mContext(context) {}

        uint64_t uint(int size)
        {
            need(static_cast<size_t>(size));
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
            std::copy_n(mIn.begin() + static_cast<long>(mPos), N, out.begin());
            mPos += N;
            return out;
        }

        Bytes bytes(size_t size)
        {
            need(size);
            Bytes out(mIn.begin() + static_cast<long>(mPos), mIn.begin() + static_cast<long>(mPos + size));
            mPos += size;
            return out;
        }

        Bytes field()
        {
            return bytes(static_cast<size_t>(uint(2)));
        }

        std::string str()
        {
            const Bytes b = field();
            return std::string(b.begin(), b.end());
        }

    private:
        void need(size_t size) const
        {
            if (mPos + size > mIn.size()) {
                throw std::runtime_error(std::string(mContext) + " truncated (" + std::to_string(mIn.size()) + " bytes)");
            }
        }

        const Bytes& mIn;
        const char* mContext;
        size_t mPos = 0;
};

} // namespace wire_codec

#endif /* COMMON_WIRECODEC_H_ */

