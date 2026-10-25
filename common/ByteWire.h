#ifndef BOOTSTRAP_BYTEWIRE_H_
#define BOOTSTRAP_BYTEWIRE_H_

// Unified binary wire encoder and decoder for protocol payloads and state serialization
// Shared by both host code and SGX enclave code.

#include "Crypto.h"
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace wire
{

inline void putUint(Bytes& out, uint64_t value, int size)
{
    for (int i = size - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

// 2-byte length prefixed field (standard protocol messages)
inline void putField(Bytes& out, const Bytes& field)
{
    if (field.size() > 0xffff) {
        throw std::runtime_error("wire: field exceeds 16-bit length prefix");
    }
    putUint(out, field.size(), 2);
    out.insert(out.end(), field.begin(), field.end());
}

// 4-byte length prefixed field (e.g. large SmartData payloads)
inline void putField32(Bytes& out, const Bytes& field)
{
    putUint(out, field.size(), 4);
    out.insert(out.end(), field.begin(), field.end());
}

class Reader
{
    public:
        explicit Reader(const Bytes& in, const char* what = "wire") : mIn(in), mWhat(what) {}

        uint64_t uint(int size)
        {
            need(static_cast<size_t>(size));
            uint64_t value = 0;
            for (int i = 0; i < size; ++i) {
                value = (value << 8) | mIn[mPos++];
            }
            return value;
        }

        Block block()
        {
            return array<16>();
        }

        template <size_t N>
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
            const size_t size = static_cast<size_t>(uint(2));
            return bytes(size);
        }

        Bytes field32()
        {
            const size_t size = static_cast<size_t>(uint(4));
            return bytes(size);
        }

        bool done() const { return mPos == mIn.size(); }

        void checkDone() const
        {
            if (mPos != mIn.size()) {
                throw std::runtime_error(std::string(mWhat) + ": trailing bytes remaining");
            }
        }

        size_t remaining() const { return mIn.size() - mPos; }

    private:
        void need(size_t size) const
        {
            if (mPos + size > mIn.size()) {
                throw std::runtime_error(std::string(mWhat) + ": payload truncated (" + std::to_string(mIn.size()) + " bytes)");
            }
        }

        const Bytes& mIn;
        const char* mWhat;
        size_t mPos = 0;
};

} // namespace wire

#endif /* BOOTSTRAP_BYTEWIRE_H_ */
