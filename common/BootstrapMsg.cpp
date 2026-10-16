#include "BootstrapMsg.h"
#include <stdexcept>

static void putUint(Bytes& out, uint64_t value, int size)
{
    for (int i = size - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

static void putString(Bytes& out, const std::string& s)
{
    putUint(out, s.size(), 2);
    out.insert(out.end(), s.begin(), s.end());
}

Bytes serialize(const BootstrapMsg& msg)
{
    Bytes out;
    putUint(out, msg.getType(), 1);
    putUint(out, static_cast<uint32_t>(msg.getSeqNum()), 4);
    putUint(out, static_cast<uint32_t>(msg.getAckNum()), 4);
    putString(out, msg.getSender());
    putString(out, msg.getDestination());
    putString(out, msg.getVehicle());
    putUint(out, msg.getPayloadBytes().size(), 4);
    out.insert(out.end(), msg.getPayloadBytes().begin(), msg.getPayloadBytes().end());
    return out;
}

BootstrapMsg deserialize(const Bytes& in)
{
    size_t pos = 0;
    auto need = [&](size_t size) {
        if (pos + size > in.size()) {
            throw std::runtime_error("bootstrap message truncated (" + std::to_string(in.size()) + " bytes)");
        }
    };
    auto uint = [&](int size) {
        need(size);
        uint64_t value = 0;
        for (int i = 0; i < size; ++i) {
            value = (value << 8) | in[pos++];
        }
        return value;
    };
    auto bytes = [&](size_t size) {
        need(size);
        Bytes out(in.begin() + pos, in.begin() + pos + size);
        pos += size;
        return out;
    };
    auto string = [&]() {
        const Bytes s = bytes(uint(2));
        return std::string(s.begin(), s.end());
    };

    BootstrapMsg msg;
    msg.setType(static_cast<int>(uint(1)));
    msg.setSeqNum(static_cast<int32_t>(uint(4)));
    msg.setAckNum(static_cast<int32_t>(uint(4)));
    msg.setSender(string());
    msg.setDestination(string());
    msg.setVehicle(string());
    msg.setPayloadBytes(bytes(uint(4)));
    return msg;
}
