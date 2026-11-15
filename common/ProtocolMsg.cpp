#include "ProtocolMsg.h"
#include "WireCodec.h"

Bytes serialize(const ProtocolMsg& msg)
{
    Bytes out;
    wire_codec::putUint(out, msg.getType(), 1);
    wire_codec::putUint(out, static_cast<uint32_t>(msg.getSeqNum()), 4);
    wire_codec::putUint(out, static_cast<uint32_t>(msg.getAckNum()), 4);
    wire_codec::putString(out, msg.getSender());
    wire_codec::putString(out, msg.getDestination());
    wire_codec::putString(out, msg.getVehicle());
    wire_codec::putUint(out, msg.getPayloadBytes().size(), 4);
    out.insert(out.end(), msg.getPayloadBytes().begin(), msg.getPayloadBytes().end());
    return out;
}

ProtocolMsg deserialize(const Bytes& in)
{
    wire_codec::Reader reader(in, "protocol message");
    ProtocolMsg msg;
    msg.setType(static_cast<int>(reader.uint(1)));
    msg.setSeqNum(static_cast<int32_t>(reader.uint(4)));
    msg.setAckNum(static_cast<int32_t>(reader.uint(4)));
    msg.setSender(reader.str());
    msg.setDestination(reader.str());
    msg.setVehicle(reader.str());
    msg.setPayloadBytes(reader.bytes(static_cast<size_t>(reader.uint(4))));
    return msg;
}

