#ifndef TEE_V2X_V2XFRAME_H_
#define TEE_V2X_V2XFRAME_H_

// A ProtocolMsg (common/ProtocolMsg.h) as an OMNeT++ packet: its wire format (serialize), the same bytes as on the
// raw sockets of the repository, carried by BackhaulBroker over the delayed IT backhaul channel.

#include "MessageType.h"
#include "ProtocolMsg.h"
#include <omnetpp/cpacket.h>
#include <utility>

class V2xFrame : public omnetpp::cPacket
{
    public:
        explicit V2xFrame(const ProtocolMsg& msg) :
            omnetpp::cPacket(messageTypeName(msg.getType())), mBytes(serialize(msg))
        {
            setByteLength(static_cast<int64_t>(mBytes.size()));
        }
        V2xFrame(const V2xFrame&) = default;
        V2xFrame* dup() const override { return new V2xFrame(*this); }

        // throws std::runtime_error on a truncated frame
        ProtocolMsg msg() const { return deserialize(mBytes); }

    private:
        Bytes mBytes;
};

#endif /* TEE_V2X_V2XFRAME_H_ */
