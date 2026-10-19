#ifndef TEE_V2X_V2XFRAME_H_
#define TEE_V2X_V2XFRAME_H_

// A BootstrapMsg (common/BootstrapMsg.h) as an OMNeT++ packet: its wire format (serialize), the same bytes as on the
// raw sockets of the repository, so Vanetza carries it over ITS-G5 (BTP port 2025) and BackhaulBroker over the
// backhaul. Its byte length is the real one: the radio's airtime follows the protocol's real message sizes.

#include "BootstrapMsg.h"
#include "BootstrapService.h"
#include <omnetpp/cpacket.h>
#include <utility>

class V2xFrame : public omnetpp::cPacket
{
    public:
        explicit V2xFrame(const BootstrapMsg& msg) :
            omnetpp::cPacket(stageName(msg.getType())), mBytes(serialize(msg))
        {
            setByteLength(static_cast<int64_t>(mBytes.size()));
        }
        V2xFrame(const V2xFrame&) = default;
        V2xFrame* dup() const override { return new V2xFrame(*this); }

        // throws std::runtime_error on a truncated frame
        BootstrapMsg msg() const { return deserialize(mBytes); }

    private:
        Bytes mBytes;
};

#endif /* TEE_V2X_V2XFRAME_H_ */
