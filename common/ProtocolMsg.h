#ifndef COMMON_PROTOCOLMSG_H_
#define COMMON_PROTOCOLMSG_H_

// Protocol message envelope exchanged between Vehicle, RSU, and ESA across all phases
// (initial bootstrap, Secrecy Forwarding handover, and authenticated telemetry).

#include "Crypto.h"
#include "MessageType.h"
#include <string>

class ProtocolMsg
{
    public:
        int getType() const { return mType; }
        const std::string& getSender() const { return mSender; }
        const std::string& getDestination() const { return mDestination; }
        const std::string& getVehicle() const { return mVehicle; }
        int getSeqNum() const { return mSeqNum; }
        int getAckNum() const { return mAckNum; }
        const Bytes& getPayloadBytes() const { return mPayload; }

        void setType(int type) { mType = type; }
        void setSender(const std::string& sender) { mSender = sender; }
        void setDestination(const std::string& destination) { mDestination = destination; }
        void setVehicle(const std::string& vehicle) { mVehicle = vehicle; }
        void setSeqNum(int seqNum) { mSeqNum = seqNum; }
        void setAckNum(int ackNum) { mAckNum = ackNum; }
        void setPayloadBytes(const Bytes& payload) { mPayload = payload; }

    private:
        int mType = 0;
        std::string mSender;
        std::string mDestination;
        std::string mVehicle;
        int mSeqNum = 0;
        int mAckNum = 0;
        Bytes mPayload;
};

inline void setPayload(ProtocolMsg& msg, const Bytes& payload)
{
    msg.setPayloadBytes(payload);
}

inline Bytes getPayload(const ProtocolMsg& msg)
{
    return msg.getPayloadBytes();
}

Bytes serialize(const ProtocolMsg&);
ProtocolMsg deserialize(const Bytes&);   // throws std::runtime_error if truncated

#endif /* COMMON_PROTOCOLMSG_H_ */

