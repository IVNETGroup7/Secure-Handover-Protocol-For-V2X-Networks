#ifndef BOOTSTRAP_BOOTSTRAPMSG_H_
#define BOOTSTRAP_BOOTSTRAPMSG_H_

// Bootstrap message exchanged by vehicle, RSU and ESA (replaces BootstrapMsg.msg)

#include "BootstrapType.h"
#include "Crypto.h"
#include <string>

class BootstrapMsg
{
    public:
        int getType() const { return mType; }
        const std::string& getSender() const { return mSender; }
        const std::string& getDestination() const { return mDestination; }
        const std::string& getVehicle() const { return mVehicle; }
        int getSeqNum() const { return mSeqNum; }
        int getAckNum() const { return mAckNum; }
        const Bytes& getPayloadBytes() const { return mPayload; }   // step data, see BootstrapPayload.h

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

// wire format (e.g. for a socket), integers in big endian:
//   type (1) | seqNum (4) | ackNum (4) | len(sender) (2) | sender | len(destination) (2) | destination
//   | len(vehicle) (2) | vehicle | len(payload) (4) | payload
Bytes serialize(const BootstrapMsg&);
BootstrapMsg deserialize(const Bytes&);   // throws std::runtime_error if truncated

#endif /* BOOTSTRAP_BOOTSTRAPMSG_H_ */
