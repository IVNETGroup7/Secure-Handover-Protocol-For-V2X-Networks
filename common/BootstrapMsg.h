#ifndef BOOTSTRAP_BOOTSTRAPMSG_H_
#define BOOTSTRAP_BOOTSTRAPMSG_H_

// Bootstrap message exchanged by vehicle, RSU and ESA (replaces BootstrapMsg.msg)

#include "Crypto.h"
#include <string>

enum BootstrapType
{
    Activation_Request = 0,
    HTTPS_Session = 1,
    Activation_Token = 2,
    PTP = 3,
    ECDH_Request = 4,
    ECDH_Response = 5,
    Auth_Request = 6,
    Save_RSU = 7,
    Auth_Granted = 8,
    Save_Vehicle = 9,
    Active_01 = 10,
    Active_02 = 11,
    Active_03 = 12,
    PTP_Sync = 13,
    PTP_Delay_Request = 14,
    PTP_Delay_Response = 15,
};

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
