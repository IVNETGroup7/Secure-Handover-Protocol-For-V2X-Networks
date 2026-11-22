#ifndef NET_RAWSOCKET_H_
#define NET_RAWSOCKET_H_

#include "Crypto.h"
#include <array>
#include <cstdint>
#include <optional>
#include <string>

// IEEE 802 "local experimental" EtherTypes
constexpr uint16_t kRadioEtherType = 0x88B5;     // vehicle <-> RSU (radio)
constexpr uint16_t kBackhaulEtherType = 0x88B6;  // RSU <-> ESA (HTTPS session)

// most data one frame carries: the Ethernet payload of the usual MTU (1500) minus len(data), so the frames
// also fit a real (or virtual) NIC; larger packets go in fragments (Link.h)
constexpr size_t kMaxFrameData = 1500 - 2;

class RawSocket
{
    public:
        // binds to "etherType" frames on "iface" (e.g. "lo"); throws std::runtime_error
        RawSocket(const std::string& iface, uint16_t etherType);
        ~RawSocket();
        RawSocket(const RawSocket&) = delete;
        RawSocket& operator=(const RawSocket&) = delete;

        int fd() const { return mFd; }

        // broadcasts data in one frame (or sends unicast once peerMac is pinned); throws std::runtime_error
        void send(const Bytes& data);

        // next frame received from the interface (non-blocking): nullopt when there is none left.
        // the copy of our own outgoing frames is skipped (the loopback copy still arrives, as on a radio)
        std::optional<Bytes> receive();

        const std::array<uint8_t, 6>& lastSrcMac() const { return mLastSrcMac; }
        const std::array<uint8_t, 6>& peerMac() const { return mDstMac; }
        void setPeerMac(const std::array<uint8_t, 6>& mac);

    private:
        int mFd = -1;
        int mIfindex = 0;
        uint16_t mEtherType;
        std::array<uint8_t, 6> mMac{};
        std::array<uint8_t, 6> mDstMac{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        std::array<uint8_t, 6> mLastSrcMac{};
};

#endif /* NET_RAWSOCKET_H_ */
