#ifndef BOOTSTRAP_RAWSOCKET_H_
#define BOOTSTRAP_RAWSOCKET_H_

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

        // broadcasts data in one frame; throws std::runtime_error (e.g. data larger than the frame)
        void send(const Bytes& data);

        // next frame received from the interface (non-blocking): nullopt when there is none left.
        // the copy of our own outgoing frames is skipped (the loopback copy still arrives, as on a radio)
        std::optional<Bytes> receive();

    private:
        int mFd = -1;
        int mIfindex = 0;
        uint16_t mEtherType;
        std::array<uint8_t, 6> mMac{};
};

#endif /* BOOTSTRAP_RAWSOCKET_H_ */
