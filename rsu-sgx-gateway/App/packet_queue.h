#ifndef PACKET_QUEUE_H_
#define PACKET_QUEUE_H_

// OT queue (frames from the V2X side) and IT queue (packets to the ESA / cloud): thread-safe FIFOs of bytes

#include <cstdint>
#include <mutex>
#include <optional>
#include <queue>
#include <vector>

using Bytes = std::vector<uint8_t>;

class PacketQueue
{
    public:
        void push(Bytes packet);
        std::optional<Bytes> pop();     // nullopt when empty
        size_t size() const;

    private:
        mutable std::mutex mMutex;
        std::queue<Bytes> mPackets;
};

#endif /* PACKET_QUEUE_H_ */
