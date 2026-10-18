#include "packet_queue.h"

void PacketQueue::push(Bytes packet)
{
    std::lock_guard<std::mutex> lock(mMutex);
    mPackets.push(std::move(packet));
}

std::optional<Bytes> PacketQueue::pop()
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (mPackets.empty()) {
        return std::nullopt;
    }
    Bytes packet = std::move(mPackets.front());
    mPackets.pop();
    return packet;
}

size_t PacketQueue::size() const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mPackets.size();
}
