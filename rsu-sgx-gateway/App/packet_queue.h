#ifndef PACKET_QUEUE_H_
#define PACKET_QUEUE_H_

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
using Clock = std::chrono::steady_clock;

// from the radio: a bootstrap message (BootstrapMsg) or a data packet (SmartData.h, reassembled)
struct OtPacket
{
    enum class Kind { Bootstrap, SmartData };
    Kind kind;
    std::string from;           // the vehicle (data packets; bootstrap messages carry their own sender)
    Bytes bytes;
    Clock::time_point received; // when the whole packet was in: start of its turn-around time
};

// to the backhaul: a bootstrap message for the ESA, or the marshaled SmartData for the cloud
struct ItPacket
{
    enum class To { Esa, Cloud };
    To to;
    std::string vehicle;        // whose data (cloud)
    Bytes bytes;
    Clock::time_point received; // of the OT packet it came from (cloud)
    size_t otSize = 0;          // size of that OT packet (cloud: the benchmark's row)
    bool traced = false;        // its OT packet was traced: trace the POST too
};

template<typename Packet>
class PacketQueue
{
    public:
        void push(Packet packet)
        {
            std::lock_guard<std::mutex> lock(mMutex);
            mPackets.push(std::move(packet));
        }

        // nullopt when empty
        std::optional<Packet> pop()
        {
            std::lock_guard<std::mutex> lock(mMutex);
            if (mPackets.empty()) {
                return std::nullopt;
            }
            Packet packet = std::move(mPackets.front());
            mPackets.pop();
            return packet;
        }

    private:
        std::mutex mMutex;
        std::queue<Packet> mPackets;
};

#endif /* PACKET_QUEUE_H_ */
