#ifndef BOOTSTRAP_LINK_H_
#define BOOTSTRAP_LINK_H_

// What the nodes exchange over the raw sockets (RawSocket.h); shared by main.cpp and the SGX gateway
// (rsu-sgx-gateway), so both speak the same frames.
//
// links: every frame is a broadcast, every node on the link gets it
//   radio     (EtherType 0x88B5)  vehicles and RSUs; each one keeps only what is for it (isForMe)
//   backhaul  (EtherType 0x88B6)  RSUs and ESA: the "HTTPS" session, established by Session_Hello/Session_Ack
//
// data of a frame: kind (1) | body
//   Bootstrap      body = serialize(BootstrapMsg)
//   Session_Hello  body = "rsu name\nsession key"  (RSU -> ESA, repeated until the ack)
//   Session_Ack    body = "rsu name\n" CY_e         (ESA -> RSU; CY_e: ESA public key, DER)
//   Data_Fragment  body = len | from | len | to | id (4) | index (2) | count (2) | piece    (radio)
//                  a data packet larger than one frame (SmartData.h: up to 64 KB), in pieces; to: its RSU

#include "BootstrapMsg.h"
#include "RawSocket.h"
#include <chrono>
#include <functional>
#include <initializer_list>
#include <map>
#include <optional>
#include <string>
#include <utility>

enum class FrameKind : uint8_t { Bootstrap = 0, Session_Hello = 1, Session_Ack = 2, Data_Fragment = 3 };

constexpr auto kSessionTimeout = std::chrono::seconds(5);         // RSU: waiting for the ESA's Session_Ack
constexpr auto kSessionRetry = std::chrono::milliseconds(100);    // RSU: Session_Hello period
constexpr int kPollPeriodMs = 100;                                // loops check their stop flag at least this often

void sendFrame(RawSocket& link, FrameKind kind, const Bytes& body);
void sendMsg(RawSocket& link, const BootstrapMsg& msg);
Bytes toBytes(const std::string& text);

// hands every frame waiting on "link" to onFrame(kind, body)
template<typename OnFrame>
void drain(RawSocket& link, OnFrame onFrame)
{
    while (auto data = link.receive()) {
        if (!data->empty()) {
            onFrame(static_cast<FrameKind>((*data)[0]), Bytes(data->begin() + 1, data->end()));
        }
    }
}

// waits until one of the links has a frame (or timeoutMs passes, or a signal arrives)
void waitFor(std::initializer_list<const RawSocket*> links, int timeoutMs = kPollPeriodMs);

// RSU side of the HTTPS session with the ESA: Session_Hello until its Session_Ack; returns CY_e.
// Throws std::runtime_error after kSessionTimeout, or as soon as stop() is true
Bytes openHttpsSession(RawSocket& backhaul, const std::string& rsu, const std::string& sessionKey,
    const std::string& iface, const std::function<bool()>& stop);

// "packet" from "from" to "to" in Data_Fragment frames (as many as it takes; returns how many);
// throws std::runtime_error
size_t sendData(RawSocket& link, const std::string& from, const std::string& to, const Bytes& packet);

// puts the Data_Fragment frames back together; a packet whose pieces stop arriving is dropped
class Reassembler
{
    public:
        struct Packet
        {
            std::string from;
            std::string to;
            Bytes bytes;
        };

        // the body of one Data_Fragment frame; the whole packet once its last piece arrives
        std::optional<Packet> add(const Bytes& body);
        size_t dropped() const { return mDropped; }     // packets given up (a piece lost)

    private:
        struct Partial
        {
            std::string to;
            std::vector<Bytes> pieces;
            std::vector<bool> have;     // which pieces arrived (a piece may be empty)
            size_t received = 0;
            std::chrono::steady_clock::time_point started;
        };

        std::map<std::pair<std::string, uint32_t>, Partial> mPartials;   // (from, id)
        size_t mDropped = 0;
};

// fork mode: tells the parent this node is ready (fd < 0: nobody waits)
void signalReady(int fd);

#endif /* BOOTSTRAP_LINK_H_ */
