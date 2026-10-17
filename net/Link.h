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

#include "BootstrapMsg.h"
#include "RawSocket.h"
#include <chrono>
#include <functional>
#include <initializer_list>
#include <string>

enum class FrameKind : uint8_t { Bootstrap = 0, Session_Hello = 1, Session_Ack = 2 };

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

// fork mode: tells the parent this node is ready (fd < 0: nobody waits)
void signalReady(int fd);

#endif /* BOOTSTRAP_LINK_H_ */
