#ifndef NET_LINK_H_
#define NET_LINK_H_

#include "Otp.h"
#include "ProtocolMsg.h"
#include "RawSocket.h"
#include <chrono>
#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

enum class FrameKind : uint8_t {
    Protocol = 0,
    Session_Hello = 1,
    Session_Ack = 2,
    Data_Fragment = 3,
    Clock_Anchor = 5,
    Cloud_Ready = 6,
    Cloud_Refused = 7,
    Peer_Cert = 8,
    Peer_Cert_Ack = 9
};

constexpr auto kSessionTimeout = std::chrono::seconds(5);         // RSU: waiting for the ESA's Session_Ack
constexpr auto kSessionRetry = std::chrono::milliseconds(500);    // RSU: Session_Hello period
constexpr int kPollPeriodMs = 100;                                // loops check their stop flag at least this often

void sendFrame(RawSocket& link, FrameKind kind, const Bytes& body);
void sendMsg(RawSocket& link, const ProtocolMsg& msg);
Bytes toBytes(const std::string& text);

Bytes packClockAnchor(int64_t simTimeNs);
std::optional<int64_t> parseClockAnchor(const Bytes& body);
std::optional<std::string> parseRsuTag(const Bytes& body);

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

// Backhaul CA-authenticated session handshake frames (Step 2 in HIL mode):
//   RSU -> Backhaul: Session_Hello { rsuName, gatewayPublicKey (Y_gw generated inside TEE) }
//   Backhaul -> RSU: Session_Ack   { rsuName, caPublicKey, gatewayCert (CA-signed), esaCert (CA-signed) }
struct SessionHello
{
    std::string rsu;
    Bytes gatewayPublicKey;         // Y_gw (91-byte P-256 DER SPKI generated inside RSU TA)
};

struct SessionAck
{
    std::string rsu;
    Bytes caPublicKey;              // Root CA public key (DER SPKI)
    Bytes gatewayCert;              // CA-signed Gateway X.509 certificate (DER)
    Bytes esaCert;                  // CA-signed ESA X.509 certificate (DER)
    OtpAlgo otpAlgo = OtpAlgo::Ascon; // Active OTP/MAC algorithm for the session (never mixed)
};

Bytes packSessionHello(const std::string& rsu, const Bytes& gatewayPublicKey);
std::optional<SessionHello> parseSessionHello(const Bytes& body);
Bytes packSessionAck(const std::string& rsu, const Bytes& caPublicKey, const Bytes& gatewayCert, const Bytes& esaCert,
    OtpAlgo otpAlgo = otpAlgorithm());
std::optional<SessionAck> parseSessionAck(const Bytes& body);

struct PeerCertFrame
{
    std::string destRsu;
    std::string peerName;
    Bytes peerCertDer;
};

struct PeerCertAck
{
    std::string destRsu;
    std::string peerName;
};

Bytes packPeerCert(const std::string& destRsu, const std::string& peerName, const Bytes& peerCertDer);
std::optional<PeerCertFrame> parsePeerCert(const Bytes& body);
Bytes packPeerCertAck(const std::string& destRsu, const std::string& peerName);
std::optional<PeerCertAck> parsePeerCertAck(const Bytes& body);

// RSU side of the CA-authenticated HTTPS session setup with the ESA:
// Sends Session_Hello (carrying TEE-generated Y_gw) until receiving matching Session_Ack.
// Throws std::runtime_error after timeout or when stop() is true.
SessionAck openHttpsSession(RawSocket& backhaul, const std::string& rsu, const Bytes& gatewayPublicKey,
    const std::string& iface, const std::function<bool()>& stop,
    std::chrono::seconds timeout = kSessionTimeout);

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

#endif /* NET_LINK_H_ */
