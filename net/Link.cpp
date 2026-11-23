#include "Link.h"
#include "WireCodec.h"
#include <poll.h>
#include <algorithm>
#include <random>
#include <stdexcept>
#include <vector>

void sendFrame(RawSocket& link, FrameKind kind, const Bytes& body)
{
    Bytes data{ static_cast<uint8_t>(kind) };
    data.insert(data.end(), body.begin(), body.end());
    link.send(data);
}

void sendMsg(RawSocket& link, const ProtocolMsg& msg)
{
    sendFrame(link, FrameKind::Protocol, serialize(msg));
}

Bytes toBytes(const std::string& text)
{
    return Bytes(text.begin(), text.end());
}

void waitFor(std::initializer_list<const RawSocket*> links, int timeoutMs)
{
    std::vector<pollfd> fds;
    for (const RawSocket* link : links) {
        fds.push_back({ link->fd(), POLLIN, 0 });
    }
    poll(fds.data(), fds.size(), timeoutMs);
}

Bytes packSessionHello(const std::string& rsu, const Bytes& gatewayPublicKey)
{
    Bytes out;
    wire_codec::putString(out, rsu);
    wire_codec::putBytes(out, gatewayPublicKey);
    return out;
}

std::optional<SessionHello> parseSessionHello(const Bytes& body)
{
    try {
        wire_codec::Reader r(body, "Session_Hello");
        SessionHello hello;
        hello.rsu = r.str();
        hello.gatewayPublicKey = r.field();
        if (hello.rsu.empty() || hello.gatewayPublicKey.empty()) {
            return std::nullopt;
        }
        // Validate that gatewayPublicKey parses as a valid public key
        publicKeyFromDer(hello.gatewayPublicKey);
        return hello;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

Bytes packSessionAck(const std::string& rsu, const Bytes& caPublicKey, const Bytes& gatewayCert, const Bytes& esaCert,
    OtpAlgo otpAlgo)
{
    Bytes out;
    wire_codec::putString(out, rsu);
    wire_codec::putBytes(out, caPublicKey);
    wire_codec::putBytes(out, gatewayCert);
    wire_codec::putBytes(out, esaCert);
    wire_codec::putUint(out, static_cast<uint8_t>(otpAlgo), 1);
    return out;
}

std::optional<SessionAck> parseSessionAck(const Bytes& body)
{
    try {
        wire_codec::Reader r(body, "Session_Ack");
        SessionAck ack;
        ack.rsu = r.str();
        ack.caPublicKey = r.field();
        ack.gatewayCert = r.field();
        ack.esaCert = r.field();
        const uint64_t algo = r.uint(1);
        if (ack.rsu.empty() || ack.caPublicKey.empty() || ack.gatewayCert.empty() || ack.esaCert.empty()
            || algo > static_cast<uint64_t>(OtpAlgo::Ascon)) {
            return std::nullopt;
        }
        ack.otpAlgo = static_cast<OtpAlgo>(algo);
        return ack;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

Bytes packPeerCert(const std::string& destRsu, const std::string& peerName, const Bytes& peerCertDer)
{
    Bytes out;
    wire_codec::putString(out, destRsu);
    wire_codec::putString(out, peerName);
    wire_codec::putBytes(out, peerCertDer);
    return out;
}

std::optional<PeerCertFrame> parsePeerCert(const Bytes& body)
{
    try {
        wire_codec::Reader r(body, "Peer_Cert");
        PeerCertFrame pc;
        pc.destRsu = r.str();
        pc.peerName = r.str();
        pc.peerCertDer = r.field();
        if (pc.destRsu.empty() || pc.peerName.empty() || pc.peerCertDer.empty()) {
            return std::nullopt;
        }
        return pc;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

Bytes packPeerCertAck(const std::string& destRsu, const std::string& peerName)
{
    Bytes out;
    wire_codec::putString(out, destRsu);
    wire_codec::putString(out, peerName);
    return out;
}

std::optional<PeerCertAck> parsePeerCertAck(const Bytes& body)
{
    try {
        wire_codec::Reader r(body, "Peer_Cert_Ack");
        PeerCertAck ack;
        ack.destRsu = r.str();
        ack.peerName = r.str();
        if (ack.destRsu.empty() || ack.peerName.empty()) {
            return std::nullopt;
        }
        return ack;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

SessionAck openHttpsSession(RawSocket& backhaul, const std::string& rsu, const Bytes& gatewayPublicKey,
    const std::string& iface, const std::function<bool()>& stop, std::chrono::seconds timeout)
{
    const Bytes hello = packSessionHello(rsu, gatewayPublicKey);
    const auto giveUp = std::chrono::steady_clock::now() + timeout;
    auto lastSent = std::chrono::steady_clock::time_point::min();
    std::optional<SessionAck> result;
    while (!result) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= giveUp || (stop && stop())) {
            throw std::runtime_error("no Session_Ack from the ESA (is it running on " + iface + "?)");
        }
        if (lastSent == std::chrono::steady_clock::time_point::min() || now - lastSent >= kSessionRetry) {
            sendFrame(backhaul, FrameKind::Session_Hello, hello);
            lastSent = now;
        }
        const auto nextSend = lastSent + kSessionRetry;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(nextSend - now).count();
        const int waitMs = static_cast<int>(std::clamp<long long>(remaining, 1,
            std::chrono::duration_cast<std::chrono::milliseconds>(kSessionRetry).count()));
        waitFor({ &backhaul }, waitMs);
        drain(backhaul, [&](FrameKind kind, const Bytes& body) {
            if (!result && kind == FrameKind::Session_Ack) {
                if (auto ack = parseSessionAck(body); ack && ack->rsu == rsu) {
                    backhaul.setPeerMac(backhaul.lastSrcMac());
                    result = std::move(*ack);
                }
            }
        });
    }
    return *result;
}

Bytes packClockAnchor(int64_t simTimeNs)
{
    Bytes out(8);
    const uint64_t raw = static_cast<uint64_t>(simTimeNs);
    for (int i = 0; i < 8; ++i) {
        out[static_cast<size_t>(7 - i)] = static_cast<uint8_t>(raw >> (8 * i));
    }
    return out;
}

std::optional<int64_t> parseClockAnchor(const Bytes& body)
{
    if (body.size() != 8) {
        return std::nullopt;
    }
    uint64_t raw = 0;
    for (uint8_t b : body) {
        raw = (raw << 8) | b;
    }
    return static_cast<int64_t>(raw);
}

std::optional<std::string> parseRsuTag(const Bytes& body)
{
    const auto end = std::find(body.begin(), body.end(), '\n');
    if (end == body.end()) {
        return std::nullopt;
    }
    return std::string(body.begin(), end);
}

namespace
{

constexpr auto kReassemblyTimeout = std::chrono::seconds(2);   // a piece this late is taken as lost

void putUint(Bytes& out, uint32_t value, int size)
{
    for (int i = size - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

void putName(Bytes& out, const std::string& name)
{
    if (name.size() > 255) {
        throw std::runtime_error("node name longer than 255 bytes: " + name);
    }
    out.push_back(static_cast<uint8_t>(name.size()));
    out.insert(out.end(), name.begin(), name.end());
}

} // namespace

size_t sendData(RawSocket& link, const std::string& from, const std::string& to, const Bytes& packet)
{
    static uint32_t nextId = std::random_device()();     // per process: a restarted sender does not collide

    Bytes header;
    putName(header, from);
    putName(header, to);
    const size_t room = kMaxFrameData - 1 - header.size() - 8; // kind, header, id, index, count
    const size_t count = std::max<size_t>(1, (packet.size() + room - 1) / room);
    if (count > 0xFFFF) {
        throw std::runtime_error("data packet too large for the fragment header");
    }

    const uint32_t id = nextId++;
    for (size_t index = 0; index < count; ++index) {
        Bytes body = header;
        putUint(body, id, 4);
        putUint(body, static_cast<uint32_t>(index), 2);
        putUint(body, static_cast<uint32_t>(count), 2);
        const size_t start = index * room;
        const size_t end = std::min(packet.size(), start + room);
        body.insert(body.end(), packet.begin() + start, packet.begin() + end);
        sendFrame(link, FrameKind::Data_Fragment, body);
    }
    return count;
}

std::optional<Reassembler::Packet> Reassembler::add(const Bytes& body)
{
    const auto now = std::chrono::steady_clock::now();
    for (auto partial = mPartials.begin(); partial != mPartials.end();) {
        if (now - partial->second.started > kReassemblyTimeout) {
            partial = mPartials.erase(partial);
            ++mDropped;
        } else {
            ++partial;
        }
    }

    // len | from | len | to | id (4) | index (2) | count (2) | piece
    size_t pos = 0;
    auto name = [&]() -> std::optional<std::string> {
        if (pos >= body.size() || body.size() - pos - 1 < body[pos]) {
            return std::nullopt;
        }
        std::string text(body.begin() + pos + 1, body.begin() + pos + 1 + body[pos]);
        pos += 1 + body[pos];
        return text;
    };
    const auto from = name();
    const auto to = name();
    if (!from || !to || body.size() - pos < 8) {
        return std::nullopt; // not a fragment of ours (another program on the link)
    }
    auto uint = [&](int size) {
        uint32_t value = 0;
        for (int i = 0; i < size; ++i) {
            value = (value << 8) | body[pos++];
        }
        return value;
    };
    const uint32_t id = uint(4);
    const size_t index = uint(2);
    const size_t count = uint(2);
    if (count == 0 || index >= count) {
        return std::nullopt;
    }

    Partial& partial = mPartials[{ *from, id }];
    if (partial.pieces.empty()) {
        partial.to = *to;
        partial.pieces.resize(count);
        partial.have.resize(count);
        partial.started = now;
    }
    if (partial.pieces.size() != count || partial.have[index]) {
        return std::nullopt; // inconsistent or repeated piece
    }
    partial.pieces[index].assign(body.begin() + pos, body.end());
    partial.have[index] = true;
    if (++partial.received < count) {
        return std::nullopt;
    }

    Packet packet{ *from, partial.to, {} };
    for (const Bytes& piece : partial.pieces) {
        packet.bytes.insert(packet.bytes.end(), piece.begin(), piece.end());
    }
    mPartials.erase({ *from, id });
    return packet;
}
