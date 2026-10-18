#include "Link.h"
#include <poll.h>
#include <unistd.h>
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

void sendMsg(RawSocket& link, const BootstrapMsg& msg)
{
    sendFrame(link, FrameKind::Bootstrap, serialize(msg));
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

GatewayCertificate newGatewayCertificate(const std::string& rsu)
{
    GatewayCertificate identity;
    identity.key = newP256Key();
    identity.certificate = selfSignedCertificate(identity.key.get(), rsu);
    identity.publicKey = publicKeyDer(identity.key.get());
    return identity;
}

Bytes openHttpsSession(RawSocket& backhaul, const std::string& rsu, const std::string& sessionKey,
    const Bytes& certificate, const std::string& iface, const std::function<bool()>& stop)
{
    Bytes hello = toBytes(rsu + "\n" + sessionKey + "\n");
    hello.insert(hello.end(), certificate.begin(), certificate.end());
    const auto giveUp = std::chrono::steady_clock::now() + kSessionTimeout;
    const Bytes name = toBytes(rsu + "\n");
    Bytes esaPublicKey;
    while (esaPublicKey.empty()) {
        if (std::chrono::steady_clock::now() >= giveUp || (stop && stop())) {
            throw std::runtime_error("no Session_Ack from the ESA (is it running on " + iface + "?)");
        }
        sendFrame(backhaul, FrameKind::Session_Hello, hello);
        waitFor({ &backhaul }, std::chrono::duration_cast<std::chrono::milliseconds>(kSessionRetry).count());
        drain(backhaul, [&](FrameKind kind, const Bytes& body) {
            // "rsu name\n" CY_e
            if (kind == FrameKind::Session_Ack && body.size() > name.size()
                && std::equal(name.begin(), name.end(), body.begin())) {
                esaPublicKey.assign(body.begin() + name.size(), body.end());
            }
        });
    }
    return esaPublicKey;
}

std::optional<SessionHello> parseSessionHello(const Bytes& body)
{
    // "rsu name\nsession key\n" certificate
    const auto first = std::find(body.begin(), body.end(), '\n');
    const auto second = first == body.end() ? body.end() : std::find(first + 1, body.end(), '\n');
    if (second == body.end()) {
        return std::nullopt;
    }
    const auto key = verifiedCertificateKey(Bytes(second + 1, body.end()));
    if (!key) {
        return std::nullopt;
    }
    return SessionHello{ std::string(body.begin(), first), std::string(first + 1, second), *key };
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

void signalReady(int fd, const Bytes& info)
{
    if (fd >= 0) {
        Bytes data{ 1 };    // ready, then the info (read until the pipe closes)
        data.insert(data.end(), info.begin(), info.end());
        if (write(fd, data.data(), data.size()) != static_cast<ssize_t>(data.size())) {
            throw std::runtime_error("cannot signal readiness");
        }
        close(fd);
    }
}
