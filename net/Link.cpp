#include "Link.h"
#include <poll.h>
#include <unistd.h>
#include <algorithm>
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

Bytes openHttpsSession(RawSocket& backhaul, const std::string& rsu, const std::string& sessionKey,
    const std::string& iface, const std::function<bool()>& stop)
{
    const auto giveUp = std::chrono::steady_clock::now() + kSessionTimeout;
    const Bytes name = toBytes(rsu + "\n");
    Bytes esaPublicKey;
    while (esaPublicKey.empty()) {
        if (std::chrono::steady_clock::now() >= giveUp || (stop && stop())) {
            throw std::runtime_error("no Session_Ack from the ESA (is it running on " + iface + "?)");
        }
        sendFrame(backhaul, FrameKind::Session_Hello, toBytes(rsu + "\n" + sessionKey));
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

void signalReady(int fd)
{
    if (fd >= 0) {
        const char ready = 1;
        if (write(fd, &ready, 1) != 1) {
            throw std::runtime_error("cannot signal readiness");
        }
        close(fd);
    }
}
