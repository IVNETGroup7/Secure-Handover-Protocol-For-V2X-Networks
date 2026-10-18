#include "RawSocket.h"
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>

static_assert(kMaxFrameData == ETH_DATA_LEN - 2, "RawSocket.h: the Ethernet payload minus len(data)");

static std::runtime_error systemError(const std::string& what)
{
    std::string text = what + ": " + std::strerror(errno);
    if (errno == EPERM || errno == EACCES) {
        text += " (raw sockets need CAP_NET_RAW: run it with 'make', in a container)";
    }
    return std::runtime_error(text);
}

RawSocket::RawSocket(const std::string& iface, uint16_t etherType) : mEtherType(etherType)
{
    mIfindex = if_nametoindex(iface.c_str());
    if (mIfindex == 0) {
        throw systemError("interface '" + iface + "'");
    }

    mFd = socket(AF_PACKET, SOCK_RAW, htons(etherType));
    if (mFd < 0) {
        throw systemError("raw socket");
    }

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(mFd, SIOCGIFHWADDR, &ifr) < 0) {
        const auto error = systemError("MAC address of '" + iface + "'");
        close(mFd);
        throw error;
    }
    std::memcpy(mMac.data(), ifr.ifr_hwaddr.sa_data, mMac.size());

    // only frames of this EtherType on this interface
    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(etherType);
    addr.sll_ifindex = mIfindex;
    if (bind(mFd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        const auto error = systemError("bind to '" + iface + "'");
        close(mFd);
        throw error;
    }
}

RawSocket::~RawSocket()
{
    if (mFd >= 0) {
        close(mFd);
    }
}

void RawSocket::send(const Bytes& data)
{
    if (data.size() > kMaxFrameData) {
        throw std::runtime_error("raw frame too large (" + std::to_string(data.size()) + " bytes)");
    }

    Bytes frame(ETH_HLEN);
    std::memset(frame.data(), 0xff, ETH_ALEN);                      // destination: broadcast
    std::memcpy(frame.data() + ETH_ALEN, mMac.data(), ETH_ALEN);    // source
    frame[12] = static_cast<uint8_t>(mEtherType >> 8);
    frame[13] = static_cast<uint8_t>(mEtherType);
    frame.push_back(static_cast<uint8_t>(data.size() >> 8));        // NICs may pad short frames
    frame.push_back(static_cast<uint8_t>(data.size()));
    frame.insert(frame.end(), data.begin(), data.end());

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(mEtherType);
    addr.sll_ifindex = mIfindex;
    addr.sll_halen = ETH_ALEN;
    std::memset(addr.sll_addr, 0xff, ETH_ALEN);

    ssize_t n;
    do {
        n = sendto(mFd, frame.data(), frame.size(), 0, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    } while (n < 0 && errno == EINTR);
    if (n != static_cast<ssize_t>(frame.size())) {
        throw systemError("raw send");
    }
}

std::optional<Bytes> RawSocket::receive()
{
    uint8_t buffer[ETH_FRAME_LEN + 64];
    while (true) {
        sockaddr_ll from{};
        socklen_t fromLength = sizeof(from);
        const ssize_t n = recvfrom(mFd, buffer, sizeof(buffer), MSG_DONTWAIT,
            reinterpret_cast<sockaddr*>(&from), &fromLength);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return std::nullopt;
            }
            throw systemError("raw receive");
        }
        if (from.sll_pkttype == PACKET_OUTGOING || n < ETH_HLEN + 2) {
            continue; // our own frame on its way out, or not ours
        }
        const size_t size = (static_cast<size_t>(buffer[ETH_HLEN]) << 8) | buffer[ETH_HLEN + 1];
        if (ETH_HLEN + 2 + size > static_cast<size_t>(n)) {
            continue; // truncated
        }
        return Bytes(buffer + ETH_HLEN + 2, buffer + ETH_HLEN + 2 + size);
    }
}
