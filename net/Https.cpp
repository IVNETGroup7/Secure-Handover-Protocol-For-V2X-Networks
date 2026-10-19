#include "Https.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>

namespace
{

constexpr int kPollMs = 100;                // the server checks stop() at least this often
constexpr int kClientTimeoutS = 5;          // the client gives up on a silent server
constexpr size_t kMaxHeader = 16 * 1024;
constexpr size_t kMaxBody = 1024 * 1024;

std::runtime_error sslError(const std::string& what)
{
    char text[256] = "no OpenSSL error";
    if (const unsigned long code = ERR_get_error()) {
        ERR_error_string_n(code, text, sizeof(text));
    }
    ERR_clear_error();
    return std::runtime_error(what + ": " + text);
}

std::runtime_error systemError(const std::string& what)
{
    return std::runtime_error(what + ": " + std::strerror(errno));
}

// a write to a peer that closed raises SIGPIPE, which would end the process: write() fails with EPIPE instead
void ignoreSigpipe()
{
    std::signal(SIGPIPE, SIG_IGN);
}

sockaddr_in socketAddress(const std::string& address, uint16_t port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
        throw std::runtime_error("not an IPv4 address: " + address);
    }
    return addr;
}

std::string peerName(const sockaddr_in& addr)
{
    char text[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &addr.sin_addr, text, sizeof(text));
    return std::string(text) + ":" + std::to_string(ntohs(addr.sin_port));
}

// small requests and answers go out at once: with Nagle's algorithm, a request written in two TLS records waits
// for the delayed ACK of the first (about 40 ms)
void noDelay(int fd)
{
    const int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
}

std::string sessionName(SSL* ssl)
{
    return std::string(SSL_get_version(ssl)) + " " + SSL_get_cipher_name(ssl);
}

// self-signed certificate for "address" (subjectAltName IP), valid for one day
std::shared_ptr<X509> selfSigned(EVP_PKEY* key, const std::string& address)
{
    std::shared_ptr<X509> cert(X509_new(), X509_free);
    check(cert != nullptr, "X509_new");
    X509_set_version(cert.get(), 2);
    const Bytes serial = randomBytes(8);
    std::shared_ptr<BIGNUM> number(BN_bin2bn(serial.data(), static_cast<int>(serial.size()), nullptr), BN_free);
    check(number && BN_to_ASN1_INTEGER(number.get(), X509_get_serialNumber(cert.get())), "certificate serial");
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 24 * 3600);
    check(X509_set_pubkey(cert.get(), key) == 1, "X509_set_pubkey");

    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("cloud"), -1, -1, 0);
    check(X509_set_issuer_name(cert.get(), name) == 1, "X509_set_issuer_name");

    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, cert.get(), cert.get(), nullptr, nullptr, 0);
    const std::string altNames = "IP:" + address + ",DNS:localhost";
    for (auto [nid, value] : { std::pair<int, std::string>{ NID_subject_alt_name, altNames },
             { NID_basic_constraints, "critical,CA:TRUE" } }) {
        X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value.c_str());
        check(extension != nullptr && X509_add_ext(cert.get(), extension, -1) == 1, "certificate extension");
        X509_EXTENSION_free(extension);
    }
    check(X509_sign(cert.get(), key, EVP_sha256()) > 0, "X509_sign");
    return cert;
}

// ---------------------------------------------------------------------------------------------
// HTTP/1.1 over an SSL*: requests and responses with a Content-Length body

std::string lower(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return std::tolower(c); });
    return text;
}

std::string trim(const std::string& text)
{
    const size_t start = text.find_first_not_of(" \t");
    const size_t end = text.find_last_not_of(" \t\r");
    return start == std::string::npos ? "" : text.substr(start, end - start + 1);
}

struct Message
{
    std::string startLine;
    std::map<std::string, std::string> headers;
    std::string body;
};

// a whole message from "buffer" (consumed), or nullopt when more bytes are needed
std::optional<Message> parse(std::string& buffer)
{
    const size_t headerEnd = buffer.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        if (buffer.size() > kMaxHeader) {
            throw std::runtime_error("HTTP header too large");
        }
        return std::nullopt;
    }
    Message message;
    size_t lineStart = 0;
    for (size_t lineEnd; lineStart < headerEnd; lineStart = lineEnd + 2) {
        lineEnd = buffer.find("\r\n", lineStart);
        const std::string line = buffer.substr(lineStart, lineEnd - lineStart);
        if (message.startLine.empty()) {
            message.startLine = line;
        } else if (const size_t colon = line.find(':'); colon != std::string::npos) {
            message.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
        }
    }
    size_t length = 0;
    if (auto header = message.headers.find("content-length"); header != message.headers.end()) {
        length = std::stoul(header->second);
    }
    if (length > kMaxBody) {
        throw std::runtime_error("HTTP body too large");
    }
    if (buffer.size() < headerEnd + 4 + length) {
        return std::nullopt;
    }
    message.body = buffer.substr(headerEnd + 4, length);
    buffer.erase(0, headerEnd + 4 + length);
    return message;
}

// reads into "buffer" until a whole message is there; nullopt: the peer closed (or stop() while waiting)
std::optional<Message> readMessage(SSL* ssl, int fd, std::string& buffer, const std::function<bool()>& stop)
{
    while (true) {
        if (auto message = parse(buffer)) {
            return message;
        }
        if (stop && SSL_pending(ssl) == 0) {
            pollfd wait{ fd, POLLIN, 0 };
            while (poll(&wait, 1, kPollMs) == 0) {
                if (stop()) {
                    return std::nullopt;
                }
            }
        }
        char chunk[16 * 1024];
        const int n = SSL_read(ssl, chunk, sizeof(chunk));
        if (n <= 0) {
            const int error = SSL_get_error(ssl, n);
            if (error == SSL_ERROR_ZERO_RETURN || (error == SSL_ERROR_SYSCALL && (errno == 0 || errno == ECONNRESET))) {
                ERR_clear_error();
                return std::nullopt; // closed
            }
            if (error == SSL_ERROR_SYSCALL && errno == EINTR && stop && stop()) {
                return std::nullopt;
            }
            if (error == SSL_ERROR_SYSCALL && errno != 0) {
                throw systemError("TLS read"); // e.g. EAGAIN: the client's receive timeout
            }
            throw sslError("TLS read");
        }
        buffer.append(chunk, static_cast<size_t>(n));
    }
}

void writeAll(SSL* ssl, const std::string& data)
{
    size_t written = 0;
    if (SSL_write_ex(ssl, data.data(), data.size(), &written) != 1 || written != data.size()) {
        throw sslError("TLS write");
    }
}

} 
std::string CloudIdentity::pem() const
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_X509(bio.get(), certificate.get()) != 1) {
        throw sslError("PEM_write_bio_X509");
    }
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<size_t>(size));
}

CloudIdentity newCloudIdentity(const std::string& address)
{
    CloudIdentity identity;
    identity.key = newP256Key();
    identity.certificate = selfSigned(identity.key.get(), address);
    return identity;
}

HttpsServer::HttpsServer(const std::string& address, uint16_t port, const CloudIdentity& identity)
{
    ignoreSigpipe();
    mContext = SSL_CTX_new(TLS_server_method());
    if (!mContext || SSL_CTX_set_min_proto_version(mContext, TLS1_2_VERSION) != 1
        || SSL_CTX_use_certificate(mContext, identity.certificate.get()) != 1
        || SSL_CTX_use_PrivateKey(mContext, identity.key.get()) != 1) {
        throw sslError("TLS server context");
    }

    mListen = socket(AF_INET, SOCK_STREAM, 0);
    if (mListen < 0) {
        throw systemError("socket");
    }
    const int yes = 1;
    setsockopt(mListen, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    const sockaddr_in addr = socketAddress(address, port);
    if (bind(mListen, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0 || listen(mListen, 4) < 0) {
        const auto error = systemError("listen on " + address + ":" + std::to_string(port));
        ::close(mListen);
        SSL_CTX_free(mContext);
        throw error;
    }
}

HttpsServer::~HttpsServer()
{
    if (mListen >= 0) {
        ::close(mListen);
    }
    SSL_CTX_free(mContext);
}

void HttpsServer::serve(const Handler& handler, const std::function<void(const std::string&, const std::string&)>& onSession,
    const std::function<bool()>& stop)
{
    while (!stop()) {
        pollfd wait{ mListen, POLLIN, 0 };
        if (poll(&wait, 1, kPollMs) <= 0) {
            continue;
        }
        sockaddr_in from{};
        socklen_t length = sizeof(from);
        const int fd = accept(mListen, reinterpret_cast<sockaddr*>(&from), &length);
        if (fd < 0) {
            continue;
        }
        const std::string peer = peerName(from);
        noDelay(fd);
        SSL* ssl = SSL_new(mContext);
        SSL_set_fd(ssl, fd);
        try {
            if (SSL_accept(ssl) != 1) {
                throw sslError("TLS handshake with " + peer);
            }
            if (onSession) {
                onSession(peer, sessionName(ssl));
            }
            std::string buffer;
            bool keepAlive = true;
            while (keepAlive) {
                const auto message = readMessage(ssl, fd, buffer, stop);
                if (!message) {
                    break;
                }
                HttpRequest request;
                const size_t space = message->startLine.find(' ');
                request.method = message->startLine.substr(0, space);
                request.path = message->startLine.substr(space + 1, message->startLine.find(' ', space + 1) - space - 1);
                request.headers = message->headers;
                request.body = message->body;
                keepAlive = lower(request.headers["connection"]) != "close";

                const HttpResponse response = handler(request, peer);
                writeAll(ssl, "HTTP/1.1 " + std::to_string(response.status) + " " + response.reason + "\r\n"
                    + "Content-Type: " + response.contentType + "\r\n"
                    + "Content-Length: " + std::to_string(response.body.size()) + "\r\n"
                    + (keepAlive ? "" : "Connection: close\r\n") + "\r\n" + response.body);
            }
            SSL_shutdown(ssl);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[cloud] %s\n", e.what());
        }
        SSL_free(ssl);
        ::close(fd);
    }
}

HttpsClient::HttpsClient(const std::string& address, uint16_t port, const std::string& trustedPem) :
    mAddress(address), mPort(port)
{
    ignoreSigpipe();
    mContext = SSL_CTX_new(TLS_client_method());
    if (!mContext || SSL_CTX_set_min_proto_version(mContext, TLS1_2_VERSION) != 1
        || SSL_CTX_load_verify_locations(mContext, trustedPem.c_str(), nullptr) != 1) {
        const auto error = sslError("TLS client context (trusted certificate " + trustedPem + ")");
        SSL_CTX_free(mContext);
        throw error;
    }
    SSL_CTX_set_verify(mContext, SSL_VERIFY_PEER, nullptr);
}

HttpsClient::~HttpsClient()
{
    close();
    SSL_CTX_free(mContext);
}

void HttpsClient::close()
{
    if (mSsl) {
        SSL_shutdown(mSsl);
        SSL_free(mSsl);
        mSsl = nullptr;
    }
    if (mFd >= 0) {
        ::close(mFd);
        mFd = -1;
    }
    mBuffer.clear();
    mPosts = 0;
}

std::string HttpsClient::connect()
{
    close();
    mFd = socket(AF_INET, SOCK_STREAM, 0);
    if (mFd < 0) {
        throw systemError("socket");
    }
    const timeval timeout{ kClientTimeoutS, 0 };
    setsockopt(mFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(mFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    noDelay(mFd);
    const sockaddr_in addr = socketAddress(mAddress, mPort);
    if (::connect(mFd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        const auto error = systemError("connect to " + mAddress + ":" + std::to_string(mPort));
        close();
        throw error;
    }

    mSsl = SSL_new(mContext);
    SSL_set_fd(mSsl, mFd);
    // the certificate must name the address we connected to (subjectAltName IP)
    X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(mSsl), mAddress.c_str());
    if (SSL_connect(mSsl) != 1) {
        const long verify = SSL_get_verify_result(mSsl);
        const auto error = verify != X509_V_OK
            ? std::runtime_error("certificate of " + mAddress + " rejected: " + X509_verify_cert_error_string(verify))
            : sslError("TLS handshake with " + mAddress);
        close();
        throw error;
    }
    mSession = sessionName(mSsl);
    return mSession;
}

HttpResponse HttpsClient::send(const Bytes& request, bool* newSession)
{
    if (newSession) {
        *newSession = false;
    }
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!mSsl || mPosts >= kPostsPerSession) {
            connect();
            if (newSession) {
                *newSession = true;
            }
        }
        ++mPosts;
        try {
            writeAll(mSsl, std::string(request.begin(), request.end()));
            auto message = readMessage(mSsl, mFd, mBuffer, nullptr);
            if (!message) {
                throw std::runtime_error("the server closed the session");
            }
            HttpResponse response;
            // "HTTP/1.1 200 OK"
            const size_t space = message->startLine.find(' ');
            response.status = std::stoi(message->startLine.substr(space + 1, 3));
            response.reason = space + 5 < message->startLine.size() ? message->startLine.substr(space + 5) : "";
            response.contentType = message->headers["content-type"];
            response.body = message->body;
            if (lower(message->headers["connection"]) == "close") {
                close();
            }
            return response;
        } catch (const std::exception&) {
            close();                // a session the server dropped (e.g. restarted): once more, in a new one
            if (attempt == 1) {
                throw;
            }
        }
    }
    return {};
}
