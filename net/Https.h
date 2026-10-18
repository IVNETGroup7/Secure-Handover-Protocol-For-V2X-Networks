#ifndef BOOTSTRAP_HTTPS_H_
#define BOOTSTRAP_HTTPS_H_

// HTTPS between the RSU and the cloud (Fig. 5 of the paper, tee.pdf step 6): real TLS over TCP (OpenSSL),
// unlike the radio and the backhaul, which are raw Ethernet links (RawSocket.h)
//   cloud  HttpsServer: a fresh P-256 key and self-signed certificate per run (address in its
//          subjectAltName), published as PEM: the RSU's trust anchor, as if provisioned before deployment
//   RSU    HttpsClient: verifies the cloud's certificate against that PEM and its address; one session for
//          kPostsPerSession requests (keep-alive), then a new one (the paper's evaluation, Section 6.1)

#include "Crypto.h"
#include <openssl/ssl.h>
#include <cstdint>
#include <functional>
#include <map>
#include <string>

constexpr const char* kCloudAddress = "127.0.0.1";
constexpr uint16_t kCloudPort = 8443;
constexpr const char* kSmartDataPath = "/smartdata";    // the marshaled SmartData, POSTed by the RSU
constexpr int kPostsPerSession = 100;

struct HttpRequest
{
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;     // names in lower case
    std::string body;
};

struct HttpResponse
{
    int status = 200;
    std::string reason = "OK";
    std::string contentType = "application/json";
    std::string body;
};

class HttpsServer
{
    public:
        // listens on address:port; writes its certificate to "certificatePem". Throws std::runtime_error
        HttpsServer(const std::string& address, uint16_t port, const std::string& certificatePem);
        ~HttpsServer();
        HttpsServer(const HttpsServer&) = delete;
        HttpsServer& operator=(const HttpsServer&) = delete;

        // until stop(): one client at a time, every request handed to "handler" (peer: "address:port");
        // onSession: a client completed the TLS handshake ("TLSv1.3 TLS_AES_256_GCM_SHA384")
        using Handler = std::function<HttpResponse(const HttpRequest&, const std::string& peer)>;
        void serve(const Handler& handler, const std::function<void(const std::string& peer,
            const std::string& session)>& onSession, const std::function<bool()>& stop);

    private:
        int mListen = -1;
        SSL_CTX* mContext = nullptr;
};

class HttpsClient
{
    public:
        // the server at address:port, whose certificate must verify against "trustedPem"
        HttpsClient(const std::string& address, uint16_t port, const std::string& trustedPem);
        ~HttpsClient();
        HttpsClient(const HttpsClient&) = delete;
        HttpsClient& operator=(const HttpsClient&) = delete;

        // TCP + TLS handshake, the certificate verified; returns the session ("TLSv1.3 TLS_AES_256_GCM_SHA384").
        // Throws std::runtime_error
        std::string connect();
        // one request in the open session (a new session when there is none, or after kPostsPerSession);
        // "headers": more header lines; "newSession": set when this request opened one. Throws std::runtime_error
        HttpResponse post(const std::string& path, const std::string& contentType, const Bytes& body,
            const std::map<std::string, std::string>& headers = {}, bool* newSession = nullptr);
        int sessions() const { return mSessions; }
        const std::string& session() const { return mSession; }   // of the last connect()

    private:
        void close();

        std::string mAddress;
        uint16_t mPort;
        SSL_CTX* mContext = nullptr;
        SSL* mSsl = nullptr;
        int mFd = -1;
        int mPosts = 0;             // requests in the current session
        int mSessions = 0;
        std::string mSession;
        std::string mBuffer;        // bytes read past the last response
};

#endif /* BOOTSTRAP_HTTPS_H_ */
