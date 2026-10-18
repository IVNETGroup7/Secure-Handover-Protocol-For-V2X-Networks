#ifndef BOOTSTRAP_HTTPS_H_
#define BOOTSTRAP_HTTPS_H_

// HTTPS between the RSU and the cloud (Fig. 5 of the paper, tee.pdf step 6): real TLS over TCP (OpenSSL),
// unlike the radio and the backhaul, which are raw Ethernet links (RawSocket.h)
//   cloud  CloudIdentity: a fresh P-256 key and self-signed certificate per run (address in its subjectAltName),
//          published as PEM: what the RSU's enclave pins (K_eg, SmartData.h) and what the RSU's TLS trusts, as if
//          provisioned before deployment. HttpsServer: TLS with that identity
//   RSU    HttpsClient: verifies the cloud's certificate against that PEM and its address; one session for
//          kPostsPerSession requests (keep-alive), then a new one (the paper's evaluation, Section 6.1).
//          Only the transport: the SmartData inside is already AES(K_eg, JSON), made in the enclave

#include "Crypto.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>

constexpr const char* kCloudAddress = "127.0.0.1";
constexpr uint16_t kCloudPort = 8443;
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

// the cloud's key pair and self-signed certificate, for "address": CY_e, as Fig. 5 names the certificate of the
// HTTPS Session { CY_e, K_eg } (here its other end is the cloud)
struct CloudIdentity
{
    std::shared_ptr<EVP_PKEY> key;      // X_e (and Y_e)
    std::shared_ptr<X509> certificate;  // CY_e: Y_e, signed by X_e
    std::string pem() const;            // the certificate, PEM
};
CloudIdentity newCloudIdentity(const std::string& address);

class HttpsServer
{
    public:
        // listens on address:port with "identity". Throws std::runtime_error
        HttpsServer(const std::string& address, uint16_t port, const CloudIdentity& identity);
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
        // one request, already made (request line, headers and body), sent as it is in the open session (a new
        // session when there is none, or after kPostsPerSession); "newSession": set when this request opened one.
        // Throws std::runtime_error
        HttpResponse send(const Bytes& request, bool* newSession = nullptr);
        const std::string& session() const { return mSession; }   // of the last connect()

    private:
        void close();

        std::string mAddress;
        uint16_t mPort;
        SSL_CTX* mContext = nullptr;
        SSL* mSsl = nullptr;
        int mFd = -1;
        int mPosts = 0;             // requests in the current session
        std::string mSession;
        std::string mBuffer;        // bytes read past the last response
};

#endif /* BOOTSTRAP_HTTPS_H_ */
