// Secure Marshaling (Secure World): data path after the bootstrap, ECALL 4 of Enclave.edl (tee.pdf step 4,
// Fig. 5 of the paper). A vehicle's OT packet becomes the JSON the cloud receives:
//   1. unpack       Message(AES(K_G, Data), Auth_d, OTP_dt)                       (common/SmartData.h)
//   2. keys         Auth_d -> K_dg, K_G of that vehicle                           (OT Key Manager, key_manager.h)
//   3. OTP_dt       == Poly1305(K_dg, Auth_d xor t, AES(K_G, Data)), t = my slot +- kOtpWindow
//   4. decrypt      Data = AES(K_G)^-1 (AES-128-GCM): SmartData { location, timing, metadata, value, Auth_d }
//   5. JSON         { Location, Timing, Metadata, Value, Trust }   (Value in base64, Trust: Auth_d in hex)
//   6. IT packet    HTTPS Header | AES(K_eg, JSON): the whole POST /smartdata, into it_https_pkt; the body is
//                   AES-256-GCM with K_eg, the key of the HTTPS Session below. The App only sends it (inside its
//                   own TLS, the transport) and cannot read the JSON
// HTTPS Session (Fig. 5), here too: the cloud's certificate CY_c, pinned by ecall_init_cloud_session, and K_eg =
// SHA256(ECDH(X_s, Y_c)) (common/SmartData.h). X_s is fresh per session and dropped once K_eg is derived; Y_s
// goes in the header (kSessionKeyHeader) so the cloud derives the same K_eg with its X_c. A new session every
// kMessagesPerSession packets (the paper's evaluation, Section 6.1).
// A packet that fails 1-4 is refused (GW_IGNORED): nothing goes to the cloud.
// Output: every failure, but only the first packet of each size when it passes (ocall_print leaves the enclave,
// inside the time the App measures). Nothing secret is printed: no K_dg, K_G, K_eg, Data or JSON.

#include "Enclave_t.h"
#include "SmartData.h"
#include "Traits.h"
#include "gateway.h"
#include "key_manager.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <algorithm>
#include <cstring>
#include <exception>
#include <memory>
#include <set>
#include <string>

namespace
{

std::set<size_t> gTraced;   // OT packet sizes already printed

// HTTPS Session of Fig. 5: { CY_c, K_eg }
struct CloudSession
{
    bool ready = false;
    std::shared_ptr<EVP_PKEY> cloudKey;     // Y_c, from the pinned CY_c
    std::string host;                       // Host header
    std::string gateway;                    // X-Gateway header
    Bytes kEg;                              // K_eg of the current session
    std::string ys;                         // its Y_s: DER, base64 (kSessionKeyHeader)
    int messages = 0;                       // made with this K_eg
    int number = 0;                         // sessions so far
};

CloudSession gCloud;

// a new session: X_s, Y_s fresh; K_eg = SHA256(ECDH(X_s, Y_c)); X_s dropped when this returns
void newCloudSession()
{
    const auto xs = newEcKey(kEcdhCurve);
    if (!gCloud.kEg.empty()) {
        OPENSSL_cleanse(gCloud.kEg.data(), gCloud.kEg.size());
    }
    gCloud.kEg = computeKEg(xs.get(), gCloud.cloudKey.get());
    gCloud.ys = base64Encode(publicKeyDer(xs.get()));
    gCloud.messages = 0;
    ++gCloud.number;
    enclavePrint("HTTPS session #" + std::to_string(gCloud.number) + " with the cloud: Y_s = " + gCloud.ys.substr(36, 16)
        + "..., K_eg = SHA256(ECDH(X_s, Y_c)) kept in the enclave, X_s dropped");
}

std::string hex(const Bytes& data)
{
    static const char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(2 * data.size());
    for (uint8_t byte : data) {
        text += digits[byte >> 4];
        text += digits[byte & 0x0f];
    }
    return text;
}

// 5. the JSON of Fig. 5
std::string toJson(const SmartData& data)
{
    return "{\"Location\":" + std::to_string(data.location)
        + ",\"Timing\":" + std::to_string(data.timing)
        + ",\"Metadata\":" + std::to_string(data.metadata)
        + ",\"Value\":\"" + base64Encode(data.value) + "\""
        + ",\"Trust\":\"" + hex(data.authD) + "\"}";
}

int marshal(const Bytes& otPacket, uint64_t now, uint8_t* out, size_t outMax, size_t* outLen)
{
    const bool traced = gTraced.insert(otPacket.size()).second;

    // 1. Message(AES(K_G, Data), Auth_d, OTP_dt)
    DataMessage message;
    try {
        message = unpackDataMessage(otPacket);
    } catch (const std::exception& e) {
        enclaveCheck(false, std::string("Secure Marshaling: not an OT packet (") + e.what() + "): ignored");
        return GW_IGNORED;
    }

    // 2. the keys of the vehicle that Auth_d names
    const auto keys = findVehicleKeys(message.authD);
    if (!keys) {
        enclaveCheck(false, "Secure Marshaling: Auth_d " + hex(message.authD).substr(0, 16)
            + "... is no activated vehicle: ignored");
        return GW_IGNORED;
    }
    const std::string& session = keys->session;

    // 3. OTP_dt: every t in +-kOtpWindow slots around my own truncated clock (as SaveRSU)
    const uint64_t tNow = dataOtpSlot(static_cast<int64_t>(now));
    bool otpOk = false;
    uint64_t tMatch = 0;
    for (uint64_t t = tNow - kOtpWindow; t <= tNow + kOtpWindow && !otpOk; ++t) {
        const Block candidate = dataOtp(keys->kDg, message.authD, t, message.sealedData);
        if (CRYPTO_memcmp(candidate.data(), message.otp.data(), candidate.size()) == 0) { // constant time
            otpOk = true;
            tMatch = t;
        }
    }
    if (!otpOk) {
        enclaveCheck(false, session + ": OTP_dt of the SmartData does not match K_dg, Auth_d and t in "
            + std::to_string(2 * kOtpWindow + 1) + " slots around " + std::to_string(tNow) + ": ignored");
        return GW_IGNORED;
    }
    if (traced) {
        const long long offset = static_cast<long long>(tMatch) - static_cast<long long>(tNow);
        enclaveCheck(true, session + ": OTP_dt = Poly1305(K_dg, Auth_d xor t, AES(K_G, Data)) with t = "
            + std::to_string(tMatch) + " (my slot " + (offset >= 0 ? "+" : "") + std::to_string(offset) + ")");
    }

    // 4. Data: AES-128-GCM with K_G
    std::optional<Bytes> plain = aesGcmDecrypt(keys->kG, message.sealedData);
    if (!plain) {
        enclaveCheck(false, session + ": AES(K_G, Data) does not decrypt with K_G (GCM tag invalid): ignored");
        return GW_IGNORED;
    }
    SmartData data;
    try {
        data = unpackSmartData(*plain);
    } catch (const std::exception& e) {
        OPENSSL_cleanse(plain->data(), plain->size());
        enclaveCheck(false, session + ": Data is not a SmartData (" + e.what() + "): ignored");
        return GW_IGNORED;
    }
    OPENSSL_cleanse(plain->data(), plain->size());
    // the Auth_d inside the encrypted Data must be the one the packet came with
    if (data.authD.size() != message.authD.size()
        || CRYPTO_memcmp(data.authD.data(), message.authD.data(), data.authD.size()) != 0) {
        enclaveCheck(false, session + ": the Auth_d inside Data is not the packet's: ignored");
        return GW_IGNORED;
    }
    if (traced) {
        enclaveCheck(true, session + ": AES(K_G, Data) decrypts with K_G (GCM tag valid), its Auth_d is the packet's");
    }

    // 5. JSON
    Bytes json;
    {
        std::string text = toJson(data);
        json.assign(text.begin(), text.end());
        OPENSSL_cleanse(&text[0], text.size());
    }
    OPENSSL_cleanse(data.value.data(), data.value.size());

    // 6. HTTPS Header | AES(K_eg, JSON)
    if (gCloud.messages >= kMessagesPerSession) {
        newCloudSession();
    }
    const Bytes body = aesGcmEncrypt(gCloud.kEg, json);      // AES-256-GCM: nonce | ciphertext | tag
    ++gCloud.messages;
    OPENSSL_cleanse(json.data(), json.size());
    const std::string header = std::string("POST ") + kSmartDataPath + " HTTP/1.1\r\n"
        + "Host: " + gCloud.host + "\r\n"
        + "Content-Type: application/octet-stream\r\n"
        + "X-Encrypted: AES-256-GCM(K_eg, application/json)\r\n"
        + kSessionKeyHeader + ": " + gCloud.ys + "\r\n"
        + "X-Gateway: " + gCloud.gateway + "\r\n"
        + "X-Vehicle: " + session + "\r\n"
        + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    if (header.size() + body.size() > outMax) {
        enclavePrint(session + ": IT packet of " + std::to_string(header.size() + body.size())
            + " B does not fit the IT buffer (" + std::to_string(outMax) + " B)");
        return GW_ERR_BUFFER;
    }
    std::copy(header.begin(), header.end(), out);
    std::copy(body.begin(), body.end(), out + header.size());
    *outLen = header.size() + body.size();
    if (traced) {
        enclavePrint(session + ": JSON -> AES(K_eg, JSON) = " + std::to_string(body.size()) + " B (session #"
            + std::to_string(gCloud.number) + "), with its HTTPS header: IT packet = " + std::to_string(*outLen) + " B");
    }
    return GW_OK;
}

} // namespace

int ecall_secure_marshal_ot_to_it(const uint8_t* ot_pkt, size_t ot_pkt_len, uint64_t current_ptp_time,
    uint8_t* it_https_pkt, size_t it_buf_max, size_t* it_pkt_len)
{
    if (!it_pkt_len) {
        return GW_ERR_ARGS;
    }
    *it_pkt_len = 0;
    if (!ot_pkt || ot_pkt_len == 0 || !it_https_pkt || it_buf_max == 0) {
        return GW_ERR_ARGS;
    }
    if (!gatewayReady()) {
        return GW_ERR_STATE;
    }
    if (!gCloud.ready) {
        enclavePrint("Secure Marshaling: no HTTPS session with the cloud (ecall_init_cloud_session first)");
        return GW_ERR_STATE;
    }
    try {
        return marshal(Bytes(ot_pkt, ot_pkt + ot_pkt_len), current_ptp_time, it_https_pkt, it_buf_max, it_pkt_len);
    } catch (const std::exception& e) { // OpenSSL failed (common/Crypto.cpp throws)
        enclavePrint(std::string("Secure Marshaling: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}

int ecall_init_cloud_session(const uint8_t* cloud_cert_pem, size_t cert_len, const char* host, const char* gateway)
{
    if (!cloud_cert_pem || cert_len == 0 || !host || !gateway) {
        return GW_ERR_ARGS;
    }
    try {
        // CY_c: a self-signed P-256 certificate (PEM), pinned: no other key will do for K_eg
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(cloud_cert_pem, static_cast<int>(cert_len)),
            BIO_free);
        std::unique_ptr<X509, decltype(&X509_free)> cert(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)
            : nullptr, X509_free);
        if (!cert) {
            enclaveCheck(false, "HTTPS session: the cloud's certificate is not a PEM certificate");
            return GW_ERR_ARGS;
        }
        EVP_PKEY* key = X509_get0_pubkey(cert.get());
        char curve[64] = "?";
        if (!key || EVP_PKEY_get_group_name(key, curve, sizeof(curve), nullptr) != 1
            || std::strcmp(curve, "prime256v1") != 0) {
            enclaveCheck(false, std::string("HTTPS session: the cloud's key is not P-256 (") + curve + ")");
            return GW_ERR_CRYPTO;
        }
        if (X509_verify(cert.get(), key) != 1) {
            enclaveCheck(false, "HTTPS session: the cloud's certificate is not signed by its own key");
            return GW_ERR_CRYPTO;
        }
        EVP_PKEY_up_ref(key);
        gCloud.cloudKey.reset(key, EVP_PKEY_free);
        gCloud.host = host;
        gCloud.gateway = gateway;
        gCloud.ready = true;
        char subject[128] = "?";
        X509_NAME_oneline(X509_get_subject_name(cert.get()), subject, sizeof(subject));
        enclaveCheck(true, std::string("HTTPS session: CY_c of the cloud pinned (") + subject
            + ", P-256, self-signature valid)");
        newCloudSession();
        return GW_OK;
    } catch (const std::exception& e) {
        enclavePrint(std::string("HTTPS session: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}
