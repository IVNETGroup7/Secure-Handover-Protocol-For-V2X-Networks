// Control component (Secure World): bootstrap of the vehicles, ECALLs 1-3 of Enclave.edl.
// Everything declared here lives in enclave memory: the App only sees what an ECALL copies out ([out]).
//
// The RSU steps of protocol/BootstrapService.cpp that touch secrets, ported (tee.pdf step 5):
//   ECDHResponse                 ECDH_Request  -> ECDH_Response   (X_g and K_dg stay here)
//   SaveRSU + AuthGranted        Auth_Request  -> Auth_Granted    (OTP search, K_g, E_K_dg(M))
//   Active02                     Active_01     -> Active_02       (D_K_dg, M for the ESA)
//   withinDeadline               t <= t_f, before each of them
// On an OTP match the state (K_g and every active session) is sealed (sgx_seal_data) and handed to the App to
// keep on disk; ecall_init_gateway unseals it (reboot recovery, tee.pdf step 5).
// The other RSU steps (relay to the ESA, PTP) have no secrets: the App runs them (App/packet_manager.cpp).
// Crypto: common/Crypto.cpp (the same code as the vehicle and the ESA), over SGX-SSL.
// Output (ocall_print) never carries a secret: no K_dg, K_g or X_g.

#include "Enclave_t.h"
#include "BootstrapType.h"
#include "Crypto.h"
#include "Traits.h"
#include "codec.h"
#include "gateway.h"
#include "gateway_internal.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <sgx_tseal.h>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>

namespace
{

// an activation the ESA authorized (Activation_Token): PendingVehicles of protocol/BootstrapService.h
struct Activation
{
    Bytes authD;        // Auth_d
    uint64_t t0 = 0;    // t_0 (ns)
    uint64_t tf = 0;    // t_f (ns)
    Bytes authEg;       // Auth_eg
};

enum class SessionState
{
    Pending,
    Active,
};

struct Session
{
    std::string id;
    SessionState state = SessionState::Pending;
    Activation activation;
    Bytes kDg;          // K_dg of this session
    Bytes yV;           // Y_V of the vehicle (cached during ECDH for handover)
};

struct HandoverSession
{
    Sha256 authExpected;
    Bytes kt;           // 32-byte transient key KT_i
    Bytes vehiclePublicKey;
};

struct Gateway
{
    bool ready = false;
    Bytes gatewayCert;                                  // CY_g
    Bytes esaPublicKey;                                 // CY_e
    Bytes groupKey;                                     // K_g
    std::map<std::string, Session> sessions;            // Unified sessions map
    std::map<Sha256, HandoverSession> handovers;        // Pre-computed handovers indexed by Sha256
};

Gateway gGateway;

constexpr size_t kMaxSealedState = 64 * 1024;
constexpr uint8_t kSealedStateVersion = 2; // version 2 includes yV

void print(const std::string& text)
{
    ocall_print(text.c_str());
}

// a validation and its result: the App shows it as one (common/Trace.h, check), see App/ocalls.cpp
void check(bool ok, const std::string& text)
{
    print((ok ? kCheckOk : kCheckFailed) + text);
}

std::string seconds(uint64_t ns)
{
    char text[32];
    snprintf(text, sizeof(text), "%.6f s", static_cast<int64_t>(ns) / 1e9);
    return text;
}

// ---------------------------------------------------------------------------------------------
// OTP_dt = Poly1305(K_dg, Auth_d xor t, m): as otpSlot / otpNonce / otpMessage of BootstrapService.cpp

// t: slot of kOtpTimeStep s of the PTP-synchronized clock (truncated timestamp); the same double arithmetic
// as SimTime::dbl(), so both sides truncate alike
uint64_t otpSlot(uint64_t ns)
{
    return static_cast<uint64_t>(std::floor((static_cast<int64_t>(ns) / 1e9) / kOtpTimeStep));
}

// Auth_d xor t: t, big endian, into the last 8 bytes of the first AES block of Auth_d
Block otpNonce(const Bytes& authD, uint64_t t)
{
    Block nonce;
    if (authD.size() < nonce.size()) {
        throw std::runtime_error("OTP: Auth_d shorter than one block");
    }
    std::copy_n(authD.begin(), nonce.size(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] ^= static_cast<uint8_t>(t >> (8 * i));
    }
    return nonce;
}

const Bytes& otpMessage()
{
    static const Bytes m(kOtpMessage, kOtpMessage + std::char_traits<char>::length(kOtpMessage));
    return m;
}

// ---------------------------------------------------------------------------------------------
// sealed state: version (2) | K_g | CY_e | count (2) | per active session:
//   session | K_dg | Y_v | Auth_d | Auth_eg | t_0 (8) | t_f (8)        (fields with a 2-byte length, codec.h)
// sgx_seal_data encrypts and MACs it with a key only this enclave (on this CPU, in HW mode) can derive:
// the App stores bytes it cannot read nor change unnoticed

void saveState()
{
    Bytes plain;
    wire::putUint(plain, kSealedStateVersion, 1);
    wire::putField(plain, gGateway.groupKey);
    wire::putField(plain, gGateway.esaPublicKey);

    size_t activeCount = 0;
    for (const auto& [id, s] : gGateway.sessions) {
        if (s.state == SessionState::Active) {
            ++activeCount;
        }
    }
    wire::putUint(plain, activeCount, 2);

    for (const auto& [id, s] : gGateway.sessions) {
        if (s.state == SessionState::Active) {
            wire::putField(plain, Bytes(id.begin(), id.end()));
            wire::putField(plain, s.kDg);
            wire::putField(plain, s.yV);
            wire::putField(plain, s.activation.authD);
            wire::putField(plain, s.activation.authEg);
            wire::putUint(plain, s.activation.t0, 8);
            wire::putUint(plain, s.activation.tf, 8);
        }
    }

    const uint32_t size = sgx_calc_sealed_data_size(0, static_cast<uint32_t>(plain.size()));
    if (size == UINT32_MAX || size > kMaxSealedState) {
        OPENSSL_cleanse(plain.data(), plain.size());
        throw std::runtime_error("sealed state too large");
    }
    Bytes sealed(size);
    const sgx_status_t status = sgx_seal_data(0, nullptr, static_cast<uint32_t>(plain.size()), plain.data(), size,
        reinterpret_cast<sgx_sealed_data_t*>(sealed.data()));
    OPENSSL_cleanse(plain.data(), plain.size());
    if (status != SGX_SUCCESS) {
        throw std::runtime_error("sgx_seal_data failed");
    }

    int saved = -1;
    if (ocall_save_sealed_state(&saved, sealed.data(), sealed.size()) != SGX_SUCCESS || saved != static_cast<int>(size)) {
        print("sealed state not saved by the App (the sessions live in enclave memory only)");
        return;
    }
    print("state sealed: K_g + " + std::to_string(activeCount) + " active session(s), "
        + std::to_string(size) + " bytes handed to the App");
}

// restores the sessions sealed by saveState (and K_g, unless the App gave one); false: nothing usable saved
bool loadState(bool keepGroupKey)
{
    Bytes sealed(kMaxSealedState);
    int loaded = -1;
    if (ocall_load_sealed_state(&loaded, sealed.data(), sealed.size()) != SGX_SUCCESS || loaded <= 0) {
        return false;
    }
    sealed.resize(static_cast<size_t>(loaded));
    const auto* data = reinterpret_cast<const sgx_sealed_data_t*>(sealed.data());
    if (sealed.size() < sizeof(sgx_sealed_data_t)) {
        print("sealed state ignored: truncated");
        return false;
    }
    uint32_t length = sgx_get_encrypt_txt_len(data);
    if (length == UINT32_MAX || sgx_calc_sealed_data_size(sgx_get_add_mac_txt_len(data), length) != sealed.size()) {
        print("sealed state ignored: inconsistent sizes");
        return false;
    }
    Bytes plain(length);
    if (sgx_unseal_data(data, nullptr, nullptr, plain.data(), &length) != SGX_SUCCESS) {
        print("sealed state ignored: does not unseal (another enclave, or changed on disk)");
        return false;
    }

    wire::Reader reader(plain);
    const uint8_t version = static_cast<uint8_t>(reader.uint(1));
    if (version != 1 && version != kSealedStateVersion) {
        OPENSSL_cleanse(plain.data(), plain.size());
        print("sealed state ignored: unknown version");
        return false;
    }
    Bytes groupKey = reader.field();
    reader.field(); // CY_e: the one the ESA presents now wins
    const size_t count = static_cast<size_t>(reader.uint(2));
    for (size_t i = 0; i < count; ++i) {
        const Bytes sessionName = reader.field();
        const std::string name(sessionName.begin(), sessionName.end());
        Session s;
        s.id = name;
        s.state = SessionState::Active;
        s.kDg = reader.field();
        if (version >= 2) {
            s.yV = reader.field();
        }
        s.activation.authD = reader.field();
        s.activation.authEg = reader.field();
        s.activation.t0 = reader.uint(8);
        s.activation.tf = reader.uint(8);
        gGateway.sessions[name] = s;
    }
    if (!keepGroupKey && groupKey.size() == kGroupKeySize) {
        gGateway.groupKey = groupKey;
    }
    OPENSSL_cleanse(plain.data(), plain.size());
    OPENSSL_cleanse(groupKey.data(), groupKey.size());
    print("sealed state restored: " + std::to_string(count) + " active session(s)"
        + (keepGroupKey ? "" : ", K_g of before the restart"));
    return true;
}

// BootstrapService::withinDeadline (RSU): from ECDH on, a message after t_f ends the protocol for that session
bool withinDeadline(const std::string& session, uint64_t now)
{
    auto it = gGateway.sessions.find(session);
    if (it != gGateway.sessions.end() && now <= it->second.activation.tf) {
        check(true, session + ": t = " + seconds(now) + " <= t_f = " + seconds(it->second.activation.tf));
        return true;
    }

    check(false, session + ": aborted: " + (it != gGateway.sessions.end() ? "t_f exceeded (" + seconds(now) + " > t_f = "
        + seconds(it->second.activation.tf) + ")" : std::string("no t_f for this session")));
    if (it != gGateway.sessions.end()) {
        gGateway.sessions.erase(it); // Atomically cleans up session, kDg, yV and activation
    }
    return false;
}

// BootstrapService::ECDHResponse: M = { ECDH_Request, Y_d } -> { ECDH_Response, Y_g }
Bytes ecdhResponse(const std::string& session, const Bytes& in)
{
    const wire::Ecdh request = wire::unpackEcdh(in);

    auto& s = gGateway.sessions[session];
    s.id = session;
    s.yV = request.publicKey; // Saved in session for future roaming / handover

    const auto keyG = newEcKey(kEcdhCurve);  // X_g and Y_g, fresh for this vehicle
    s.kDg = ecdh(keyG.get(), publicKeyFromDer(request.publicKey).get());
    print(session + ": ECDH done, K_dg kept in the enclave");

    return wire::pack(wire::Ecdh{ ECDH_Response, publicKeyDer(keyG.get()) });
}

struct PendingMatch {
    std::string sessionId;
    Activation activation;
    uint64_t matchedTime = 0;
};

// Helper: search pending activations whose Auth_d produces candidate OTP matching request.otp
static std::optional<PendingMatch> findMatchingPendingSession(
    const Bytes& kDg, const Block& targetOtp, uint64_t tNow)
{
    const uint64_t tMin = tNow >= kOtpWindow ? tNow - kOtpWindow : 0;
    for (const auto& [id, ses] : gGateway.sessions) {
        if (ses.state != SessionState::Pending) {
            continue;
        }
        for (uint64_t t = tMin; t <= tNow + kOtpWindow; ++t) {
            const Block candidate = poly1305Aes(kDg, otpNonce(ses.activation.authD, t), otpMessage());
            if (CRYPTO_memcmp(candidate.data(), targetOtp.data(), candidate.size()) == 0) { // constant time
                return PendingMatch{ id, ses.activation, t };
            }
        }
    }
    return std::nullopt;
}

// BootstrapService::SaveRSU + AuthGranted: M = { Auth_Request, OTP_dt } ->
// E_K_dg({ Auth_Granted, OTP_dt, K_dg, K_g, CY_e, Auth_eg }); nullopt: no pending Auth_d matches (ignored)
std::optional<Bytes> authGranted(const std::string& session, const Bytes& in, uint64_t now)
{
    const wire::AuthRequest request = wire::unpackAuthRequest(in);

    auto it = gGateway.sessions.find(session);
    if (it == gGateway.sessions.end() || it->second.kDg.empty()) {
        check(false, session + ": no K_dg for this session: ignored");
        return std::nullopt;
    }
    const uint64_t tNow = otpSlot(now);

    // past its t_f an activation is no longer pending
    for (auto ses = gGateway.sessions.begin(); ses != gGateway.sessions.end();) {
        if (ses->second.state == SessionState::Pending && now > ses->second.activation.tf) {
            ses = gGateway.sessions.erase(ses);
        } else {
            ++ses;
        }
    }

    const auto match = findMatchingPendingSession(it->second.kDg, request.otp, tNow);
    if (!match) {
        size_t pendingCount = 0;
        for (const auto& [name, ses] : gGateway.sessions) {
            if (ses.state == SessionState::Pending) ++pendingCount;
        }
        check(false, session + ": OTP_dt matches no pending Auth_d (" + std::to_string(pendingCount)
            + " pending x " + std::to_string(2 * kOtpWindow + 1) + " slots around t = " + std::to_string(tNow)
            + "): ignored");
        return std::nullopt;
    }

    const uint64_t tMatch = match->matchedTime;
    const long long slotOffset = static_cast<long long>(tMatch) - static_cast<long long>(tNow);
    check(true, session + ": OTP_dt matches the Auth_d of the activation of " + match->sessionId + " with t = "
        + std::to_string(tMatch) + " (my slot " + (slotOffset >= 0 ? "+" : "") + std::to_string(slotOffset) + ")");

    // the session (and its K_dg) is now bound to that Auth_d: status active, sealed for a restart
    it->second.activation = match->activation;
    it->second.state = SessionState::Active;
    if (match->sessionId != session) {
        gGateway.sessions.erase(match->sessionId);
    }
    saveState();

    wire::AuthGranted m;
    m.type = Auth_Granted;
    m.otp = request.otp;                                // OTP_dt: the one matched
    m.kDg = it->second.kDg;                             // K_dg
    m.kG = gGateway.groupKey;                           // K_g
    m.esaPublicKey = gGateway.esaPublicKey;             // CY_e
    m.authEg = it->second.activation.authEg;            // Auth_eg: lets the vehicle check CY_e
    Bytes sealed = aesGcmEncrypt(it->second.kDg, wire::pack(m)); // E_K_dg(M): AES-256-GCM
    print(session + ": Auth_Granted = E_K_dg(M), " + std::to_string(sealed.size()) + " bytes");
    return sealed;
}

// BootstrapService::Active02: E_K_dg({ Active_01, Auth_d, OTP_dt, Auth_de }) -> { Active_02, Auth_d, OTP_dt, Auth_de }
// for the ESA; nullopt: does not decrypt with this session's K_dg (ignored)
std::optional<Bytes> active02(const std::string& session, const Bytes& in)
{
    auto it = gGateway.sessions.find(session);
    if (it == gGateway.sessions.end() || it->second.kDg.empty()) {
        check(false, session + ": no K_dg for this session: ignored");
        return std::nullopt;
    }
    const auto plain = aesGcmDecrypt(it->second.kDg, in);
    if (!plain) {
        check(false, session + ": E_K_dg(M) does not decrypt with the K_dg of this session: ignored");
        return std::nullopt;
    }
    check(true, session + ": E_K_dg(M) decrypts with the K_dg of this session (GCM tag valid)");
    wire::Active m = wire::unpackActive(*plain);
    m.type = Active_02;
    print(session + ": M relayed to the ESA");
    return wire::pack(m);
}

std::optional<Bytes> forwardingRequest(const std::string& session, const Bytes& in, uint64_t now)
{
    const wire::ForwardingRequest request = wire::unpackForwardingRequest(in);
    auto it = gGateway.handovers.find(request.auth);
    if (it == gGateway.handovers.end()) {
        check(false, session + ": Forwarding_Request auth matches no pending handover session: ignored");
        return std::nullopt;
    }

    const uint64_t tNow = otpSlot(now);
    const uint64_t tMin = tNow >= kOtpWindow ? tNow - kOtpWindow : 0;
    bool otpValid = false;
    uint64_t tMatch = 0;
    const Bytes authBytes(request.auth.begin(), request.auth.end());
    const Bytes& ktBytes = it->second.kt; // 32-byte key

    for (uint64_t t = tMin; t <= tNow + kOtpWindow; ++t) {
        const Block candidate = poly1305Aes(ktBytes, otpNonce(authBytes, t), otpMessage());
        if (CRYPTO_memcmp(candidate.data(), request.otp.data(), candidate.size()) == 0) {
            otpValid = true;
            tMatch = t;
            break;
        }
    }
    if (!otpValid) {
        check(false, session + ": Forwarding_Request OTP failed verification: ignored");
        return std::nullopt;
    }

    check(true, session + ": Forwarding_Request OTP verified with t = " + std::to_string(tMatch));

    // Derive auth' = SHA256(auth)
    Sha256 authPrime = sha256(authBytes);

    // Fresh OTP' using the 32-byte KT_i key
    Block otpPrime = poly1305Aes(ktBytes, otpNonce(Bytes(authPrime.begin(), authPrime.end()), tNow), otpMessage());

    wire::ForwardingGranted m;
    m.type = Forwarding_Granted;
    m.nextRsuPublicKey = {}; // optional pre-load
    m.authPrime = authPrime;
    m.kG = gGateway.groupKey;
    m.otp = otpPrime;

    // Encrypted with KT_i (AES-256-GCM)
    Bytes sealed = aesGcmEncrypt(ktBytes, wire::pack(m));

    // Bind session into active sessions
    auto& s = gGateway.sessions[session];
    s.id = session;
    s.state = SessionState::Active;
    s.kDg = ktBytes;
    s.yV = it->second.vehiclePublicKey;
    s.activation.t0 = now;
    s.activation.tf = now + static_cast<uint64_t>(kActivationWindow * 1e9);
    gGateway.handovers.erase(it);
    saveState();

    print(session + ": Forwarding_Granted = E_KT(M), " + std::to_string(sealed.size()) + " bytes");
    return sealed;
}

} // namespace

// ---------------------------------------------------------------------------------------------
// Inter-Enclave Interface (gateway_internal.h)

bool gatewayFindVehicleKeys(const Bytes& authD, Bytes& outKdg, Bytes& outKg)
{
    if (!gGateway.ready) {
        return false;
    }
    for (const auto& [name, s] : gGateway.sessions) {
        if (s.state == SessionState::Active && s.activation.authD == authD) {
            outKdg = s.kDg;
            outKg = gGateway.groupKey;
            return true;
        }
    }
    return false;
}

bool gatewayIsReady()
{
    return gGateway.ready;
}

// ---------------------------------------------------------------------------------------------
// ECALLs of Enclave.edl

int ecall_init_gateway(const uint8_t* gw_cert, size_t cert_len, const uint8_t* esa_pub_key, size_t esa_len,
    const uint8_t* group_key, size_t group_key_len)
{
    if (!esa_pub_key || esa_len == 0 || (cert_len > 0 && !gw_cert) || (group_key_len > 0 && !group_key)) {
        return GW_ERR_ARGS;
    }

    // CY_e must be a valid public key (DER SubjectPublicKeyInfo): parsed by OpenSSL inside the enclave (SGX-SSL)
    const unsigned char* der = esa_pub_key;
    EVP_PKEY* key = d2i_PUBKEY(nullptr, &der, static_cast<long>(esa_len));
    if (!key) {
        check(false, "init_gateway: CY_e is not a valid public key");
        return GW_ERR_CRYPTO;
    }
    char curve[64] = "?";
    EVP_PKEY_get_group_name(key, curve, sizeof(curve), nullptr);
    EVP_PKEY_free(key);

    // K_g: given (shared by the RSUs) or generated here, with the enclave's RNG
    Bytes groupKey(kGroupKeySize);
    if (group_key_len > 0) {
        if (group_key_len != kGroupKeySize) {
            return GW_ERR_ARGS;
        }
        groupKey.assign(group_key, group_key + group_key_len);
    } else if (RAND_bytes(groupKey.data(), static_cast<int>(groupKey.size())) != 1) {
        return GW_ERR_CRYPTO;
    }

    gGateway.gatewayCert.assign(gw_cert, gw_cert + cert_len);
    gGateway.esaPublicKey.assign(esa_pub_key, esa_pub_key + esa_len);
    gGateway.groupKey = groupKey;
    print("init_gateway: CY_e " + std::string(curve) + " (" + std::to_string(esa_len) + " bytes), K_g "
        + (group_key_len > 0 ? "given" : "generated inside") + " (" + std::to_string(groupKey.size()) + " bytes)");

    // a restart: the sessions activated before it (sealed state kept by the App)
    try {
        loadState(group_key_len > 0);
    } catch (const std::exception& e) {
        print(std::string("sealed state ignored: ") + e.what());
    }
    gGateway.ready = true;
    return GW_OK;
}

int ecall_control_add_activation_token(const char* session, uint64_t t0, uint64_t tf, const uint8_t* auth_d,
    size_t auth_d_len, const uint8_t* auth_eg, size_t auth_eg_len)
{
    if (!gGateway.ready) {
        return GW_ERR_STATE;
    }
    if (!session || !auth_d || auth_d_len == 0 || !auth_eg || auth_eg_len == 0 || t0 >= tf) {
        return GW_ERR_ARGS;
    }

    // BootstrapService::PTP: pending until an Auth_Request's OTP matches its Auth_d; its t_f is checked from ECDH on
    auto& s = gGateway.sessions[session];
    s.id = session;
    s.state = SessionState::Pending;
    s.activation = Activation{ Bytes(auth_d, auth_d + auth_d_len), t0, tf,
        Bytes(auth_eg, auth_eg + auth_eg_len) };

    size_t pendingCount = 0;
    for (const auto& [name, ses] : gGateway.sessions) {
        if (ses.state == SessionState::Pending) ++pendingCount;
    }
    print(std::string(session) + ": activation pending until t_f = " + seconds(tf) + " ("
        + std::to_string(pendingCount) + " pending)");
    return GW_OK;
}

int ecall_control_handle_bootstrap(int msg_type, const char* session, const uint8_t* in_pkt, size_t in_len,
    uint8_t* out_pkt, size_t out_max_len, size_t* actual_out_len, int* out_type, uint64_t current_ptp_time)
{
    if (!actual_out_len || !out_type) {
        return GW_ERR_ARGS;
    }
    *actual_out_len = 0;
    *out_type = -1;
    if (!gGateway.ready) {
        return GW_ERR_STATE;
    }
    if (!session || !in_pkt || in_len == 0 || !out_pkt || out_max_len == 0) {
        return GW_ERR_ARGS;
    }
    
    if (msg_type != ECDH_Request && msg_type != Auth_Request && msg_type != Active_01 && msg_type != Forwarding_Request) {
        return GW_ERR_ARGS; // not a message the gateway handles in the enclave
    }

    // nothing may escape the ECALL: errors (bad payload, OpenSSL) become a status
    try {
        const std::string name = session;
        const Bytes in(in_pkt, in_pkt + in_len);
    
        if (msg_type != Forwarding_Request && !withinDeadline(name, current_ptp_time)) {
            return GW_IGNORED;
        }

        std::optional<Bytes> out;
        int type = -1;
        switch (msg_type) {
            case ECDH_Request:       
                out = ecdhResponse(name, in); 
                type = ECDH_Response; 
                break;
            case Auth_Request:       
                out = authGranted(name, in, current_ptp_time); 
                type = Auth_Granted; 
                break;
            case Active_01:          
                out = active02(name, in); 
                type = Active_02; 
                break;
            case Forwarding_Request: 
                out = forwardingRequest(name, in, current_ptp_time); 
                type = Forwarding_Granted; 
                break;
        }
        
        if (!out) {
            return GW_IGNORED;
        }
        if (out->size() > out_max_len) {
            return GW_ERR_BUFFER;
        }
        std::memcpy(out_pkt, out->data(), out->size());
        *actual_out_len = out->size();
        *out_type = type;
        return GW_OK;
    } catch (const std::exception& e) {
        print(std::string(session) + ": error: " + e.what());
        return GW_ERR_CRYPTO;
    }
}

int ecall_trigger_handover(const char* session, uint64_t t_i, uint8_t* out_tau, uint8_t* out_yv, size_t* yv_len)
{
    if (!session || !out_tau || !out_yv || !yv_len) return GW_ERR_ARGS;
    if (!gGateway.ready) return GW_ERR_STATE;

    try {
        auto it = gGateway.sessions.find(session);
        if (it == gGateway.sessions.end() || it->second.kDg.empty() || it->second.yV.empty()) {
            return GW_IGNORED;
        }
        if (it->second.yV.size() > 128) {
            return GW_ERR_BUFFER;
        }

        // tau_{i+2} = Poly1305_AES(K_dg, padding(t_i))
        Block nonce{};
        for (int i = 0; i < 8; ++i) nonce[15 - i] = static_cast<uint8_t>(t_i >> (8 * i));
        Block tau = poly1305Aes(it->second.kDg, nonce, otpMessage());

        std::memcpy(out_tau, tau.data(), 16);
        std::memcpy(out_yv, it->second.yV.data(), it->second.yV.size());
        *yv_len = it->second.yV.size();

        OPENSSL_cleanse(nonce.data(), nonce.size());
        OPENSSL_cleanse(tau.data(), tau.size());
        return GW_OK;
    } catch (const std::exception& e) {
        print(std::string("trigger_handover error: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}

int ecall_receive_forwarding_notice(const uint8_t* yv, size_t yv_len, const uint8_t* tau, uint8_t* out_yg, size_t* yg_len)
{
    if (!yv || yv_len == 0 || !tau || !out_yg || !yg_len) return GW_ERR_ARGS;
    if (!gGateway.ready) return GW_ERR_STATE;

    try {
        Bytes vehicleKey(yv, yv + yv_len);
        Block tauBlock;
        std::memcpy(tauBlock.data(), tau, 16);

        // 1. Generate Y_G_i+2 and X_G_i+2
        const auto keyG = newEcKey(kEcdhCurve);
        Bytes yg = publicKeyDer(keyG.get());
        if (yg.size() > 128) {
            return GW_ERR_BUFFER;
        }
        
        // 2. K_dh_i = Y_V ^ X_G
        Bytes kDh = ecdh(keyG.get(), publicKeyFromDer(vehicleKey).get());

        // 3. KT_mac = Poly1305(K_dh_i, K_dh_i xor tau)
        Block nonce{};
        for (int i = 0; i < 16; ++i) nonce[i] = kDh[i] ^ tauBlock[i];
        Block ktMac = poly1305Aes(kDh, nonce, otpMessage());

        // Derive full 32-byte key for KT_i: SHA256(ktMac)
        Bytes ktMacBytes(ktMac.begin(), ktMac.end());
        Sha256 ktKey = sha256(ktMacBytes);
        Bytes kt(ktKey.begin(), ktKey.end());

        // 4. auth_{i+2} = SHA256(tau)
        Bytes tauBytes(tauBlock.begin(), tauBlock.end());
        Sha256 auth = sha256(tauBytes);

        HandoverSession hs;
        hs.authExpected = auth;
        hs.kt = kt;
        hs.vehiclePublicKey = vehicleKey;
        gGateway.handovers[auth] = hs;

        std::memcpy(out_yg, yg.data(), yg.size());
        *yg_len = yg.size();

        OPENSSL_cleanse(kDh.data(), kDh.size());
        OPENSSL_cleanse(nonce.data(), nonce.size());
        OPENSSL_cleanse(ktMac.data(), ktMac.size());
        OPENSSL_cleanse(ktKey.data(), ktKey.size());
        return GW_OK;
    } catch (const std::exception& e) {
        print(std::string("receive_forwarding_notice error: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}
