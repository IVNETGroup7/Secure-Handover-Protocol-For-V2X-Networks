// Control component (Secure World): bootstrap of the vehicles, ECALLs 1-3 of Enclave.edl.
// Everything declared here lives in enclave memory: the App only sees what an ECALL copies out ([out]).
//
// The RSU steps of protocol/BootstrapService.cpp that touch secrets, ported (tee.pdf step 5):
//   ECDHResponse                 ECDH_Request  -> ECDH_Response   (X_g and K_dg stay here)
//   SaveRSU + AuthGranted        Auth_Request  -> Auth_Granted    (OTP search, K_g, E_K_dg(M))
//   Active02                     Active_01     -> Active_02       (D_K_dg, M for the ESA)
//   withinWindow                 t_0 <= t <= t_f, before each of them
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
#include "key_manager.h"
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
    uint64_t t0;        // t_0 (ns)
    uint64_t tf;        // t_f (ns)
    Bytes authEg;       // Auth_eg
};

struct HandoverSession
{
    Sha256 authExpected;
    Block kt;
    Bytes vehiclePublicKey;
};

struct Gateway
{
    bool ready = false;
    Bytes gatewayCert;                                  // CY_g
    Bytes esaPublicKey;                                 // CY_e
    Bytes groupKey;                                     // K_g
    std::map<std::string, Activation> pending;          // waiting for an OTP (searched by SaveRSU)
    std::map<std::string, Activation> active;           // an OTP matched: bound to that session
    std::map<std::string, Bytes> kdg;                   // K_dg per session
    std::map<std::string, Bytes> yv;                    // Y_V per session (saved during ECDH)
    std::map<std::string, HandoverSession> handovers;   // Pre-computed handovers indexed by stringified Auth expected
};

Gateway gGateway;

constexpr size_t kMaxSealedState = 64 * 1024;
constexpr uint8_t kSealedStateVersion = 1;

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

// ---------------------------------------------------------------------------------------------
// sealed state: version (1) | K_g | CY_e | count (2) | per active session:
//   session | K_dg | Auth_d | Auth_eg | t_0 (8) | t_f (8)        (fields with a 2-byte length, codec.h)
// sgx_seal_data encrypts and MACs it with a key only this enclave (on this CPU, in HW mode) can derive:
// the App stores bytes it cannot read nor change unnoticed

void saveState()
{
    Bytes plain;
    wire::putUint(plain, kSealedStateVersion, 1);
    wire::putField(plain, gGateway.groupKey);
    wire::putField(plain, gGateway.esaPublicKey);
    wire::putUint(plain, gGateway.active.size(), 2);
    for (const auto& [session, activation] : gGateway.active) {
        const auto kDg = gGateway.kdg.find(session);
        wire::putField(plain, Bytes(session.begin(), session.end()));
        wire::putField(plain, kDg != gGateway.kdg.end() ? kDg->second : Bytes());
        wire::putField(plain, activation.authD);
        wire::putField(plain, activation.authEg);
        wire::putUint(plain, activation.t0, 8);
        wire::putUint(plain, activation.tf, 8);
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
    print("state sealed: K_g + " + std::to_string(gGateway.active.size()) + " active session(s), "
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
    if (reader.uint(1) != kSealedStateVersion) {
        OPENSSL_cleanse(plain.data(), plain.size());
        print("sealed state ignored: unknown version");
        return false;
    }
    Bytes groupKey = reader.field();
    reader.field(); // CY_e: the one the ESA presents now wins
    const size_t count = static_cast<size_t>(reader.uint(2));
    for (size_t i = 0; i < count; ++i) {
        const Bytes session = reader.field();
        const std::string name(session.begin(), session.end());
        gGateway.kdg[name] = reader.field();
        Activation activation;
        activation.authD = reader.field();
        activation.authEg = reader.field();
        activation.t0 = reader.uint(8);
        activation.tf = reader.uint(8);
        gGateway.active[name] = activation;
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

// BootstrapService::withinWindow (RSU): from ECDH on, a message outside [t_0, t_f] ends the protocol for that session
bool withinWindow(const std::string& session, uint64_t now)
{
    const Activation* activation = nullptr;
    if (auto pending = gGateway.pending.find(session); pending != gGateway.pending.end()) {
        activation = &pending->second;
    } else if (auto active = gGateway.active.find(session); active != gGateway.active.end()) {
        activation = &active->second;
    }
    if (activation && activation->t0 <= now && now <= activation->tf) {
        check(true, session + ": t_0 = " + seconds(activation->t0) + " <= t = " + seconds(now) + " <= t_f = "
            + seconds(activation->tf));
        return true;
    }

    check(false, session + ": aborted: " + (activation ? "t = " + seconds(now) + " outside [t_0, t_f] = ["
        + seconds(activation->t0) + ", " + seconds(activation->tf) + "]" : std::string("no activation window for this session")));
    gGateway.kdg.erase(session); // an aborted bootstrap leaves no key
    gGateway.pending.erase(session);
    gGateway.active.erase(session);
    return false;
}

// BootstrapService::ECDHResponse: M = { ECDH_Request, Y_d } -> { ECDH_Response, Y_g }
Bytes ecdhResponse(const std::string& session, const Bytes& in)
{
    const wire::Ecdh request = wire::unpackEcdh(in);

    gGateway.yv[session] = request.publicKey; // Save Y_V for future roaming

    const auto keyG = newEcKey(kEcdhCurve);  // X_g and Y_g, fresh for this vehicle
    gGateway.kdg[session] = ecdh(keyG.get(), publicKeyFromDer(request.publicKey).get());
    gGateway.active.erase(session); // a new K_dg, not yet authenticated: the old one's binding goes with it
    print(session + ": ECDH done, K_dg kept in the enclave");

    return wire::pack(wire::Ecdh{ ECDH_Response, publicKeyDer(keyG.get()) });
}

// BootstrapService::SaveRSU + AuthGranted: M = { Auth_Request, OTP_dt } ->
// E_K_dg({ Auth_Granted, OTP_dt, K_dg, K_g, CY_e, Auth_eg }); nullopt: no pending Auth_d matches (ignored)
std::optional<Bytes> authGranted(const std::string& session, const Bytes& in, uint64_t now)
{
    const wire::AuthRequest request = wire::unpackAuthRequest(in);

    // as the paper (BootstrapService::SaveRSU): every K_dg of an ECDH not yet bound to an activation, with every
    // pending Auth_d and every t in +-kOtpWindow slots around my own truncated clock; a match binds that K_dg to
    // that Auth_d (status active)
    const uint64_t tNow = otpSlot(now);

    // past its t_f an activation is no longer pending
    for (auto pending = gGateway.pending.begin(); pending != gGateway.pending.end();) {
        pending = now > pending->second.tf ? gGateway.pending.erase(pending) : std::next(pending);
    }

    std::string bound;              // the ECDH session whose K_dg matched
    auto match = gGateway.pending.end();
    uint64_t tMatch = 0;
    size_t unauthenticated = 0;
    for (const auto& [candidate, kDg] : gGateway.kdg) {
        if (gGateway.active.count(candidate) != 0) {
            continue; // K_dg already bound to an activation
        }
        ++unauthenticated;
        for (auto pending = gGateway.pending.begin(); pending != gGateway.pending.end() && match == gGateway.pending.end();
             ++pending) {
            for (uint64_t t = tNow - kOtpWindow; t <= tNow + kOtpWindow; ++t) {
                const Block otp = poly1305Aes(kDg, otpNonce(pending->second.authD, t), otpMessage());
                if (CRYPTO_memcmp(otp.data(), request.otp.data(), otp.size()) == 0) { // constant time
                    bound = candidate;
                    match = pending;
                    tMatch = t;
                    break;
                }
            }
        }
        if (match != gGateway.pending.end()) {
            break;
        }
    }
    if (match == gGateway.pending.end()) {
        check(false, session + ": OTP_dt matches no combination (" + std::to_string(unauthenticated)
            + " K_dg not yet authenticated x " + std::to_string(gGateway.pending.size()) + " pending Auth_d x "
            + std::to_string(2 * kOtpWindow + 1) + " slots around t = " + std::to_string(tNow) + "): ignored");
        return std::nullopt;
    }
    const long long slotOffset = static_cast<long long>(tMatch) - static_cast<long long>(tNow);
    check(true, session + ": OTP_dt matches the K_dg of the ECDH with " + bound + " and the Auth_d of the activation of "
        + match->first + ", with t = " + std::to_string(tMatch) + " (my slot " + (slotOffset >= 0 ? "+" : "")
        + std::to_string(slotOffset) + ")");

    // that K_dg is now bound to that Auth_d: status active, sealed for a restart
    gGateway.active[bound] = match->second;
    gGateway.pending.erase(match);
    saveState();

    // M = { Auth_Granted, OTP_dt, K_g, CY_e, Auth_eg }    (the paper's (10))
    wire::AuthGranted m;
    m.type = Auth_Granted;
    m.otp = request.otp;                                // OTP_dt: the one matched
    m.kG = gGateway.groupKey;                           // K_g
    m.esaPublicKey = gGateway.esaPublicKey;             // CY_e
    m.authEg = gGateway.active[bound].authEg;           // Auth_eg: lets the vehicle check CY_e
    Bytes sealed = aesGcmEncrypt(gGateway.kdg.at(bound), wire::pack(m)); // E_K_dg(M): AES-256-GCM
    print(session + ": Auth_Granted = E_K_dg(M), " + std::to_string(sealed.size()) + " bytes");
    return sealed;
}

// BootstrapService::Active02: E_K_dg({ Active_01, Auth_d, OTP_dt, Auth_de }) -> { Active_02, Auth_d, OTP_dt, Auth_de }
// for the ESA; nullopt: does not decrypt with this session's K_dg (ignored)
std::optional<Bytes> active02(const std::string& session, const Bytes& in)
{
    auto kDg = gGateway.kdg.find(session);
    if (kDg == gGateway.kdg.end()) {
        check(false, session + ": no K_dg for this session: ignored");
        return std::nullopt;
    }
    const auto plain = aesGcmDecrypt(kDg->second, in);
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
    const std::string authStr(request.auth.begin(), request.auth.end());
    auto it = gGateway.handovers.find(authStr);
    if (it == gGateway.handovers.end()) {
        check(false, session + ": Forwarding_Request auth matches no pending handover session: ignored");
        return std::nullopt;
    }

    const uint64_t tNow = otpSlot(now);
    bool otpValid = false;
    uint64_t tMatch = 0;
    const Bytes authBytes(request.auth.begin(), request.auth.end());
    const Bytes ktBytes(it->second.kt.begin(), it->second.kt.end());
    for (uint64_t t = tNow - kOtpWindow; t <= tNow + kOtpWindow; ++t) {
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

    // Fresh OTP'
    Block otpPrime = poly1305Aes(ktBytes, otpNonce(Bytes(authPrime.begin(), authPrime.end()), tNow), otpMessage());

    wire::ForwardingGranted m;
    m.type = Forwarding_Granted;
    m.nextRsuPublicKey = {}; // optional pre-load
    m.authPrime = authPrime;
    m.kG = gGateway.groupKey;
    m.otp = otpPrime;

    // Encrypted with KT_i
    Bytes sealed = aesGcmEncrypt(ktBytes, wire::pack(m));

    // Bind session
    gGateway.kdg[session] = ktBytes;
    gGateway.yv[session] = it->second.vehiclePublicKey;
    gGateway.handovers.erase(it);

    print(session + ": Forwarding_Granted = E_KT(M), " + std::to_string(sealed.size()) + " bytes");
    return sealed;
}

} // namespace

// ---------------------------------------------------------------------------------------------
// OT Key Manager (key_manager.h): what the Secure Marshaling reads of this state

bool gatewayReady()
{
    return gGateway.ready;
}

std::optional<VehicleKeys> findVehicleKeys(const Bytes& authD)
{
    // the activated sessions (an OTP matched in SaveRSU, or restored from the sealed state) and their K_dg
    for (const auto& [session, activation] : gGateway.active) {
        if (activation.authD.size() != authD.size()
            || CRYPTO_memcmp(activation.authD.data(), authD.data(), authD.size()) != 0) {
            continue;
        }
        const auto kDg = gGateway.kdg.find(session);
        if (kDg == gGateway.kdg.end()) {
            return std::nullopt;
        }
        return VehicleKeys{ session, kDg->second, gGateway.groupKey }; // one K_G for every vehicle of this RSU
    }
    return std::nullopt;
}

void enclavePrint(const std::string& text)
{
    print(text);
}

void enclaveCheck(bool ok, const std::string& text)
{
    check(ok, text);
}

// ---------------------------------------------------------------------------------------------

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
    gGateway.pending[session] = Activation{ Bytes(auth_d, auth_d + auth_d_len), t0, tf,
        Bytes(auth_eg, auth_eg + auth_eg_len) };
    print(std::string(session) + ": activation pending until t_f = " + seconds(tf) + " ("
        + std::to_string(gGateway.pending.size()) + " pending)");
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
    
        if (msg_type != Forwarding_Request && !withinWindow(name, current_ptp_time)) {
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
    if (!gGateway.ready) return GW_ERR_STATE;
    auto kDg = gGateway.kdg.find(session);
    auto yV = gGateway.yv.find(session);
    if (kDg == gGateway.kdg.end() || yV == gGateway.yv.end()) return GW_IGNORED;

    // tau_{i+2} = Poly1305_AES(K_dg, padding(t_i))[cite: 39]
    Block nonce{};
    for (int i = 0; i < 8; ++i) nonce[15 - i] = static_cast<uint8_t>(t_i >> (8 * i));
    Block tau = poly1305Aes(kDg->second, nonce, otpMessage());

    std::memcpy(out_tau, tau.data(), 16);
    std::memcpy(out_yv, yV->second.data(), yV->second.size());
    *yv_len = yV->second.size();
    return GW_OK;
}

int ecall_receive_forwarding_notice(const uint8_t* yv, size_t yv_len, const uint8_t* tau, uint8_t* out_yg, size_t* yg_len)
{
    if (!gGateway.ready) return GW_ERR_STATE;

    Bytes vehicleKey(yv, yv + yv_len);
    Block tauBlock;
    std::memcpy(tauBlock.data(), tau, 16);

    // 1. Generate Y_G_i+2 and X_G_i+2
    const auto keyG = newEcKey(kEcdhCurve);
    Bytes yg = publicKeyDer(keyG.get());
    
    // 2. K_dh_i = Y_V ^ X_G[cite: 39]
    Bytes kDh = ecdh(keyG.get(), publicKeyFromDer(vehicleKey).get());

    // 3. KT_i = Poly1305(K_dh_i, K_dh_i xor tau)[cite: 39]
    Block nonce{};
    for(int i=0; i<16; ++i) nonce[i] = kDh[i] ^ tauBlock[i];
    Block kt = poly1305Aes(kDh, nonce, otpMessage());

    // 4. auth_{i+2} = SHA256(tau)[cite: 39]
    Bytes tauBytes(tauBlock.begin(), tauBlock.end());
    Sha256 auth = sha256(tauBytes);

    HandoverSession hs;
    hs.authExpected = auth;
    hs.kt = kt;
    hs.vehiclePublicKey = vehicleKey;
    
    std::string authStr(auth.begin(), auth.end());
    gGateway.handovers[authStr] = hs;

    std::memcpy(out_yg, yg.data(), yg.size());
    *yg_len = yg.size();
    return GW_OK;
}
