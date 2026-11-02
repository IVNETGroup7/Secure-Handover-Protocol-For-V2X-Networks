#include "gateway_session.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>

namespace
{

constexpr uint8_t kSealedStateVersion = 2; // 2: Y_V and t_i per session (Secrecy Forwarding)

std::string seconds(uint64_t ns)
{
    char text[32];
    std::snprintf(text, sizeof(text), "%.6f s", static_cast<int64_t>(ns) / 1e9);
    return text;
}

uint64_t otpSlot(uint64_t ns)
{
    return static_cast<uint64_t>(std::floor((static_cast<int64_t>(ns) / 1e9) / kOtpTimeStep));
}

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

std::string toJson(const SmartData& data)
{
    return "{\"Location\":" + std::to_string(data.location)
        + ",\"Timing\":" + std::to_string(data.timing)
        + ",\"Metadata\":" + std::to_string(data.metadata)
        + ",\"Value\":\"" + ta_crypto::base64Encode(data.value) + "\""
        + ",\"Trust\":\"" + hex(data.authD) + "\"}";
}

} // namespace

GatewayTaSession::~GatewayTaSession()
{
    ta_crypto::cleanse(mGroupKey.data(), mGroupKey.size());
    ta_crypto::cleanse(mCloud.kEg.data(), mCloud.kEg.size());
    for (auto& [_, k] : mKdg) {
        ta_crypto::cleanse(k.data(), k.size());
    }
}

void GatewayTaSession::setStorageId(const std::string& storageId, bool deleteExisting)
{
    mStorageId = storageId;
    if (deleteExisting) {
        ta_crypto::deletePersistentState(mStorageId);
    }
}

std::string GatewayTaSession::takeLogs()
{
    std::string out = std::move(mLogs);
    mLogs.clear();
    return out;
}

void GatewayTaSession::print(const std::string& text)
{
    mLogs += text + "\n";
}

void GatewayTaSession::check(bool ok, const std::string& text)
{
    print((ok ? kCheckOk : kCheckFailed) + text);
}

Block GatewayTaSession::computeForwardingToken(const Bytes& kDg, uint64_t authSlot)
{
    Block nonce{};
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] = static_cast<uint8_t>(authSlot >> (8 * i));
    }
    return ta_crypto::poly1305Aes(kDg, nonce, otpMessage());
}

HandoverKeys GatewayTaSession::computeHandoverKeys(const Bytes& kDh, const Block& tau)
{
    if (kDh.size() != 32) {
        throw std::runtime_error("Secrecy Forwarding: K_dh needs 32 bytes (got " + std::to_string(kDh.size()) + ")");
    }
    HandoverKeys keys;
    keys.kDh = kDh;

    Block nonce{};
    for (size_t j = 0; j < nonce.size(); ++j) {
        nonce[j] = static_cast<uint8_t>(kDh[j] ^ tau[j]);
    }
    keys.kt = ta_crypto::poly1305Aes(kDh, nonce, otpMessage());

    Bytes material(keys.kt.begin(), keys.kt.end());
    material.insert(material.end(), kDh.begin(), kDh.end());
    const Sha256 kt32 = ta_crypto::sha256(material);
    keys.kt32.assign(kt32.begin(), kt32.end());

    keys.auth = ta_crypto::sha256(Bytes(tau.begin(), tau.end()));
    return keys;
}

Block GatewayTaSession::computeForwardingOtp(const HandoverKeys& keys, uint64_t slot)
{
    Block nonce{};
    std::copy_n(keys.auth.begin(), nonce.size(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] ^= static_cast<uint8_t>(slot >> (8 * i));
    }
    return ta_crypto::poly1305Aes(keys.kt32, nonce, otpMessage());
}

void GatewayTaSession::saveState()
{
    Bytes plain;
    wire::putUint(plain, kSealedStateVersion, 1);
    wire::putField(plain, mGroupKey);
    wire::putField(plain, mEsaPublicKey);
    wire::putUint(plain, mActive.size(), 2);
    for (const auto& [session, activation] : mActive) {
        const auto kDg = mKdg.find(session);
        wire::putField(plain, Bytes(session.begin(), session.end()));
        wire::putField(plain, kDg != mKdg.end() ? kDg->second : Bytes());
        wire::putField(plain, activation.authD);
        wire::putField(plain, activation.authEg);
        wire::putUint(plain, activation.t0, 8);
        wire::putUint(plain, activation.tf, 8);
        const auto yV = mYv.find(session);
        const auto tI = mAuthTime.find(session);
        wire::putField(plain, yV != mYv.end() ? yV->second : Bytes());
        wire::putUint(plain, tI != mAuthTime.end() ? tI->second : 0, 8);
    }

    const size_t size = plain.size();
    const bool ok = ta_crypto::savePersistentState(mStorageId, plain);
    ta_crypto::cleanse(plain.data(), plain.size());
    if (!ok) {
        print("sealed state not saved to Secure Storage (the sessions live in TA memory only)");
        return;
    }
    print("state sealed to OP-TEE Secure Storage (" + mStorageId + "): K_g + "
        + std::to_string(mActive.size()) + " active session(s), " + std::to_string(size) + " bytes");
}

bool GatewayTaSession::loadState(bool keepGroupKey)
{
    std::optional<Bytes> plainOpt = ta_crypto::loadPersistentState(mStorageId);
    if (!plainOpt || plainOpt->empty()) {
        return false;
    }
    Bytes& plain = *plainOpt;
    wire::Reader reader(plain);
    if (reader.uint(1) != kSealedStateVersion) {
        ta_crypto::cleanse(plain.data(), plain.size());
        print("sealed state ignored: unknown version");
        return false;
    }
    Bytes groupKey = reader.field();
    reader.field(); // CY_e: the one the ESA presents now wins
    const size_t count = static_cast<size_t>(reader.uint(2));
    for (size_t i = 0; i < count; ++i) {
        const Bytes session = reader.field();
        const std::string name(session.begin(), session.end());
        mKdg[name] = reader.field();
        Activation activation;
        activation.authD = reader.field();
        activation.authEg = reader.field();
        activation.t0 = reader.uint(8);
        activation.tf = reader.uint(8);
        mActive[name] = activation;
        mYv[name] = reader.field();
        mAuthTime[name] = reader.uint(8);
    }
    if (!keepGroupKey && groupKey.size() == kGroupKeySize) {
        mGroupKey = groupKey;
    }
    ta_crypto::cleanse(plain.data(), plain.size());
    ta_crypto::cleanse(groupKey.data(), groupKey.size());
    print("sealed state restored from OP-TEE Secure Storage: " + std::to_string(count) + " active session(s)"
        + (keepGroupKey ? "" : ", K_g of before the restart"));
    return true;
}

bool GatewayTaSession::withinWindow(const std::string& session, uint64_t now)
{
    const Activation* activation = nullptr;
    if (auto pending = mPending.find(session); pending != mPending.end()) {
        activation = &pending->second;
    } else if (auto active = mActive.find(session); active != mActive.end()) {
        activation = &active->second;
    }
    if (activation && activation->t0 <= now && now <= activation->tf) {
        check(true, session + ": t_0 = " + seconds(activation->t0) + " <= t = " + seconds(now) + " <= t_f = "
            + seconds(activation->tf));
        return true;
    }

    check(false, session + ": aborted: " + (activation ? "t = " + seconds(now) + " outside [t_0, t_f] = ["
        + seconds(activation->t0) + ", " + seconds(activation->tf) + "]" : std::string("no activation window for this session")));
    mKdg.erase(session);
    mPending.erase(session);
    mActive.erase(session);
    mYv.erase(session);
    mAuthTime.erase(session);
    return false;
}

std::optional<GatewayTaSession::VehicleKeys> GatewayTaSession::findVehicleKeys(const Bytes& authD) const
{
    for (const auto& [session, activation] : mActive) {
        if (activation.authD.size() != authD.size()
            || ta_crypto::constTimeCmp(activation.authD.data(), authD.data(), authD.size()) != 0) {
            continue;
        }
        const auto kDg = mKdg.find(session);
        if (kDg == mKdg.end()) {
            return std::nullopt;
        }
        return VehicleKeys{ session, kDg->second, mGroupKey };
    }
    return std::nullopt;
}

void GatewayTaSession::newCloudSession()
{
    const auto derived = ta_crypto::generateAndDeriveEcdh(mCloud.cloudPublicKeyDer);
    if (!mCloud.kEg.empty()) {
        ta_crypto::cleanse(mCloud.kEg.data(), mCloud.kEg.size());
    }
    const Sha256 digest = ta_crypto::sha256(derived.sharedSecret);
    mCloud.kEg.assign(digest.begin(), digest.end());
    mCloud.ys = ta_crypto::base64Encode(derived.publicKeyDer);
    mCloud.messages = 0;
    ++mCloud.number;
    print("HTTPS session #" + std::to_string(mCloud.number) + " with the cloud: Y_s = " + mCloud.ys.substr(36, 16)
        + "..., K_eg = SHA256(ECDH(X_s, Y_e)) kept in the TA, X_s dropped");
}

Bytes GatewayTaSession::ecdhResponse(const std::string& session, const Bytes& in)
{
    const wire::Ecdh request = wire::unpackEcdh(in);
    mYv[session] = request.publicKey; // Y_V: kept for the Secrecy Forwarding of this vehicle

    const auto derived = ta_crypto::generateAndDeriveEcdh(request.publicKey);
    mKdg[session] = derived.sharedSecret;
    mActive.erase(session);
    print(session + ": ECDH done, K_dg kept in the TA");

    return wire::pack(wire::Ecdh{ ECDH_Response, derived.publicKeyDer });
}

std::optional<Bytes> GatewayTaSession::authGranted(const std::string& session, const Bytes& in, uint64_t now)
{
    const wire::AuthRequest request = wire::unpackAuthRequest(in);
    const uint64_t tNow = otpSlot(now);

    for (auto pending = mPending.begin(); pending != mPending.end();) {
        pending = now > pending->second.tf ? mPending.erase(pending) : std::next(pending);
    }

    std::string bound;
    auto match = mPending.end();
    uint64_t tMatch = 0;
    size_t unauthenticated = 0;
    for (const auto& [candidate, kDg] : mKdg) {
        if (mActive.count(candidate) != 0) {
            continue;
        }
        ++unauthenticated;
        for (auto pending = mPending.begin(); pending != mPending.end() && match == mPending.end(); ++pending) {
            for (uint64_t t = tNow - kOtpWindow; t <= tNow + kOtpWindow; ++t) {
                const Block otp = ta_crypto::poly1305Aes(kDg, otpNonce(pending->second.authD, t), otpMessage());
                if (ta_crypto::constTimeCmp(otp.data(), request.otp.data(), otp.size()) == 0) {
                    bound = candidate;
                    match = pending;
                    tMatch = t;
                    break;
                }
            }
        }
        if (match != mPending.end()) {
            break;
        }
    }
    if (match == mPending.end()) {
        check(false, session + ": OTP_dt matches no combination (" + std::to_string(unauthenticated)
            + " K_dg not yet authenticated x " + std::to_string(mPending.size()) + " pending Auth_d x "
            + std::to_string(2 * kOtpWindow + 1) + " slots around t = " + std::to_string(tNow) + "): ignored");
        return std::nullopt;
    }
    const long long slotOffset = static_cast<long long>(tMatch) - static_cast<long long>(tNow);
    check(true, session + ": OTP_dt matches the K_dg of the ECDH with " + bound + " and the Auth_d of the activation of "
        + match->first + ", with t = " + std::to_string(tMatch) + " (my slot " + (slotOffset >= 0 ? "+" : "")
        + std::to_string(slotOffset) + ")");

    mActive[bound] = match->second;
    mAuthTime[bound] = tMatch;
    mPending.erase(match);
    saveState();

    wire::AuthGranted m;
    m.type = Auth_Granted;
    m.otp = request.otp;
    m.kG = mGroupKey;
    m.esaPublicKey = mEsaPublicKey;
    m.authEg = mActive[bound].authEg;
    Bytes sealed = ta_crypto::aesGcmEncrypt(mKdg.at(bound), wire::pack(m));
    print(session + ": Auth_Granted = E_K_dg(M), " + std::to_string(sealed.size()) + " bytes");
    return sealed;
}

std::optional<Bytes> GatewayTaSession::active02(const std::string& session, const Bytes& in)
{
    auto kDg = mKdg.find(session);
    if (kDg == mKdg.end()) {
        check(false, session + ": no K_dg for this session: ignored");
        return std::nullopt;
    }
    const auto plain = ta_crypto::aesGcmDecrypt(kDg->second, in);
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

std::optional<Bytes> GatewayTaSession::forwardingGranted(const std::string& session, const Bytes& in, uint64_t now)
{
    const wire::ForwardingRequest request = wire::unpackForwardingRequest(in);

    auto match = mHandovers.end();
    for (auto handover = mHandovers.begin(); handover != mHandovers.end(); ++handover) {
        const Sha256& expected = handover->second.keys.auth;
        if (ta_crypto::constTimeCmp(expected.data(), request.auth.data(), expected.size()) == 0) {
            match = handover;
        }
    }
    if (match == mHandovers.end()) {
        check(false, session + ": auth_{i+2} of no announced handover (" + std::to_string(mHandovers.size())
            + " pending): ignored");
        return std::nullopt;
    }
    HandoverSession& handover = match->second;
    check(true, session + ": auth_{i+2} = SHA256(tau_{i+2}) of the handover of " + handover.session);

    const uint64_t tNow = otpSlot(now);
    bool otpOk = false;
    uint64_t tMatch = 0;
    for (uint64_t t = tNow - kOtpWindow; t <= tNow + kOtpWindow && !otpOk; ++t) {
        const Block candidate = computeForwardingOtp(handover.keys, t);
        if (ta_crypto::constTimeCmp(candidate.data(), request.otp.data(), candidate.size()) == 0) {
            otpOk = true;
            tMatch = t;
        }
    }
    if (!otpOk) {
        check(false, session + ": OTP does not match KT_i and auth_{i+2} in " + std::to_string(2 * kOtpWindow + 1)
            + " slots around t = " + std::to_string(tNow) + ": ignored");
        return std::nullopt;
    }
    const long long slotOffset = static_cast<long long>(tMatch) - static_cast<long long>(tNow);
    check(true, session + ": OTP = Poly1305(KT_i, auth_{i+2} xor t_c, m) with t_c = " + std::to_string(tMatch)
        + " (my slot " + (slotOffset >= 0 ? "+" : "") + std::to_string(slotOffset) + ")");

    const std::string vehicle = handover.session;
    mPending.erase(vehicle);
    mActive[vehicle] = Activation{ handover.authD, now, now, Bytes() };
    mKdg[vehicle] = handover.keys.kDh;
    mYv[vehicle] = handover.yv;
    mAuthTime[vehicle] = tMatch;
    saveState();

    wire::ForwardingGranted m;
    m.type = Forwarding_Granted;
    m.nextRsuPublicKey = {};
    m.authPrime = ta_crypto::sha256(Bytes(request.auth.begin(), request.auth.end()));
    m.kG = mGroupKey;
    m.otp = request.otp;
    Bytes kt(handover.keys.kt.begin(), handover.keys.kt.end());
    Bytes sealed = ta_crypto::aesGcmEncrypt(kt, wire::pack(m));
    ta_crypto::cleanse(kt.data(), kt.size());
    ta_crypto::cleanse(handover.keys.kt.data(), handover.keys.kt.size());
    ta_crypto::cleanse(handover.keys.kt32.data(), handover.keys.kt32.size());
    mHandovers.erase(match);
    print(vehicle + ": Forwarding_Granted = E_KT_i(M), " + std::to_string(sealed.size()) + " bytes; " + vehicle
        + " active here (K_dh_i as its K_dg)");
    return sealed;
}

int GatewayTaSession::marshal(const Bytes& otPacket, uint64_t now, Bytes& outItPkt)
{
    const bool traced = mTracedSizes.insert(otPacket.size()).second;

    DataMessage message;
    try {
        if (!otPacket.empty() && otPacket[0] == Secure_Data) {
            const wire::SecureData m = wire::unpackSecureData(otPacket);
            message = DataMessage{ m.cipherData, m.authD, m.otp };
        } else {
            message = unpackDataMessage(otPacket);
        }
    } catch (const std::exception& e) {
        check(false, std::string("Secure Marshaling: not an OT packet (") + e.what() + "): ignored");
        return GW_IGNORED;
    }

    const auto keys = findVehicleKeys(message.authD);
    if (!keys) {
        check(false, "Secure Marshaling: Auth_d " + hex(message.authD).substr(0, 16)
            + "... is no activated vehicle: ignored");
        return GW_IGNORED;
    }
    const std::string& session = keys->session;

    std::optional<Bytes> plain = ta_crypto::aesGcmDecrypt(keys->kG, message.sealedData);
    if (!plain) {
        check(false, session + ": AES(K_G, Data) does not decrypt with K_G (GCM tag invalid): ignored");
        return GW_IGNORED;
    }
    SmartData data;
    try {
        data = unpackSmartData(*plain);
    } catch (const std::exception& e) {
        ta_crypto::cleanse(plain->data(), plain->size());
        check(false, session + ": Data is not a SmartData (" + e.what() + "): ignored");
        return GW_IGNORED;
    }
    ta_crypto::cleanse(plain->data(), plain->size());
    auto refuse = [&](const std::string& why) {
        ta_crypto::cleanse(data.value.data(), data.value.size());
        check(false, session + ": " + why + ": ignored");
        return GW_IGNORED;
    };
    if (data.authD.size() != message.authD.size()
        || ta_crypto::constTimeCmp(data.authD.data(), message.authD.data(), data.authD.size()) != 0) {
        return refuse("the Auth_d inside Data is not the packet's Auth_d");
    }
    if (traced) {
        check(true, session + ": AES(K_G, Data) decrypts with K_G (GCM tag valid, Value = "
            + std::to_string(data.value.size()) + " B)");
    }

    const uint64_t tNow = dataOtpSlot(static_cast<int64_t>(now));
    bool otpOk = false;
    uint64_t tMatch = 0;
    for (uint64_t t = tNow - kOtpWindow; t <= tNow + kOtpWindow && !otpOk; ++t) {
        Block nonce{};
        std::copy_n(message.authD.begin(), nonce.size(), nonce.begin());
        for (int i = 0; i < 8; ++i) {
            nonce[static_cast<size_t>(15 - i)] ^= static_cast<uint8_t>(t >> (8 * i));
        }
        const Block candidate = ta_crypto::poly1305Aes(keys->kDg, nonce, message.sealedData);
        if (ta_crypto::constTimeCmp(candidate.data(), message.otp.data(), candidate.size()) == 0) {
            otpOk = true;
            tMatch = t;
        }
    }
    if (!otpOk) {
        return refuse("OTP_dt does not match K_dg and AES(K_G, Data) in " + std::to_string(2 * kOtpWindow + 1)
            + " slots around t = " + std::to_string(tNow));
    }
    if (traced) {
        const long long offset = static_cast<long long>(tMatch) - static_cast<long long>(tNow);
        check(true, session + ": OTP_dt = Poly1305(K_dg, Auth_d xor t, AES(K_G, Data)) with t = "
            + std::to_string(tMatch) + " (my slot " + (offset >= 0 ? "+" : "") + std::to_string(offset) + ")");
    }

    Bytes json;
    {
        std::string text = toJson(data);
        json.assign(text.begin(), text.end());
        ta_crypto::cleanse(&text[0], text.size());
    }
    ta_crypto::cleanse(data.value.data(), data.value.size());

    if (mCloud.messages >= kMessagesPerSession) {
        newCloudSession();
    }
    const Bytes body = ta_crypto::aesGcmEncrypt(mCloud.kEg, json);
    ++mCloud.messages;
    ta_crypto::cleanse(json.data(), json.size());
    const std::string header = std::string("POST ") + kSmartDataPath + " HTTP/1.1\r\n"
        + "Host: " + mCloud.host + "\r\n"
        + "Content-Type: application/octet-stream\r\n"
        + "X-Encrypted: AES-256-GCM(K_eg, application/json)\r\n"
        + kSessionKeyHeader + ": " + mCloud.ys + "\r\n"
        + "X-Gateway: " + mCloud.gateway + "\r\n"
        + "X-Vehicle: " + session + "\r\n"
        + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";

    outItPkt.resize(header.size() + body.size());
    std::copy(header.begin(), header.end(), outItPkt.begin());
    std::copy(body.begin(), body.end(), outItPkt.begin() + static_cast<long>(header.size()));
    if (traced) {
        print(session + ": JSON -> AES(K_eg, JSON) = " + std::to_string(body.size()) + " B (session #"
            + std::to_string(mCloud.number) + "), with its HTTPS header: IT packet = " + std::to_string(outItPkt.size()) + " B");
    }
    return GW_OK;
}

int GatewayTaSession::initGateway(const Bytes& gwCert, const Bytes& esaPubKey, const Bytes& groupKey)
{
    if (esaPubKey.empty()) {
        return GW_ERR_ARGS;
    }
    const std::string curve = ta_crypto::verifySubjectPublicKeyInfo(esaPubKey);
    if (curve.empty()) {
        check(false, "init_gateway: CY_e is not a valid public key");
        return GW_ERR_CRYPTO;
    }

    Bytes kg;
    if (!groupKey.empty()) {
        if (groupKey.size() != kGroupKeySize) {
            return GW_ERR_ARGS;
        }
        kg = groupKey;
    } else {
        kg = ta_crypto::randomBytes(kGroupKeySize);
    }

    mGatewayCert = gwCert;
    mEsaPublicKey = esaPubKey;
    mGroupKey = kg;
    print("init_gateway: CY_e " + curve + " (" + std::to_string(esaPubKey.size()) + " bytes), K_g "
        + (!groupKey.empty() ? "given" : "generated inside") + " (" + std::to_string(kg.size()) + " bytes)");

    try {
        loadState(!groupKey.empty());
    } catch (const std::exception& e) {
        print(std::string("sealed state ignored: ") + e.what());
    }
    mReady = true;
    return GW_OK;
}

int GatewayTaSession::initCloudSession(const std::string& cloudCertPem, const std::string& host,
    const std::string& gateway)
{
    if (cloudCertPem.empty() || host.empty() || gateway.empty()) {
        return GW_ERR_ARGS;
    }
    try {
        std::string errorReason;
        const auto pinned = ta_crypto::verifySelfSignedP256CertPem(cloudCertPem, errorReason);
        if (!pinned) {
            check(false, errorReason);
            return errorReason.find("not a PEM") != std::string::npos ? GW_ERR_ARGS : GW_ERR_CRYPTO;
        }
        mCloud.cloudPublicKeyDer = pinned->publicKeyDer;
        mCloud.host = host;
        mCloud.gateway = gateway;
        mCloud.ready = true;
        check(true, "HTTPS session: CY_e of the cloud pinned (" + pinned->subject
            + ", P-256, self-signature valid)");
        newCloudSession();
        return GW_OK;
    } catch (const std::exception& e) {
        print(std::string("HTTPS session: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::addActivationToken(const std::string& session, uint64_t t0, uint64_t tf, const Bytes& authD,
    const Bytes& authEg)
{
    if (!mReady) {
        return GW_ERR_STATE;
    }
    if (session.empty() || authD.empty() || authEg.empty() || t0 >= tf) {
        return GW_ERR_ARGS;
    }
    mPending[session] = Activation{ authD, t0, tf, authEg };
    print(session + ": activation pending until t_f = " + seconds(tf) + " ("
        + std::to_string(mPending.size()) + " pending)");
    return GW_OK;
}

int GatewayTaSession::handleBootstrap(int msgType, const std::string& session, const Bytes& inPkt,
    uint64_t currentPtpTime, Bytes& outPkt, int& outType)
{
    outType = -1;
    outPkt.clear();
    if (!mReady) {
        return GW_ERR_STATE;
    }
    if (session.empty() || inPkt.empty()) {
        return GW_ERR_ARGS;
    }
    if (msgType != ECDH_Request && msgType != Auth_Request && msgType != Active_01 && msgType != Forwarding_Request) {
        return GW_ERR_ARGS;
    }

    try {
        if (msgType != Forwarding_Request && !withinWindow(session, currentPtpTime)) {
            return GW_IGNORED;
        }

        std::optional<Bytes> out;
        int type = -1;
        switch (msgType) {
            case ECDH_Request:       out = ecdhResponse(session, inPkt); type = ECDH_Response; break;
            case Auth_Request:       out = authGranted(session, inPkt, currentPtpTime); type = Auth_Granted; break;
            case Active_01:          out = active02(session, inPkt); type = Active_02; break;
            case Forwarding_Request: out = forwardingGranted(session, inPkt, currentPtpTime); type = Forwarding_Granted; break;
        }
        if (!out) {
            return GW_IGNORED;
        }
        outPkt = std::move(*out);
        outType = type;
        return GW_OK;
    } catch (const std::exception& e) {
        print(session + ": error: " + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::secureMarshalOtToIt(const Bytes& otPkt, uint64_t currentPtpTime, Bytes& outItPkt)
{
    outItPkt.clear();
    if (otPkt.empty()) {
        return GW_ERR_ARGS;
    }
    if (!mReady) {
        return GW_ERR_STATE;
    }
    if (!mCloud.ready) {
        print("Secure Marshaling: no HTTPS session with the cloud (init_cloud_session first)");
        return GW_ERR_STATE;
    }
    try {
        return marshal(otPkt, currentPtpTime, outItPkt);
    } catch (const std::exception& e) {
        print(std::string("Secure Marshaling: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::triggerHandover(const std::string& session, uint64_t ti, Block& outTau, Bytes& outYv,
    Bytes& outAuthD)
{
    outYv.clear();
    outAuthD.clear();
    if (!mReady) {
        return GW_ERR_STATE;
    }
    if (session.empty()) {
        return GW_ERR_ARGS;
    }

    try {
        const auto active = mActive.find(session);
        const auto kDg = mKdg.find(session);
        const auto yV = mYv.find(session);
        const auto tI = mAuthTime.find(session);
        if (active == mActive.end() || kDg == mKdg.end() || yV == mYv.end() || yV->second.empty()) {
            check(false, session + ": Secrecy Forwarding of a session not active here (or without Y_V): ignored");
            return GW_IGNORED;
        }
        if (ti == 0 && tI == mAuthTime.end()) {
            check(false, session + ": Secrecy Forwarding without t_i (activated before t_i was kept): ignored");
            return GW_IGNORED;
        }
        const uint64_t slot = ti != 0 ? ti : tI->second;
        outTau = computeForwardingToken(kDg->second, slot);
        outYv = yV->second;
        outAuthD = active->second.authD;
        print(session + ": Secrecy Forwarding: tau_{i+2} = Poly1305(K_dg, t_i = " + std::to_string(slot)
            + ", m), with Y_V and Auth_d for the Forwarding_Notice (K_dg stays here)");
        return GW_OK;
    } catch (const std::exception& e) {
        print(session + ": error: " + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::receiveForwardingNotice(const std::string& session, const Bytes& yv, const Block& tau,
    const Bytes& authD, Bytes& outYg)
{
    outYg.clear();
    if (!mReady) {
        return GW_ERR_STATE;
    }
    if (session.empty() || yv.empty() || authD.empty()) {
        return GW_ERR_ARGS;
    }

    try {
        HandoverSession handover;
        handover.session = session;
        handover.yv = yv;
        handover.tau = tau;
        handover.authD = authD;

        const auto derived = ta_crypto::generateAndDeriveEcdh(handover.yv);
        handover.keys = computeHandoverKeys(derived.sharedSecret, handover.tau);
        mHandovers[handover.session] = handover;
        outYg = derived.publicKeyDer;

        print(handover.session + ": Forwarding_Notice: K_dh_i = ECDH(X_G, Y_V), KT_i and auth_{i+2} kept in the "
            "TA until the Forwarding_Request (" + std::to_string(mHandovers.size()) + " pending)");
        return GW_OK;
    } catch (const std::exception& e) {
        print(session + ": error: " + e.what());
        return GW_ERR_CRYPTO;
    }
}

