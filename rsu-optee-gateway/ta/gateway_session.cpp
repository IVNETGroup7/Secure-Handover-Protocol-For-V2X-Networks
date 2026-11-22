#include "gateway_session.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>

namespace
{

constexpr uint8_t kSealedStateVersion = 3; // 3: Auth_d-keyed active sessions + confirmed flag
constexpr size_t kMaxPendingEcdh = 64;     // Bound unauthenticated ECDH pool against memory exhaustion

std::string seconds(uint64_t ns)
{
    const int64_t signedNs = static_cast<int64_t>(ns);
    const bool neg = signedNs < 0;
    const uint64_t absNs = neg ? static_cast<uint64_t>(-signedNs) : static_cast<uint64_t>(signedNs);
    const unsigned long long sec = static_cast<unsigned long long>(absNs / 1000000000ULL);
    const unsigned long long usec = static_cast<unsigned long long>((absNs % 1000000000ULL) / 1000ULL);
    char text[48];
    std::snprintf(text, sizeof(text), "%s%llu.%06llu s", neg ? "-" : "", sec, usec);
    return text;
}

uint64_t otpSlot(uint64_t ns)
{
    return static_cast<uint64_t>(std::floor((static_cast<int64_t>(ns) / 1e9) / kOtpTimeStep));
}

void slotWindow(uint64_t tNow, uint64_t& tMin, uint64_t& tMax)
{
    const uint64_t w = static_cast<uint64_t>(kOtpWindow);
    tMin = tNow >= w ? tNow - w : 0;
    tMax = tNow + w;
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

Bytes deriveEsaKey(const Bytes& sharedSecret, const Bytes& gwPubKey, const Bytes& esaPubKey)
{
    Bytes material;
    material.reserve(sharedSecret.size() + gwPubKey.size() + esaPubKey.size());
    material.insert(material.end(), sharedSecret.begin(), sharedSecret.end());
    material.insert(material.end(), gwPubKey.begin(), gwPubKey.end());
    material.insert(material.end(), esaPubKey.begin(), esaPubKey.end());
    const Sha256 digest = ta_crypto::sha256(material);
    ta_crypto::cleanse(material.data(), material.size());
    return Bytes(digest.begin(), digest.end());
}

} // namespace

GatewayTaSession::~GatewayTaSession()
{
    ta_crypto::cleanse(mGroupKey.data(), mGroupKey.size());
    ta_crypto::cleanse(mEsaSessionKey.data(), mEsaSessionKey.size());
    ta_crypto::cleanse(mCloud.kEg.data(), mCloud.kEg.size());
    for (auto& ecdh : mPendingEcdh) {
        ta_crypto::cleanse(ecdh.kDg.data(), ecdh.kDg.size());
    }
    for (auto& [_, sess] : mActiveSessions) {
        ta_crypto::cleanse(sess.kDg.data(), sess.kDg.size());
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
    wire::putUint(plain, mActiveSessions.size(), 2);
    for (const auto& [_, active] : mActiveSessions) {
        wire::putField(plain, Bytes(active.session.begin(), active.session.end()));
        wire::putField(plain, active.kDg);
        wire::putField(plain, active.authD);
        wire::putField(plain, active.authEg);
        wire::putUint(plain, active.t0, 8);
        wire::putUint(plain, active.tf, 8);
        wire::putField(plain, active.yV);
        wire::putUint(plain, active.authTime, 8);
        wire::putUint(plain, active.confirmed ? 1 : 0, 1);
    }

    const size_t size = plain.size();
    const bool ok = ta_crypto::savePersistentState(mStorageId, plain);
    ta_crypto::cleanse(plain.data(), plain.size());
    if (!ok) {
        print("sealed state not saved to Secure Storage (the sessions live in TA memory only)");
        return;
    }
    print("state sealed to OP-TEE Secure Storage (" + mStorageId + "): K_g + "
        + std::to_string(mActiveSessions.size()) + " active session(s), " + std::to_string(size) + " bytes");
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
    reader.field(); // CY_e: the CA-verified ESA key from initGateway wins
    const size_t count = static_cast<size_t>(reader.uint(2));
    for (size_t i = 0; i < count; ++i) {
        const Bytes sessionBytes = reader.field();
        ActiveSession active;
        active.session.assign(sessionBytes.begin(), sessionBytes.end());
        active.kDg = reader.field();
        active.authD = reader.field();
        active.authEg = reader.field();
        active.t0 = reader.uint(8);
        active.tf = reader.uint(8);
        active.yV = reader.field();
        active.authTime = reader.uint(8);
        active.confirmed = reader.uint(1) != 0;
        const Bytes key = active.authD;
        mActiveSessions[key] = std::move(active);
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

void GatewayTaSession::purgeExpiredActivations(uint64_t now)
{
    for (auto it = mPendingActivations.begin(); it != mPendingActivations.end();) {
        if (now > it->tf) {
            // Spec Step 3.2: expired pending record must be deleted and Auth_d marked compromised/excluded
            mCompromisedAuthD.insert(it->authD);
            print("pending activation expired past t_f = " + seconds(it->tf) + ": deleted and Auth_d "
                + hex(it->authD).substr(0, 16) + "... marked compromised");
            it = mPendingActivations.erase(it);
        } else {
            ++it;
        }
    }
}

bool GatewayTaSession::isCompromisedAuthD(const Bytes& authD) const
{
    for (const Bytes& bad : mCompromisedAuthD) {
        if (bad.size() == authD.size() && ta_crypto::constTimeCmp(bad.data(), authD.data(), bad.size()) == 0) {
            return true;
        }
    }
    return false;
}

bool GatewayTaSession::isActiveAuthD(const Bytes& authD) const
{
    for (const auto& [existing, _] : mActiveSessions) {
        if (existing.size() == authD.size()
            && ta_crypto::constTimeCmp(existing.data(), authD.data(), existing.size()) == 0) {
            return true;
        }
    }
    return false;
}

std::optional<GatewayTaSession::VehicleKeys> GatewayTaSession::findVehicleKeys(const Bytes& authD) const
{
    for (const auto& [_, active] : mActiveSessions) {
        if (active.authD.size() != authD.size()
            || ta_crypto::constTimeCmp(active.authD.data(), authD.data(), active.authD.size()) != 0) {
            continue;
        }
        if (active.kDg.empty()) {
            return std::nullopt;
        }
        return VehicleKeys{ active.session, active.kDg, mGroupKey };
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
        + "..., K_eg = SHA256(ECDH(X_s, Y_cloud)) kept in the TA, X_s dropped");
}

Bytes GatewayTaSession::ecdhResponse(const std::string& session, const Bytes& in)
{
    const wire::Ecdh request = wire::unpackEcdh(in);
    const auto derived = ta_crypto::generateAndDeriveEcdh(request.publicKey);
    if (mPendingEcdh.size() >= kMaxPendingEcdh) {
        ta_crypto::cleanse(mPendingEcdh.front().kDg.data(), mPendingEcdh.front().kDg.size());
        mPendingEcdh.erase(mPendingEcdh.begin());
    }
    // Spec Step 5: add to pool of unauthenticated pending ECDH secrets; NEVER touch mActiveSessions!
    mPendingEcdh.push_back(PendingEcdh{ derived.sharedSecret, request.publicKey, session });
    print(session + ": ECDH done, K_dg added to unauthenticated pending pool ("
        + std::to_string(mPendingEcdh.size()) + " pending)");

    return wire::pack(wire::Ecdh{ ECDH_Response, derived.publicKeyDer });
}

std::optional<Bytes> GatewayTaSession::authGranted(const std::string& session, const Bytes& in, uint64_t now)
{
    const uint64_t taStartMs = ta_crypto::monotonicTimeMs();
    const wire::AuthRequest request = wire::unpackAuthRequest(in);
    const uint64_t tNow = otpSlot(now);
    uint64_t tMin = 0, tMax = 0;
    slotWindow(tNow, tMin, tMax);

    purgeExpiredActivations(now);

    // Spec Step 7.1 & Section 5.3 (Reboot Protection):
    // Discard any Auth_Request from an already-active device WITHOUT disturbing its active session.
    for (const auto& [_, active] : mActiveSessions) {
        for (uint64_t t = tMin; t <= tMax; ++t) {
            const Block nonce = otpNonce(active.authD, t);
            const Block activeOtp = ta_crypto::poly1305Aes(active.kDg, nonce, otpMessage());
            if (ta_crypto::constTimeCmp(activeOtp.data(), request.otp.data(), activeOtp.size()) == 0) {
                check(false, session + ": Auth_Request from already-active device (" + active.session
                    + "): discarded (active session preserved)");
                return std::nullopt;
            }
            for (const auto& ecdh : mPendingEcdh) {
                const Block candidate = ta_crypto::poly1305Aes(ecdh.kDg, nonce, otpMessage());
                if (ta_crypto::constTimeCmp(candidate.data(), request.otp.data(), candidate.size()) == 0) {
                    check(false, session + ": Auth_Request from already-active device (" + active.session
                        + " via new ECDH): discarded (active session preserved)");
                    return std::nullopt;
                }
            }
        }
    }

    // Spec Step 7.2-7.3: anonymous sweep over (unauthenticated pending K_dg) x (pending Auth_d in [t_0, t_f]) x (t +- 1)
    auto ecdhMatch = mPendingEcdh.end();
    auto pendingMatch = mPendingActivations.end();
    uint64_t tMatch = 0;
    size_t inWindowCount = 0;
    for (const auto& pending : mPendingActivations) {
        if (pending.t0 <= now && now <= pending.tf) {
            ++inWindowCount;
        }
    }

    for (auto ecdh = mPendingEcdh.begin(); ecdh != mPendingEcdh.end() && pendingMatch == mPendingActivations.end(); ++ecdh) {
        for (auto pending = mPendingActivations.begin(); pending != mPendingActivations.end(); ++pending) {
            if (now < pending->t0 || now > pending->tf) {
                continue; // Enforce both t_0 <= now <= t_f
            }
            bool matched = false;
            for (uint64_t t = tMin; t <= tMax; ++t) {
                const Block otp = ta_crypto::poly1305Aes(ecdh->kDg, otpNonce(pending->authD, t), otpMessage());
                if (ta_crypto::constTimeCmp(otp.data(), request.otp.data(), otp.size()) == 0) {
                    ecdhMatch = ecdh;
                    pendingMatch = pending;
                    tMatch = t;
                    matched = true;
                    break;
                }
            }
            if (matched) {
                break;
            }
        }
    }

    if (pendingMatch == mPendingActivations.end()) {
        check(false, session + ": OTP_dt matches no combination (" + std::to_string(mPendingEcdh.size())
            + " pending K_dg x " + std::to_string(inWindowCount) + " in-window pending Auth_d ["
            + std::to_string(mPendingActivations.size()) + " total] x " + std::to_string(2 * kOtpWindow + 1)
            + " slots around t = " + std::to_string(tNow) + "): ignored");
        return std::nullopt;
    }

    // Defensive check: never overwrite an already-active Auth_d
    if (isActiveAuthD(pendingMatch->authD)) {
        check(false, session + ": matched Auth_d is already active: ignored");
        return std::nullopt;
    }

    const long long slotOffset = static_cast<long long>(tMatch) - static_cast<long long>(tNow);
    check(true, session + ": t_0 = " + seconds(pendingMatch->t0) + " <= t = " + seconds(now) + " <= t_f = "
        + seconds(pendingMatch->tf));
    check(true, session + ": OTP_dt matched pending K_dg (" + ecdhMatch->peerLabel + ") and anonymous Auth_d "
        + hex(pendingMatch->authD).substr(0, 16) + "... with t = " + std::to_string(tMatch)
        + " (my slot " + (slotOffset >= 0 ? "+" : "") + std::to_string(slotOffset) + ")");

    const Bytes authDKey = pendingMatch->authD;
    const std::string peerName = !ecdhMatch->peerLabel.empty() ? ecdhMatch->peerLabel : session;
    ActiveSession activated{
        peerName,
        pendingMatch->authD,
        pendingMatch->authEg,
        pendingMatch->t0,
        pendingMatch->tf,
        ecdhMatch->kDg,
        ecdhMatch->yV,
        tMatch,
        false
    };
    mActiveSessions[authDKey] = std::move(activated);
    mPendingActivations.erase(pendingMatch);
    ta_crypto::cleanse(ecdhMatch->kDg.data(), ecdhMatch->kDg.size());
    mPendingEcdh.erase(ecdhMatch);
    saveState();

    // Spec Step 8: generate FRESH Poly1305 OTP_dt authenticating Auth_Granted under K_dg and Auth_d,
    // advancing the timestamp by elapsed TEE / Secure Storage sealing time before sending.
    const uint64_t taEndMs = ta_crypto::monotonicTimeMs();
    const uint64_t elapsedNs = taEndMs >= taStartMs ? (taEndMs - taStartMs) * 1000000ULL : 0ULL;
    const uint64_t tReply = otpSlot(now + elapsedNs);
    const ActiveSession& active = mActiveSessions.at(authDKey);
    wire::AuthGranted m;
    m.type = Auth_Granted;
    m.kG = mGroupKey;
    m.esaPublicKey = mEsaPublicKey;
    m.authEg = active.authEg;
    m.otp = ta_crypto::poly1305Aes(active.kDg, otpNonce(active.authD, tReply), wire::authGrantedOtpData(m));

    Bytes sealed = ta_crypto::aesGcmEncrypt(active.kDg, wire::pack(m));
    print(session + ": Auth_Granted = E_K_dg(M with fresh OTP_dt), " + std::to_string(sealed.size()) + " bytes");
    return sealed;
}

std::optional<Bytes> GatewayTaSession::active02(const std::string& session, const Bytes& in, uint64_t now)
{
    // Locate the active session whose K_dg authenticates & decrypts Active_01 (AES-256-GCM).
    // Never modifies or erases mActiveSessions on decryption/validation failure!
    ActiveSession* matched = nullptr;
    std::optional<Bytes> plain;

    for (auto& [_, active] : mActiveSessions) {
        if (!active.kDg.empty() && active.session == session) {
            if (auto p = ta_crypto::aesGcmDecrypt(active.kDg, in)) {
                matched = &active;
                plain = std::move(p);
                break;
            }
        }
    }
    if (!matched) {
        for (auto& [_, active] : mActiveSessions) {
            if (active.kDg.empty() || active.session == session) {
                continue;
            }
            if (auto p = ta_crypto::aesGcmDecrypt(active.kDg, in)) {
                matched = &active;
                plain = std::move(p);
                break;
            }
        }
    }
    if (!matched || !plain) {
        check(false, session + ": Active_01 does not decrypt with any active K_dg: ignored");
        return std::nullopt;
    }
    check(true, session + ": E_K_dg(Active_01) decrypted with active K_dg (GCM tag valid)");

    wire::Active m = wire::unpackActive(*plain);
    ta_crypto::cleanse(plain->data(), plain->size());
    if (m.type != Active_01) {
        check(false, session + ": unexpected inner type in Active_01: ignored");
        return std::nullopt;
    }
    if (matched->confirmed) {
        check(false, session + ": duplicate Active_01 for already-confirmed session: ignored");
        return std::nullopt;
    }
    if (m.authD.size() != matched->authD.size()
        || ta_crypto::constTimeCmp(m.authD.data(), matched->authD.data(), m.authD.size()) != 0) {
        check(false, session + ": Auth_d inside Active_01 does not match active session: ignored");
        return std::nullopt;
    }

    // Verify fresh Active_01 OTP_dt in [t-1, t+1] before forwarding to ESA
    const uint64_t tNow = otpSlot(now);
    uint64_t tMin = 0, tMax = 0;
    slotWindow(tNow, tMin, tMax);
    const Bytes otpInput = wire::activeOtpData(m.authD, m.authDe);
    bool otpValid = false;
    for (uint64_t t = tMin; t <= tMax; ++t) {
        const Block expected = ta_crypto::poly1305Aes(matched->kDg, otpNonce(matched->authD, t), otpInput);
        if (ta_crypto::constTimeCmp(expected.data(), m.otp.data(), expected.size()) == 0) {
            otpValid = true;
            break;
        }
    }
    if (!otpValid) {
        check(false, session + ": Active_01 OTP_dt invalid for K_dg and Auth_d in t +- 1: ignored");
        return std::nullopt;
    }
    check(true, session + ": Active_01 Auth_d and fresh OTP_dt verified inside TA");

    matched->confirmed = true;
    saveState();

    // Spec Step 11 & Theorem 2: re-encrypt Active_02 under mutually-authenticated K_esa inside TA
    // so Gateway Normal World (REE) and backhaul observers NEVER see plaintext OTP_dt, Auth_d, or Auth_de!
    m.type = Active_02;
    Bytes plainOut = wire::pack(m);
    Bytes sealedForEsa = ta_crypto::aesGcmEncrypt(mEsaSessionKey, plainOut);
    ta_crypto::cleanse(plainOut.data(), plainOut.size());
    print(session + ": Active_02 re-encrypted under K_esa (" + std::to_string(sealedForEsa.size())
        + " bytes: Normal World cannot read OTP_dt) -> ESA");
    return sealedForEsa;
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
    uint64_t tMin = 0, tMax = 0;
    slotWindow(tNow, tMin, tMax);
    bool otpOk = false;
    uint64_t tMatch = 0;
    for (uint64_t t = tMin; t <= tMax && !otpOk; ++t) {
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
    mActiveSessions[handover.authD] = ActiveSession{
        vehicle, handover.authD, Bytes(), now, now, handover.keys.kDh, handover.yv, tMatch, true
    };
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
    uint64_t tMin = 0, tMax = 0;
    slotWindow(tNow, tMin, tMax);
    bool otpOk = false;
    uint64_t tMatch = 0;
    for (uint64_t t = tMin; t <= tMax && !otpOk; ++t) {
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

int GatewayTaSession::initIdentity(Bytes& outGatewayPubKey)
{
    outGatewayPubKey.clear();
    try {
        mGatewayKey = ta_crypto::EcdhKeyPair::generate();
        outGatewayPubKey = mGatewayKey.publicKeyDer();
        print("init_identity: generated P-256 Gateway keypair inside TA (X_gw stays in TEE, CY_g = "
            + std::to_string(outGatewayPubKey.size()) + " bytes)");
        return GW_OK;
    } catch (const std::exception& e) {
        print(std::string("init_identity: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::initGateway(const Bytes& caPubKey, const Bytes& gwCertDer, const Bytes& esaCertDer,
    const Bytes& groupKey)
{
    if (!mGatewayKey.valid()) {
        check(false, "init_gateway: gateway identity not generated (call init_identity first)");
        return GW_ERR_STATE;
    }
    if (caPubKey.empty() || gwCertDer.empty() || esaCertDer.empty()) {
        return GW_ERR_ARGS;
    }
    const std::string caCurve = ta_crypto::verifySubjectPublicKeyInfo(caPubKey);
    if (caCurve.empty()) {
        check(false, "init_gateway: CA public key is not a valid P-256 key");
        return GW_ERR_CRYPTO;
    }

    // Verify Gateway's own certificate against Root CA and confirm it binds our TEE-resident CY_g
    std::string err;
    const auto gwPinned = ta_crypto::verifyCertDerSignedByCa(gwCertDer, caPubKey, err);
    if (!gwPinned) {
        check(false, "init_gateway: gateway certificate rejected (" + err + ")");
        return GW_ERR_CRYPTO;
    }
    if (gwPinned->publicKeyDer != mGatewayKey.publicKeyDer()) {
        check(false, "init_gateway: gateway certificate public key does not match TEE identity key");
        return GW_ERR_CRYPTO;
    }

    // Verify ESA's X.509 certificate against Root CA and extract verified CY_e
    const auto esaPinned = ta_crypto::verifyCertDerSignedByCa(esaCertDer, caPubKey, err);
    if (!esaPinned) {
        check(false, "init_gateway: ESA certificate rejected (" + err + ")");
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

    // Derive mutually-authenticated Gateway <-> ESA HTTPS channel key K_esa inside Secure World
    Bytes shared;
    try {
        shared = mGatewayKey.deriveSharedSecret(esaPinned->publicKeyDer);
    } catch (const std::exception& e) {
        check(false, std::string("init_gateway: K_esa ECDH failed: ") + e.what());
        return GW_ERR_CRYPTO;
    }
    Bytes kEsa = deriveEsaKey(shared, mGatewayKey.publicKeyDer(), esaPinned->publicKeyDer);
    ta_crypto::cleanse(shared.data(), shared.size());

    if (!mEsaSessionKey.empty()) {
        ta_crypto::cleanse(mEsaSessionKey.data(), mEsaSessionKey.size());
    }
    mCaPublicKey = caPubKey;
    mGatewayCert = gwCertDer;
    mEsaPublicKey = esaPinned->publicKeyDer;
    mEsaSessionKey = std::move(kEsa);
    mGroupKey = kg;
    check(true, "init_gateway: CA root pinned; Gateway (" + gwPinned->subject + ") and ESA (" + esaPinned->subject
        + ") certificates CA-verified; K_esa derived inside TA, K_g "
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
    if (!mReady || mCaPublicKey.empty()) {
        check(false, "HTTPS session: gateway not initialized with Root CA");
        return GW_ERR_STATE;
    }
    if (cloudCertPem.empty() || host.empty() || gateway.empty()) {
        return GW_ERR_ARGS;
    }
    try {
        std::string errorReason;
        const auto pinned = ta_crypto::verifyCertPemSignedByCa(cloudCertPem, mCaPublicKey, errorReason);
        if (!pinned) {
            check(false, "HTTPS session: cloud certificate rejected (" + errorReason + ")");
            return errorReason.find("not a PEM") != std::string::npos ? GW_ERR_ARGS : GW_ERR_CRYPTO;
        }
        mCloud.cloudPublicKeyDer = pinned->publicKeyDer;
        mCloud.host = host;
        mCloud.gateway = gateway;
        mCloud.ready = true;
        check(true, "HTTPS session: Cloud certificate verified against pinned CA (" + pinned->subject
            + ", P-256)");
        newCloudSession();
        return GW_OK;
    } catch (const std::exception& e) {
        print(std::string("HTTPS session: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::addActivationToken(const Bytes& encryptedToken, uint64_t currentPtpTime)
{
    if (!mReady || mEsaSessionKey.empty()) {
        return GW_ERR_STATE;
    }
    if (encryptedToken.empty()) {
        return GW_ERR_ARGS;
    }
    try {
        // Spec Step 3: decrypt Activation_Token inside TEE using mutually-authenticated K_esa
        auto plain = ta_crypto::aesGcmDecrypt(mEsaSessionKey, encryptedToken);
        if (!plain) {
            check(false, "Activation_Token does not decrypt with K_esa (GCM tag invalid): ignored");
            return GW_IGNORED;
        }
        const wire::ActivationToken token = wire::unpackActivationToken(*plain);
        ta_crypto::cleanse(plain->data(), plain->size());

        if (token.type != Activation_Token || token.authD.empty() || token.authEg.empty() || token.t0 >= token.tf) {
            check(false, "Activation_Token has invalid fields or t_0 >= t_f: ignored");
            return GW_IGNORED;
        }

        purgeExpiredActivations(currentPtpTime);

        if (isCompromisedAuthD(token.authD)) {
            check(false, "Activation_Token for excluded/compromised Auth_d " + hex(token.authD).substr(0, 16)
                + "...: rejected");
            return GW_IGNORED;
        }
        if (isActiveAuthD(token.authD)) {
            check(false, "Activation_Token for already-active Auth_d " + hex(token.authD).substr(0, 16)
                + "...: rejected (active session preserved)");
            return GW_IGNORED;
        }

        // Replace any existing pending entry for the same Auth_d, otherwise append anonymously
        bool updated = false;
        for (auto& existing : mPendingActivations) {
            if (existing.authD.size() == token.authD.size()
                && ta_crypto::constTimeCmp(existing.authD.data(), token.authD.data(), existing.authD.size()) == 0) {
                existing = PendingActivation{ token.authD, token.t0, token.tf, token.authEg };
                updated = true;
                break;
            }
        }
        if (!updated) {
            mPendingActivations.push_back(PendingActivation{ token.authD, token.t0, token.tf, token.authEg });
        }
        check(true, "E_K_esa(Activation_Token) decrypted inside TA: anonymous Auth_d "
            + hex(token.authD).substr(0, 16) + "... pending for [" + seconds(token.t0) + ", " + seconds(token.tf)
            + "] (" + std::to_string(mPendingActivations.size()) + " pending)");
        return GW_OK;
    } catch (const std::exception& e) {
        print(std::string("Activation_Token error: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::handleBootstrap(int msgType, const std::string& session, const Bytes& inPkt,
    uint64_t currentPtpTime, Bytes& outPkt, int& outType)
{
    outType = -1;
    outPkt.clear();
    if (!mReady) {
        return GW_ERR_STATE;
    }
    if (inPkt.empty()) {
        return GW_ERR_ARGS;
    }
    if (msgType != ECDH_Request && msgType != Auth_Request && msgType != Active_01) {
        return GW_ERR_ARGS;
    }

    const std::string peer = session.empty() ? std::string("unknown") : session;
    try {
        std::optional<Bytes> out;
        int type = -1;
        switch (msgType) {
            case ECDH_Request: out = ecdhResponse(peer, inPkt); type = ECDH_Response; break;
            case Auth_Request: out = authGranted(peer, inPkt, currentPtpTime); type = Auth_Granted; break;
            case Active_01:    out = active02(peer, inPkt, currentPtpTime); type = Active_02; break;
        }
        if (!out) {
            return GW_IGNORED;
        }
        outPkt = std::move(*out);
        outType = type;
        return GW_OK;
    } catch (const std::exception& e) {
        print(peer + ": error: " + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::handleForwardingRequest(const std::string& session, const Bytes& inPkt,
    uint64_t currentPtpTime, Bytes& outPkt)
{
    outPkt.clear();
    if (!mReady) {
        return GW_ERR_STATE;
    }
    if (session.empty() || inPkt.empty()) {
        return GW_ERR_ARGS;
    }

    try {
        std::optional<Bytes> out = forwardingGranted(session, inPkt, currentPtpTime);
        if (!out) {
            return GW_IGNORED;
        }
        outPkt = std::move(*out);
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
        const ActiveSession* active = nullptr;
        for (const auto& [_, candidate] : mActiveSessions) {
            if (candidate.session == session && (!active || candidate.authTime >= active->authTime)) {
                active = &candidate;
            }
        }
        if (!active || active->kDg.empty() || active->yV.empty()) {
            check(false, session + ": Secrecy Forwarding of a session not active here (or without Y_V): ignored");
            return GW_IGNORED;
        }
        if (ti == 0 && active->authTime == 0) {
            check(false, session + ": Secrecy Forwarding without t_i (activated before t_i was kept): ignored");
            return GW_IGNORED;
        }
        const uint64_t slot = ti != 0 ? ti : active->authTime;
        outTau = computeForwardingToken(active->kDg, slot);
        outYv = active->yV;
        outAuthD = active->authD;
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
