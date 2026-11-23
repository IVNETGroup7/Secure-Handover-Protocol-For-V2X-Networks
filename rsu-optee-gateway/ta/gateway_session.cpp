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
constexpr size_t kMaxPendingHandovers = 64;
constexpr uint64_t kHandoverPendingTtlNs = 30ULL * 1000000000ULL;
constexpr uint32_t kMaxForwardingNoticesPerVehicle = 4;
constexpr uint32_t kMaxForwardingReqsPerSec = 5;
constexpr uint64_t kForwardingRateWindowNs = 1000000000ULL;
constexpr size_t kCloudSessionPreload = 3; // Standby ephemeral Cloud ECDH sessions pre-derived at init (0 ms rotation stall)

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

// Wiped list of derived Ascon keys used during the pending-ECDH Auth_Request sweep
struct WipedAsconKeyList
{
    std::vector<ascon::Key> keys;

    WipedAsconKeyList() = default;
    WipedAsconKeyList(const WipedAsconKeyList&) = delete;
    WipedAsconKeyList& operator=(const WipedAsconKeyList&) = delete;
    ~WipedAsconKeyList()
    {
        for (ascon::Key& key : keys) {
            ta_crypto::cleanse(key.data(), key.size());
        }
    }
};

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

Bytes deriveRsuPeerKey(const Bytes& sharedSecret, const Bytes& pubA, const Bytes& pubB)
{
    const bool aFirst = std::lexicographical_compare(pubA.begin(), pubA.end(), pubB.begin(), pubB.end());
    const Bytes& first = aFirst ? pubA : pubB;
    const Bytes& second = aFirst ? pubB : pubA;
    static constexpr char kLabel[] = "rsu-peer";
    Bytes material;
    material.reserve(sizeof(kLabel) - 1 + sharedSecret.size() + first.size() + second.size());
    material.insert(material.end(), kLabel, kLabel + sizeof(kLabel) - 1);
    material.insert(material.end(), sharedSecret.begin(), sharedSecret.end());
    material.insert(material.end(), first.begin(), first.end());
    material.insert(material.end(), second.begin(), second.end());
    const Sha256 digest = ta_crypto::sha256(material);
    ta_crypto::cleanse(material.data(), material.size());
    return Bytes(digest.begin(), digest.end());
}

template<typename ActiveMap>
auto findActiveSessionByCipher(ActiveMap& sessions, const std::string& hint, const Bytes& sealed,
    std::optional<Bytes>& outPlain) -> decltype(&sessions.begin()->second)
{
    for (auto& [_, active] : sessions) {
        if (!active.kDg.empty() && active.session == hint) {
            if (auto p = ta_crypto::aesGcmDecrypt(active.kDg, sealed)) {
                outPlain = std::move(p);
                return &active;
            }
        }
    }
    for (auto& [_, active] : sessions) {
        if (active.kDg.empty() || active.session == hint) {
            continue;
        }
        if (auto p = ta_crypto::aesGcmDecrypt(active.kDg, sealed)) {
            outPlain = std::move(p);
            return &active;
        }
    }
    return nullptr;
}

} // namespace

GatewayTaSession::~GatewayTaSession()
{
    ta_crypto::cleanse(mGroupKey.data(), mGroupKey.size());
    ta_crypto::cleanse(mEsaSessionKey.data(), mEsaSessionKey.size());
    ta_crypto::cleanse(mCloud.kEg.data(), mCloud.kEg.size());
    for (auto& pre : mCloud.preloaded) {
        ta_crypto::cleanse(pre.kEg.data(), pre.kEg.size());
    }
    for (auto& [_, peer] : mPeerRsus) {
        ta_crypto::cleanse(peer.kRsu.data(), peer.kRsu.size());
    }
    for (auto& ecdh : mPendingEcdh) {
        ta_crypto::cleanse(ecdh.kDg.data(), ecdh.kDg.size());
    }
    for (auto& [_, sess] : mActiveSessions) {
        ta_crypto::cleanse(sess.kDg.data(), sess.kDg.size());
    }
    for (auto& [_, handover] : mHandovers) {
        ta_crypto::cleanse(handover.keys.kDh.data(), handover.keys.kDh.size());
        ta_crypto::cleanse(handover.keys.kt.data(), handover.keys.kt.size());
        ta_crypto::cleanse(handover.keys.kt32.data(), handover.keys.kt32.size());
    }
}

void GatewayTaSession::setStorageId(const std::string& storageId, bool deleteExisting, OtpAlgo otpAlgo)
{
    mStorageId = storageId;
    mOtpAlgo = otpAlgo;
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

Block GatewayTaSession::computeMac(const Bytes& key32, OtpPurpose purpose, const Block& nonce, const Bytes& msg) const
{
    if (mOtpAlgo == OtpAlgo::Ascon) {
        const ScopedAsconKey key(key32, purpose);
        return computeAsconOtp(key.key, nonce, msg);
    }
    return ta_crypto::poly1305Aes(key32, nonce, msg);
}

Block GatewayTaSession::computeForwardingToken(const Bytes& kDg, uint64_t authSlot) const
{
    Block nonce{};
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] = static_cast<uint8_t>(authSlot >> (8 * i));
    }
    return computeMac(kDg, OtpPurpose::ForwardingToken, nonce, otpMessage());
}

HandoverKeys GatewayTaSession::computeHandoverKeys(const Bytes& kDh, const Block& tau) const
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
    keys.kt = computeMac(kDh, OtpPurpose::HandoverKey, nonce, otpMessage());

    Bytes material(keys.kt.begin(), keys.kt.end());
    material.insert(material.end(), kDh.begin(), kDh.end());
    const Sha256 kt32 = ta_crypto::sha256(material);
    keys.kt32.assign(kt32.begin(), kt32.end());
    ta_crypto::cleanse(material.data(), material.size());

    keys.auth = ta_crypto::sha256(Bytes(tau.begin(), tau.end()));
    Bytes primeMaterial(keys.kt.begin(), keys.kt.end());
    primeMaterial.insert(primeMaterial.end(), keys.auth.begin(), keys.auth.end());
    keys.authPrime = ta_crypto::sha256(primeMaterial);
    ta_crypto::cleanse(primeMaterial.data(), primeMaterial.size());
    return keys;
}

Block GatewayTaSession::computeForwardingOtp(const HandoverKeys& keys, uint64_t slot) const
{
    Block nonce{};
    std::copy_n(keys.auth.begin(), nonce.size(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] ^= static_cast<uint8_t>(slot >> (8 * i));
    }
    return computeMac(keys.kt32, OtpPurpose::ForwardingRequest, nonce, wire::forwardingRequestOtpData(keys.auth));
}

Block GatewayTaSession::computeForwardingGrantedOtp(const HandoverKeys& keys, uint64_t slot,
    const wire::ForwardingGranted& m) const
{
    Block nonce{};
    std::copy_n(keys.authPrime.begin(), nonce.size(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(15 - i)] ^= static_cast<uint8_t>(slot >> (8 * i));
    }
    return computeMac(keys.kt32, OtpPurpose::ForwardingGranted, nonce, wire::forwardingGrantedOtpData(m));
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
        wire::putUint(plain, 0, 8); // Conjecture 5: t_i stays volatile in TA RAM only
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

void GatewayTaSession::purgeExpiredHandovers(uint64_t now)
{
    for (auto it = mHandovers.begin(); it != mHandovers.end();) {
        if (now > it->second.createdAt && (now - it->second.createdAt) > kHandoverPendingTtlNs) {
            ta_crypto::cleanse(it->second.keys.kDh.data(), it->second.keys.kDh.size());
            ta_crypto::cleanse(it->second.keys.kt.data(), it->second.keys.kt.size());
            ta_crypto::cleanse(it->second.keys.kt32.data(), it->second.keys.kt32.size());
            it = mHandovers.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<NeighborRsuKey> GatewayTaSession::neighborRsuList() const
{
    std::vector<NeighborRsuKey> out;
    out.reserve(std::min(mPeerRsus.size(), kMaxNeighborRsus));
    for (const auto& [_, peer] : mPeerRsus) {
        if (out.size() >= kMaxNeighborRsus) {
            break;
        }
        out.push_back(NeighborRsuKey{ peer.name, peer.publicKeyDer });
    }
    return out;
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
    if (!mCloud.kEg.empty()) {
        ta_crypto::cleanse(mCloud.kEg.data(), mCloud.kEg.size());
    }
    if (!mCloud.preloaded.empty()) {
        mCloud.kEg = std::move(mCloud.preloaded.back().kEg);
        mCloud.ys = std::move(mCloud.preloaded.back().ys);
        mCloud.preloaded.pop_back();
    } else {
        const auto derived = ta_crypto::generateAndDeriveEcdh(mCloud.cloudPublicKeyDer);
        const Sha256 digest = ta_crypto::sha256(derived.sharedSecret);
        mCloud.kEg.assign(digest.begin(), digest.end());
        mCloud.ys = ta_crypto::base64Encode(derived.publicKeyDer);
    }
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

    // Pre-derive pending ECDH Ascon keys once for the reboot check & anonymous sweep (unused in Poly1305 mode)
    WipedAsconKeyList pendingAsconKeys;
    if (mOtpAlgo == OtpAlgo::Ascon) {
        pendingAsconKeys.keys.reserve(mPendingEcdh.size());
        for (const auto& ecdh : mPendingEcdh) {
            pendingAsconKeys.keys.push_back(deriveAsconOtpKey(ecdh.kDg, OtpPurpose::AuthRequest));
        }
    }
    auto pendingAuthReqOtp = [&](size_t idx, const Block& nonce) -> Block {
        if (mOtpAlgo == OtpAlgo::Ascon) {
            return computeAsconOtp(pendingAsconKeys.keys[idx], nonce, otpMessage());
        }
        return ta_crypto::poly1305Aes(mPendingEcdh[idx].kDg, nonce, otpMessage());
    };

    // Spec Step 7.1 & Section 5.3 (Reboot Protection):
    // Discard any Auth_Request from an already-active device WITHOUT disturbing its active session.
    for (const auto& [_, active] : mActiveSessions) {
        for (uint64_t t = tMin; t <= tMax; ++t) {
            const Block nonce = otpNonce(active.authD, t);
            const Block activeOtp = computeMac(active.kDg, OtpPurpose::AuthRequest, nonce, otpMessage());
            if (ta_crypto::constTimeCmp(activeOtp.data(), request.otp.data(), activeOtp.size()) == 0) {
                check(false, session + ": Auth_Request from already-active device (" + active.session
                    + "): discarded (active session preserved)");
                return std::nullopt;
            }
            for (size_t i = 0; i < mPendingEcdh.size(); ++i) {
                const Block candidate = pendingAuthReqOtp(i, nonce);
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

    for (size_t i = 0; i < mPendingEcdh.size() && pendingMatch == mPendingActivations.end(); ++i) {
        const auto ecdh = mPendingEcdh.begin() + static_cast<std::ptrdiff_t>(i);
        for (auto pending = mPendingActivations.begin(); pending != mPendingActivations.end(); ++pending) {
            if (now < pending->t0 || now > pending->tf) {
                continue; // Enforce both t_0 <= now <= t_f
            }
            bool matched = false;
            for (uint64_t t = tMin; t <= tMax; ++t) {
                const Block otp = pendingAuthReqOtp(i, otpNonce(pending->authD, t));
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

    // Spec Step 8: generate FRESH OTP_dt authenticating Auth_Granted under K_dg and Auth_d,
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
    m.nextRsus = neighborRsuList();
    m.otp = computeMac(active.kDg, OtpPurpose::AuthGranted, otpNonce(active.authD, tReply), wire::authGrantedOtpData(m));

    Bytes sealed = ta_crypto::aesGcmEncrypt(active.kDg, wire::pack(m));
    print(session + ": Auth_Granted = E_K_dg(M with fresh OTP_dt + " + std::to_string(m.nextRsus.size())
        + " neighbor key(s)), " + std::to_string(sealed.size()) + " bytes");
    return sealed;
}

std::optional<Bytes> GatewayTaSession::active02(const std::string& session, const Bytes& in, uint64_t now)
{
    // Locate the active session whose K_dg authenticates & decrypts Active_01 (AES-256-GCM).
    // Never modifies or erases mActiveSessions on decryption/validation failure!
    std::optional<Bytes> plain;
    ActiveSession* matched = findActiveSessionByCipher(mActiveSessions, session, in, plain);
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
        const Block expected = computeMac(matched->kDg, OtpPurpose::Active01, otpNonce(matched->authD, t), otpInput);
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
    const uint64_t taStartMs = ta_crypto::monotonicTimeMs();

    // Conjecture 4 (DoS mitigation): rate-limit Forwarding_Request per sender per 1 s window
    if (mForwardingRate.size() > 128) {
        for (auto it = mForwardingRate.begin(); it != mForwardingRate.end();) {
            if (now >= it->second.windowStartNs + kForwardingRateWindowNs) {
                it = mForwardingRate.erase(it);
            } else {
                ++it;
            }
        }
    }
    RateBucket& bucket = mForwardingRate[session];
    if (bucket.windowStartNs == 0 || now < bucket.windowStartNs
        || (now - bucket.windowStartNs) >= kForwardingRateWindowNs) {
        bucket.windowStartNs = now;
        bucket.count = 0;
    }
    if (++bucket.count > kMaxForwardingReqsPerSec) {
        check(false, session + ": Forwarding_Request rate limit exceeded: ignored");
        return std::nullopt;
    }

    const wire::ForwardingRequest request = wire::unpackForwardingRequest(in);
    purgeExpiredHandovers(now);

    auto match = mHandovers.end();
    for (auto handover = mHandovers.begin(); handover != mHandovers.end(); ++handover) {
        const Sha256& expected = handover->first;
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
    check(true, session + ": OTP = " + std::string(otpAlgoName(mOtpAlgo))
        + "(KT_i^32, auth_{i+2} xor t_c, Forwarding_Request) with t_c = "
        + std::to_string(tMatch) + " (my slot " + (slotOffset >= 0 ? "+" : "") + std::to_string(slotOffset) + ")");

    const std::string vehicle = handover.session;
    mActiveSessions[handover.authD] = ActiveSession{
        vehicle, handover.authD, Bytes(), now, now, handover.keys.kDh, handover.yv, tMatch, true, 0
    };
    saveState();

    const uint64_t taEndMs = ta_crypto::monotonicTimeMs();
    const uint64_t elapsedNs = taEndMs >= taStartMs ? (taEndMs - taStartMs) * 1000000ULL : 0ULL;
    const uint64_t tReply = otpSlot(now + elapsedNs);

    wire::ForwardingGranted m;
    m.type = Forwarding_Granted;
    m.nextRsus = neighborRsuList();
    m.authPrime = handover.keys.authPrime;
    m.kG = mGroupKey;
    m.otp = computeForwardingGrantedOtp(handover.keys, tReply, m);
    Bytes kt(handover.keys.kt.begin(), handover.keys.kt.end());
    Bytes sealed = ta_crypto::aesGcmEncrypt(kt, wire::pack(m));
    ta_crypto::cleanse(kt.data(), kt.size());
    ta_crypto::cleanse(handover.keys.kDh.data(), handover.keys.kDh.size());
    ta_crypto::cleanse(handover.keys.kt.data(), handover.keys.kt.size());
    ta_crypto::cleanse(handover.keys.kt32.data(), handover.keys.kt32.size());
    mHandovers.erase(match);
    print(vehicle + ": Forwarding_Granted = E_KT_i(M with fresh OTP' + " + std::to_string(m.nextRsus.size())
        + " neighbor key(s)), " + std::to_string(sealed.size()) + " bytes; " + vehicle
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
        const Block candidate = computeMac(keys->kDg, OtpPurpose::SecureData, nonce, message.sealedData);
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
        check(true, session + ": OTP_dt = " + std::string(otpAlgoName(mOtpAlgo))
            + "(K_dg, Auth_d xor t, AES(K_G, Data)) with t = "
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
        for (auto& pre : mCloud.preloaded) {
            ta_crypto::cleanse(pre.kEg.data(), pre.kEg.size());
        }
        mCloud.preloaded.clear();
        mCloud.preloaded.reserve(kCloudSessionPreload + 1);
        for (size_t i = 0; i < kCloudSessionPreload + 1; ++i) {
            const auto derived = ta_crypto::generateAndDeriveEcdh(mCloud.cloudPublicKeyDer);
            const Sha256 digest = ta_crypto::sha256(derived.sharedSecret);
            mCloud.preloaded.push_back(PrecomputedCloudSession{
                Bytes(digest.begin(), digest.end()),
                ta_crypto::base64Encode(derived.publicKeyDer)
            });
        }
        check(true, "HTTPS session: Cloud certificate verified against pinned CA (" + pinned->subject
            + ", P-256; " + std::to_string(kCloudSessionPreload) + " standby session(s) pre-derived)");
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

int GatewayTaSession::registerPeerRsu(const std::string& peerName, const Bytes& peerCertDer)
{
    if (!mReady || !mGatewayKey.valid() || mCaPublicKey.empty()) {
        check(false, "register_peer_rsu: gateway not initialized with Root CA");
        return GW_ERR_STATE;
    }
    if (peerName.empty() || peerCertDer.empty()) {
        return GW_ERR_ARGS;
    }

    std::string err;
    const auto peerPinned = ta_crypto::verifyCertDerSignedByCa(peerCertDer, mCaPublicKey, err);
    if (!peerPinned) {
        check(false, "register_peer_rsu: certificate for " + peerName + " rejected (" + err + ")");
        return GW_ERR_CRYPTO;
    }
    if (peerPinned->publicKeyDer == mGatewayKey.publicKeyDer()) {
        return GW_OK;
    }

    try {
        Bytes shared = mGatewayKey.deriveSharedSecret(peerPinned->publicKeyDer);
        Bytes kRsu = deriveRsuPeerKey(shared, mGatewayKey.publicKeyDer(), peerPinned->publicKeyDer);
        ta_crypto::cleanse(shared.data(), shared.size());
        if (auto it = mPeerRsus.find(peerName); it != mPeerRsus.end()) {
            ta_crypto::cleanse(it->second.kRsu.data(), it->second.kRsu.size());
        }
        mPeerRsus[peerName] = PeerRsu{ peerName, peerPinned->publicKeyDer, std::move(kRsu) };
        check(true, "register_peer_rsu: " + peerName + " (" + peerPinned->subject + ") CA-verified; K_rsu derived inside TA");
        return GW_OK;
    } catch (const std::exception& e) {
        check(false, std::string("register_peer_rsu: ") + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::sealForwardingNoticeForPeer(ActiveSession& active, const std::string& targetRsu, uint64_t slot,
    Bytes& outSealedNotice)
{
    outSealedNotice.clear();
    const auto peer = mPeerRsus.find(targetRsu);
    if (peer == mPeerRsus.end()) {
        check(false, active.session + ": no CA-verified K_rsu for peer RSU '" + targetRsu + "': ignored");
        return GW_IGNORED;
    }
    if (active.forwardingNoticesSent >= kMaxForwardingNoticesPerVehicle) {
        check(false, active.session + ": Forwarding_Notice fan-out cap ("
            + std::to_string(kMaxForwardingNoticesPerVehicle) + ") reached: ignored");
        return GW_IGNORED;
    }

    const Block tau = computeForwardingToken(active.kDg, slot);
    wire::ForwardingNotice notice;
    notice.type = Forwarding_Notice;
    notice.vehiclePublicKey = active.yV;
    notice.tau = tau;
    notice.authD = active.authD;
    notice.vehicleLabel = active.session;

    Bytes plain = wire::pack(notice);
    outSealedNotice = ta_crypto::aesGcmEncrypt(peer->second.kRsu, plain);
    ta_crypto::cleanse(plain.data(), plain.size());
    ++active.forwardingNoticesSent;

    print(active.session + ": Secrecy Forwarding: E_K_rsu(Forwarding_Notice) (" + std::to_string(outSealedNotice.size())
        + " B, t_i = " + std::to_string(slot) + ") sealed inside TA -> " + targetRsu + " (K_dg stays here)");
    return GW_OK;
}

int GatewayTaSession::handleHandoverPredict(const Bytes& inPkt, uint64_t currentPtpTime, std::string& outTargetRsu,
    Bytes& outSealedNotice)
{
    outTargetRsu.clear();
    outSealedNotice.clear();
    if (!mReady) {
        return GW_ERR_STATE;
    }
    if (inPkt.empty()) {
        return GW_ERR_ARGS;
    }

    try {
        std::optional<Bytes> plain;
        ActiveSession* matched = findActiveSessionByCipher(mActiveSessions, "", inPkt, plain);
        if (!matched || !plain) {
            check(false, "Handover_Predict: does not decrypt with any active K_dg: ignored");
            return GW_IGNORED;
        }
        const wire::HandoverPredict m = wire::unpackHandoverPredict(*plain);
        ta_crypto::cleanse(plain->data(), plain->size());

        if (m.type != Handover_Predict || m.targetRsu.empty()
            || m.authD.size() != matched->authD.size()
            || ta_crypto::constTimeCmp(m.authD.data(), matched->authD.data(), m.authD.size()) != 0) {
            check(false, matched->session + ": Handover_Predict has invalid inner fields: ignored");
            return GW_IGNORED;
        }

        const uint64_t tNow = otpSlot(currentPtpTime);
        uint64_t tMin = 0, tMax = 0;
        slotWindow(tNow, tMin, tMax);
        const Bytes otpInput = wire::handoverPredictOtpData(m.targetRsu);
        bool otpValid = false;
        for (uint64_t t = tMin; t <= tMax; ++t) {
            const Block expected = computeMac(matched->kDg, OtpPurpose::HandoverPredict, otpNonce(matched->authD, t),
                otpInput);
            if (ta_crypto::constTimeCmp(expected.data(), m.otp.data(), expected.size()) == 0) {
                otpValid = true;
                break;
            }
        }
        if (!otpValid) {
            check(false, matched->session + ": Handover_Predict OTP_dt invalid in t +- 1: ignored");
            return GW_IGNORED;
        }
        if (matched->authTime == 0 || matched->kDg.empty() || matched->yV.empty()) {
            check(false, matched->session + ": Handover_Predict without volatile t_i in TA RAM: ignored");
            return GW_IGNORED;
        }

        const int status = sealForwardingNoticeForPeer(*matched, m.targetRsu, matched->authTime, outSealedNotice);
        if (status == GW_OK) {
            outTargetRsu = m.targetRsu;
        }
        return status;
    } catch (const std::exception& e) {
        print(std::string("Handover_Predict error: ") + e.what());
        return GW_IGNORED;
    }
}

int GatewayTaSession::triggerHandover(const std::string& session, const std::string& targetRsu, uint64_t ti,
    Bytes& outSealedNotice)
{
    outSealedNotice.clear();
    if (!mReady) {
        return GW_ERR_STATE;
    }
    if (session.empty() || targetRsu.empty()) {
        return GW_ERR_ARGS;
    }

    try {
        ActiveSession* active = nullptr;
        for (auto& [_, candidate] : mActiveSessions) {
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
        return sealForwardingNoticeForPeer(*active, targetRsu, slot, outSealedNotice);
    } catch (const std::exception& e) {
        print(session + ": error: " + e.what());
        return GW_ERR_CRYPTO;
    }
}

int GatewayTaSession::receiveForwardingNotice(const std::string& senderRsu, const Bytes& sealedNotice,
    uint64_t currentPtpTime)
{
    if (!mReady || !mGatewayKey.valid()) {
        return GW_ERR_STATE;
    }
    if (senderRsu.empty() || sealedNotice.empty()) {
        return GW_ERR_ARGS;
    }

    const auto peer = mPeerRsus.find(senderRsu);
    if (peer == mPeerRsus.end()) {
        check(false, "Forwarding_Notice from untrusted/unregistered RSU '" + senderRsu + "': ignored");
        return GW_IGNORED;
    }

    try {
        auto plain = ta_crypto::aesGcmDecrypt(peer->second.kRsu, sealedNotice);
        if (!plain) {
            check(false, "Forwarding_Notice from " + senderRsu + " failed K_rsu GCM authentication: ignored");
            return GW_IGNORED;
        }
        const wire::ForwardingNotice notice = wire::unpackForwardingNotice(*plain);
        ta_crypto::cleanse(plain->data(), plain->size());

        if (notice.type != Forwarding_Notice || notice.vehiclePublicKey.empty()
            || notice.authD.empty() || notice.vehicleLabel.empty()) {
            check(false, "Forwarding_Notice from " + senderRsu + " has invalid fields: ignored");
            return GW_IGNORED;
        }

        purgeExpiredHandovers(currentPtpTime);

        // Compute K_dh_i = ECDH(X_gw, Y_V) directly with this gateway's CA-certified keypair (no slow keygen!)
        const Bytes kDh = mGatewayKey.deriveSharedSecret(notice.vehiclePublicKey);
        HandoverKeys keys = computeHandoverKeys(kDh, notice.tau);

        if (mHandovers.find(keys.auth) == mHandovers.end() && mHandovers.size() >= kMaxPendingHandovers) {
            auto oldest = mHandovers.begin();
            for (auto it = mHandovers.begin(); it != mHandovers.end(); ++it) {
                if (it->second.createdAt < oldest->second.createdAt) {
                    oldest = it;
                }
            }
            ta_crypto::cleanse(oldest->second.keys.kDh.data(), oldest->second.keys.kDh.size());
            ta_crypto::cleanse(oldest->second.keys.kt.data(), oldest->second.keys.kt.size());
            ta_crypto::cleanse(oldest->second.keys.kt32.data(), oldest->second.keys.kt32.size());
            mHandovers.erase(oldest);
        }

        HandoverSession handover;
        handover.session = notice.vehicleLabel;
        handover.yv = notice.vehiclePublicKey;
        handover.tau = notice.tau;
        handover.keys = std::move(keys);
        handover.authD = notice.authD;
        handover.createdAt = currentPtpTime;
        const Sha256 key = handover.keys.auth;
        mHandovers[key] = std::move(handover);

        print(notice.vehicleLabel + ": Forwarding_Notice decrypted under K_rsu (" + senderRsu
            + "): K_dh_i = ECDH(X_gw, Y_V), KT_i, auth_{i+2}, auth'_{i+2} kept in TA ("
            + std::to_string(mHandovers.size()) + " pending)");
        return GW_OK;
    } catch (const std::exception& e) {
        print(senderRsu + ": Forwarding_Notice error: " + e.what());
        return GW_IGNORED;
    }
}
