#include "HandoverService.h"
#include "BootstrapService.h"
#include "Crypto.h"
#include "Trace.h"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <stdexcept>
#include <openssl/crypto.h>

static inline uint64_t otpSlot(int64_t ns)
{
    return static_cast<uint64_t>(std::floor((static_cast<double>(ns) / 1e9) / kOtpTimeStep));
}

static inline Block otpNonce(const Bytes& auth, uint64_t t)
{
    Block nonce{};
    const size_t n = std::min(auth.size(), nonce.size());
    std::copy_n(auth.begin(), n, nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[15 - i] ^= static_cast<uint8_t>(t >> (8 * i));
    }
    return nonce;
}

static inline const Bytes& otpMessage()
{
    static const Bytes m(kOtpMessage, kOtpMessage + std::char_traits<char>::length(kOtpMessage));
    return m;
}

HandoverService::HandoverService(const Config& config)
    : mName(config.name), mRole(config.role), mGroupKey(config.groupKey)
{
    if (mRole == Role::Rsu && mGroupKey.empty()) {
        mGroupKey = randomBytes(kGroupKeySize);
    }
}

void HandoverService::initVehicle(const BootstrapResult& context)
{
    if (mRole != Role::Vehicle) {
        throw std::runtime_error(myName() + ": initVehicle called on non-vehicle");
    }
    mCurrentRsu = context.rsu;
    mKdg = context.kDg;
    mGroupKey = context.kG;
    mAuthD = context.authD;
    mEcdhKey = context.ecdhKey;
}

void HandoverService::registerVehicle(const std::string& vehicle, const Bytes& kDg, const Bytes& yV)
{
    if (mRole != Role::Rsu) {
        throw std::runtime_error(myName() + ": registerVehicle called on non-RSU");
    }
    mSessions[vehicle] = VehicleSession{ vehicle, kDg, yV };
}

void HandoverService::triggerHandover(const std::string& vehicle, const std::string& nextRsu, const Bytes& nextRsuPublicKey)
{
    if (mRole != Role::Rsu) {
        throw std::runtime_error(myName() + ": triggerHandover is only for RSU");
    }
    auto it = mSessions.find(vehicle);
    if (it == mSessions.end() || it->second.kDg.empty() || it->second.yV.empty()) {
        throw std::runtime_error(myName() + ": cannot hand over vehicle " + vehicle + " (no session keys/Y_V)");
    }

    const uint64_t tNow = otpSlot(SimTime::now().ns());
    mTi = tNow;

    Block nonce{};
    for (int i = 0; i < 8; ++i) nonce[15 - i] = static_cast<uint8_t>(mTi >> (8 * i));
    const Block tau = poly1305Aes(it->second.kDg, nonce, otpMessage());

    // If next RSU public key was pre-provided, send Handover_Command directly
    if (!nextRsuPublicKey.empty()) {
        HandoverCommandPayload cmd;
        cmd.type = Handover_Command;
        cmd.targetRsuPublicKey = nextRsuPublicKey;
        cmd.ti = mTi;
        sendBootstrap(Handover_Command, vehicle, 0, 0, vehicle, pack(cmd));
    }

    // Send Forwarding_Notice to Next RSU over HTTPS / Backhaul
    ForwardingNoticePayload notice;
    notice.type = Forwarding_Notice;
    notice.ti = mTi;
    notice.vehiclePublicKey = it->second.yV;
    notice.tau = tau;
    sendBootstrap(Forwarding_Notice, nextRsu, 0, 0, vehicle, pack(notice));
}

void HandoverService::indicate(const BootstrapMsg& msg)
{
    if (!isForMe(msg)) return;
    dispatch(msg);
}

void HandoverService::handleHttps(const BootstrapMsg& msg)
{
    if (!isForMe(msg)) return;
    dispatch(msg);
}

bool HandoverService::isForMe(const BootstrapMsg& msg) const
{
    const std::string destination = msg.getDestination();
    return destination == myName() ||
           (msg.getType() == Forwarding_Request && mRole == Role::Rsu);
}

void HandoverService::dispatch(const BootstrapMsg& msg)
{
    switch (msg.getType()) {
        case Forwarding_Notice:  handleForwardingNotice(msg); break;   // Target RSU
        case Handover_Command:   handleHandoverCommand(msg); break;    // Vehicle
        case Forwarding_Request: handleForwardingRequest(msg); break;  // Target RSU
        case Forwarding_Granted: handleForwardingGranted(msg); break;  // Vehicle
        default:
            break;
    }
}

void HandoverService::handleForwardingNotice(const BootstrapMsg& received)
{
    printStep("ForwardingNotice", &received);
    const ForwardingNoticePayload notice = unpackForwardingNotice(received.payload());
    for (const std::string& line : describe(notice)) {
        printDetail(line);
    }

    // 1. Generate Y_G and X_G
    const auto keyG = newEcKey(kEcdhCurve);
    const Bytes yg = publicKeyDer(keyG.get());

    // 2. K_dh = Y_V ^ X_G
    const Bytes kDh = ecdh(keyG.get(), publicKeyFromDer(notice.vehiclePublicKey).get());

    // 3. KT_mac = Poly1305(K_dh, K_dh xor tau)
    Block ktNonce{};
    for (int i = 0; i < 16; ++i) ktNonce[i] = kDh[i % kDh.size()] ^ notice.tau[i];
    const Block ktMac = poly1305Aes(kDh, ktNonce, otpMessage());

    // 4. KT_i = SHA256(ktMac)
    Bytes ktMacBytes(ktMac.begin(), ktMac.end());
    const Sha256 ktKey = sha256(ktMacBytes);
    const Bytes kt(ktKey.begin(), ktKey.end());

    // 5. auth = SHA256(tau)
    Bytes tauBytes(notice.tau.begin(), notice.tau.end());
    const Sha256 auth = sha256(tauBytes);

    HandoverTicket ticket;
    ticket.auth = auth;
    ticket.vehiclePublicKey = notice.vehiclePublicKey;
    ticket.pseudonym = received.getVehicle();
    ticket.kG = mGroupKey;
    ticket.kt = kt;
    ticket.expiry = SimTime::now() + 60.0;
    mTickets[auth] = ticket;

    printCheck(true, "Forwarding_Notice registered for vehicle " + ticket.pseudonym);

    // 6. Send Handover_Command to Vehicle with Target RSU's fresh public key Y_G and t_i
    HandoverCommandPayload cmd;
    cmd.type = Handover_Command;
    cmd.ti = notice.ti;
    cmd.targetRsuPublicKey = yg;
    sendBootstrap(Handover_Command, received.getVehicle(), 0, 0, received.getVehicle(), pack(cmd));
}

void HandoverService::handleHandoverCommand(const BootstrapMsg& received)
{
    printStep("HandoverCommand", &received);
    const HandoverCommandPayload m = unpackHandoverCommand(received.payload());
    mTi = m.ti;

    if (!mEcdhKey) {
        throw std::runtime_error(myName() + ": no ECDH key for handover");
    }

    // K_dh_i = Y_G_next ^ X_V
    const Bytes kDh = ecdh(mEcdhKey.get(), publicKeyFromDer(m.targetRsuPublicKey).get());

    // tau is derived exactly as the source RSU did
    Block nonce{};
    for (int i = 0; i < 8; ++i) nonce[15 - i] = static_cast<uint8_t>(mTi >> (8 * i));
    const Block tau = poly1305Aes(mKdg, nonce, otpMessage());

    // KT_mac = Poly1305(K_dh, K_dh xor tau)
    Block ktNonce{};
    for (int i = 0; i < 16; ++i) ktNonce[i] = kDh[i % kDh.size()] ^ tau[i];
    const Block ktMac = poly1305Aes(kDh, ktNonce, otpMessage());

    // Derive 32-byte key for KT_i: SHA256(ktMac)
    Bytes ktMacBytes(ktMac.begin(), ktMac.end());
    const Sha256 ktKey = sha256(ktMacBytes);
    mKt = Bytes(ktKey.begin(), ktKey.end());

    Bytes tauBytes(tau.begin(), tau.end());
    const Sha256 auth = sha256(tauBytes);

    ForwardingRequestPayload req;
    req.type = Forwarding_Request;
    req.auth = auth;
    req.otp = poly1305Aes(mKt, otpNonce(Bytes(auth.begin(), auth.end()), otpSlot(SimTime::now().ns())), otpMessage());

    sendBootstrap(Forwarding_Request, "target_rsu", received.getAckNum(), received.getSeqNum() + 1, myName(), pack(req));
}

void HandoverService::handleForwardingRequest(const BootstrapMsg& received)
{
    printStep("ForwardingRequest", &received);
    const ForwardingRequestPayload req = unpackForwardingRequest(received.payload());
    for (const std::string& line : describe(req)) {
        printDetail(line);
    }

    auto it = mTickets.find(req.auth);
    if (it == mTickets.end()) {
        printCheck(false, "Forwarding_Request: unknown auth ticket");
        return;
    }

    const uint64_t tNow = otpSlot(SimTime::now().ns());
    const uint64_t tMin = tNow >= kOtpWindow ? tNow - kOtpWindow : 0;
    bool otpValid = false;
    Bytes authBytes(req.auth.begin(), req.auth.end());
    for (uint64_t t = tMin; t <= tNow + kOtpWindow; ++t) {
        const Block candidate = poly1305Aes(it->second.kt, otpNonce(authBytes, t), otpMessage());
        if (CRYPTO_memcmp(candidate.data(), req.otp.data(), candidate.size()) == 0) {
            otpValid = true;
            break;
        }
    }

    if (!otpValid) {
        printCheck(false, "Forwarding_Request: vehicle OTP verification failed");
        return;
    }
    printCheck(true, "Forwarding_Request: vehicle OTP verified");

    const Sha256 authPrime = sha256(authBytes);
    Bytes authPrimeBytes(authPrime.begin(), authPrime.end());
    const Block otpPrime = poly1305Aes(it->second.kt, otpNonce(authPrimeBytes, tNow), otpMessage());

    ForwardingGrantedPayload granted;
    granted.type = Forwarding_Granted;
    granted.kG = mGroupKey;
    granted.authPrime = authPrime;
    granted.otp = otpPrime;

    const Bytes plainPayload = pack(granted);
    const Bytes encPayload = aesGcmEncrypt(it->second.kt, plainPayload);

    const std::string vehicleId = it->second.pseudonym.empty() ? received.getSender() : it->second.pseudonym;
    mSessions[vehicleId] = VehicleSession{ vehicleId, it->second.kt, it->second.vehiclePublicKey };
    mTickets.erase(it);

    sendBootstrap(Forwarding_Granted, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, vehicleId, encPayload);
    printKeep("New K_dg (Handover)", mSessions[vehicleId].kDg, vehicleId);
    notifyCompleted(vehicleId, myName());
}

void HandoverService::handleForwardingGranted(const BootstrapMsg& received)
{
    printStep("ForwardingGranted", &received);

    const auto plain = aesGcmDecrypt(mKt, received.payload());
    if (!plain) {
        printCheck(false, "Forwarding_Granted decryption failed");
        return;
    }

    const ForwardingGrantedPayload m = unpackForwardingGranted(*plain);

    // 1. Verify auth' = SHA256(auth)
    Block nonce{};
    for (int i = 0; i < 8; ++i) nonce[15 - i] = static_cast<uint8_t>(mTi >> (8 * i));
    const Block tau = poly1305Aes(mKdg, nonce, otpMessage());
    Bytes tauBytes(tau.begin(), tau.end());
    const Sha256 auth = sha256(tauBytes);
    Bytes authBytes(auth.begin(), auth.end());
    const Sha256 expectedAuthPrime = sha256(authBytes);
    if (m.authPrime != expectedAuthPrime) {
        printCheck(false, "Forwarding_Granted auth' verification failed");
        return;
    }
    printCheck(true, "Forwarding_Granted auth' verified (target RSU authenticated)");

    // 2. Verify fresh OTP'
    const uint64_t tNow = otpSlot(SimTime::now().ns());
    const uint64_t tMin = tNow >= kOtpWindow ? tNow - kOtpWindow : 0;
    bool otpValid = false;
    for (uint64_t t = tMin; t <= tNow + kOtpWindow; ++t) {
        const Block candidate = poly1305Aes(mKt, otpNonce(Bytes(expectedAuthPrime.begin(), expectedAuthPrime.end()), t), otpMessage());
        if (CRYPTO_memcmp(candidate.data(), m.otp.data(), candidate.size()) == 0) {
            otpValid = true;
            break;
        }
    }
    if (!otpValid) {
        printCheck(false, "Forwarding_Granted OTP' verification failed");
        return;
    }
    printCheck(true, "Forwarding_Granted OTP' verified (freshness confirmed)");

    const std::string prevRsu = mCurrentRsu;
    mCurrentRsu = received.getSender();
    mGroupKey = m.kG;
    mKdg = mKt;
    printKeep("New K_g", mGroupKey, myName());
    printKeep("New K_dg", mKdg, myName());
    notifyCompleted(myName(), mCurrentRsu);
}

void HandoverService::sendBootstrap(int type, const std::string& destination, int seqNum, int ackNum,
    const std::string& vehicle, const Bytes& payload)
{
    BootstrapMsg msg;
    msg.setType(type);
    msg.setSender(myName());
    msg.setDestination(destination);
    msg.setVehicle(!vehicle.empty() ? vehicle : mRole == Role::Vehicle ? myName() : destination);
    msg.setSeqNum(seqNum);
    msg.setAckNum(ackNum);
    msg.setPayload(payload);
    ++mSent;

    if (type == Forwarding_Notice && mRole == Role::Rsu) {
        if (!mTransport.https) {
            throw std::runtime_error(myName() + ": no HTTPS transport for Forwarding_Notice");
        }
        trace::send(myName(), stageName(type), destination, msg.getVehicle(), "HTTPS", payload.size());
        mTransport.https(msg);
        return;
    }

    if (!mTransport.radio) {
        throw std::runtime_error(myName() + ": no radio transport for handover");
    }
    trace::send(myName(), stageName(type), destination, msg.getVehicle(), "radio", payload.size());
    mTransport.radio(msg);
}

void HandoverService::printStep(const char* step, const BootstrapMsg* received)
{
    if (received) {
        trace::step(myName(), step, stageName(received->getType()), received->getSender(), received->getVehicle());
    } else {
        trace::step(myName(), step);
    }
}

void HandoverService::printDetail(const std::string& text) const
{
    trace::detail(myName(), text);
}

void HandoverService::printCheck(bool ok, const std::string& text) const
{
    trace::check(myName(), ok, text, false);
}

void HandoverService::printKeep(const std::string& name, const Bytes& value, const std::string& vehicle, bool echo) const
{
    trace::keep(myName(), name, value, vehicle, echo);
}

void HandoverService::notifyCompleted(const std::string& vehicle, const std::string& targetRsu)
{
    trace::end(myName(), mRole == Role::Vehicle ? "handover completed (with " + targetRsu + ")" : "RSU handover ready (" + vehicle + ")");

    if (mOnCompleted) {
        HandoverResult res;
        res.vehicle = vehicle;
        res.sourceRsu = mRole == Role::Vehicle ? mCurrentRsu : myName();
        res.targetRsu = targetRsu;
        res.newKdg = mRole == Role::Vehicle ? mKdg : mSessions[vehicle].kDg;
        res.newKg = mGroupKey;
        mOnCompleted(res);
    }
}

const Bytes& HandoverService::kDg(const std::string& vehicle) const
{
    if (mRole == Role::Vehicle) {
        return mKdg;
    }
    static const Bytes empty;
    auto it = mSessions.find(vehicle);
    return it != mSessions.end() ? it->second.kDg : empty;
}
