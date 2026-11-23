#include "HandoverClient.h"
#include "HandoverPayload.h"
#include "MessageType.h"
#include "Otp.h"
#include "ProtocolMsg.h"
#include "Trace.h"
#include <iostream>
#include <stdexcept>
#include <openssl/crypto.h>

HandoverClient::HandoverClient(VehicleSession& session) :
    mSession(session)
{
}

const std::string& HandoverClient::targetRsu() const
{
    static const std::string none;
    return mPending ? mPending->target : none;
}

void HandoverClient::handleMessage(const ProtocolMsg& msg)
{
    switch (msg.getType()) {
        case Forwarding_Granted: onForwardingGranted(msg); break;
        default:
            std::cerr << mSession.name() << ": unexpected handover message type "
                      << messageTypeName(msg.getType()) << std::endl;
            break;
    }
}

void HandoverClient::sendEncryptedPredict(const std::string& targetRsu)
{
    printStep("HandoverPredict");

    const uint64_t tNow = VehicleSession::otpSlot(mSession.localClock());
    HandoverPredictPayload m;
    m.type = Handover_Predict;
    m.authD = mSession.traits().authD;
    m.targetRsu = targetRsu;
    m.otp = computeOtp(mSession.kDg(), OtpPurpose::HandoverPredict, VehicleSession::otpNonce(m.authD, tNow),
        handoverPredictOtpData(targetRsu));
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    const Bytes sealed = aesGcmEncrypt(mSession.kDg(), pack(m));
    printDetail("E_K_dg(M) = AES-256-GCM, " + std::to_string(sealed.size()) + " bytes -> " + mSession.currentRsu());
    mSession.send(Handover_Predict, mSession.currentRsu(), 0, 0, "", sealed);
}

void HandoverClient::requestPrediction(const std::string& targetRsu)
{
    if (!mSession.isActivated() || !mSession.ecdhKey() || targetRsu.empty() || targetRsu == mSession.currentRsu()) {
        return;
    }

    const auto targetKey = mSession.neighborKey(targetRsu);
    if (!targetKey) {
        printCheck(false, "no pre-loaded key for " + targetRsu + ": cannot pre-compute handover");
        return;
    }

    const Block tau = forwardingToken(mSession.kDg(), mSession.lastAuthSlot());
    PendingHandover handover;
    handover.target = targetRsu;
    handover.keys = handoverKeys(ecdh(mSession.ecdhKey(), publicKeyFromDer(*targetKey).get()), tau);
    mPending = handover;
    const std::string macName = otpAlgoName(otpAlgorithm());
    printDetail("tau_{i+2} = " + macName + "(K_dg, t_i = " + std::to_string(mSession.lastAuthSlot())
        + ", m); K_dh_i = ECDH(X_V, Y_G_{i+2}); KT_i = " + macName + "(K_dh_i, K_dh_i xor tau_{i+2}, m)");

    sendEncryptedPredict(targetRsu);

    if (mOnPrefetchReady) {
        mOnPrefetchReady(targetRsu);
    }

    printDetail("Forwarding_Request to " + targetRsu + " held until requestForwarding()");
}

void HandoverClient::resendPrediction()
{
    if (!mPending || !mSession.isActivated()) {
        return;
    }
    sendEncryptedPredict(mPending->target);
}

void HandoverClient::requestForwarding()
{
    if (!mPending) {
        throw std::runtime_error(mSession.name() + ": requestForwarding() without pre-computed handover keys");
    }
    printStep("ForwardingRequest");

    const uint64_t t = VehicleSession::otpSlot(mSession.localClock());
    ForwardingRequestPayload m;
    m.type = Forwarding_Request;
    m.auth = mPending->keys.auth;
    m.otp = forwardingOtp(mPending->keys, t);
    mPending->otp = m.otp;
    mPending->slot = t;
    mPending->requested = true;
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }
    printDetail("t_c = " + std::to_string(t));

    mSession.send(Forwarding_Request, mPending->target, 0, 0, "", pack(m));
}

void HandoverClient::onForwardingGranted(const ProtocolMsg& received)
{
    printStep("ForwardingGranted", &received);

    if (!mPending || !mPending->requested) {
        printCheck(false, "no Forwarding_Request sent: ignored");
        return;
    }
    if (received.getSender() != mPending->target) {
        printCheck(false, "not from " + mPending->target + ", the RSU I asked: ignored");
        return;
    }

    const Bytes kt(mPending->keys.kt.begin(), mPending->keys.kt.end());
    const auto plain = aesGcmDecrypt(kt, getPayload(received));
    if (!plain) {
        printCheck(false, "E_KT_i(M) does not decrypt with my KT_i: ignored");
        return;
    }
    printCheck(true, "E_KT_i(M) decrypts with my KT_i (GCM tag valid)");
    const ForwardingGrantedPayload m = unpackForwardingGranted(*plain);
    if (m.type != Forwarding_Granted) {
        printCheck(false, "unexpected inner message type in Forwarding_Granted: ignored");
        return;
    }
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    if (CRYPTO_memcmp(mPending->keys.authPrime.data(), m.authPrime.data(), m.authPrime.size()) != 0) {
        printCheck(false, "auth'_{i+2} != SHA256(KT_i || auth_{i+2}): ignored");
        return;
    }
    printCheck(true, "auth'_{i+2} = SHA256(KT_i || auth_{i+2})");

    const uint64_t tNow = VehicleSession::otpSlot(mSession.localClock());
    const uint64_t tMin = tNow >= static_cast<uint64_t>(kOtpWindow) ? tNow - kOtpWindow : 0;
    const uint64_t tMax = tNow + kOtpWindow;
    bool otpValid = false;
    for (uint64_t t = tMin; t <= tMax; ++t) {
        const Block expected = forwardingGrantedOtp(mPending->keys, t, m.nextRsus, m.authPrime, m.kG);
        if (CRYPTO_memcmp(expected.data(), m.otp.data(), expected.size()) == 0) {
            otpValid = true;
            break;
        }
    }
    if (!otpValid) {
        printCheck(false, "fresh OTP' in Forwarding_Granted invalid in t +- 1: ignored");
        return;
    }
    printCheck(true, "fresh OTP' in Forwarding_Granted verified with KT_i in t +- 1");

    if (m.kG.size() != kGroupKeySize) {
        printCheck(false, "K_G_{i+2} has " + std::to_string(m.kG.size()) + " bytes: ignored");
        return;
    }

    // Switch active RSU session to G_{i+2}
    const Bytes kDh = mPending->keys.kDh;
    const uint64_t nextAuthSlot = mPending->slot;
    mSession.activateWithRsu(received.getSender(), m.kG, kDh, nextAuthSlot);
    mSession.setNeighborRsus(m.nextRsus);
    mPending.reset();

    trace::keep(mSession.name(), "K_g", mSession.groupKey(), mSession.name());
    trace::keep(mSession.name(), "K_dg", mSession.kDg(), mSession.name());
    trace::end(mSession.name(), "handover done (now with " + mSession.currentRsu() + ")");

    if (mOnHandoverCompleted) {
        HandoverResult result;
        result.vehicle = mSession.name();
        result.rsu = mSession.currentRsu();
        result.kDg = mSession.kDg();
        result.kG = mSession.groupKey();
        result.authD = mSession.traits().authD;
        mOnHandoverCompleted(result);
    }
}

void HandoverClient::printStep(const char* step, const ProtocolMsg* received) const
{
    if (received) {
        trace::step(mSession.name(), step, messageTypeName(received->getType()),
            received->getSender(), received->getVehicle());
    } else {
        trace::step(mSession.name(), step);
    }
}

void HandoverClient::printDetail(const std::string& text) const
{
    trace::detail(mSession.name(), text);
}

void HandoverClient::printCheck(bool ok, const std::string& text) const
{
    trace::check(mSession.name(), ok, text);
}

