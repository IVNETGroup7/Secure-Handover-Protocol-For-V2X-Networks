#include "HandoverClient.h"
#include "HandoverPayload.h"
#include "MessageType.h"
#include "ProtocolMsg.h"
#include "Trace.h"
#include <iostream>
#include <stdexcept>
#include <openssl/crypto.h>

HandoverClient::HandoverClient(VehicleSession& session, bool deferHandover) :
    mSession(session),
    mDeferHandover(deferHandover)
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
        case Handover_Command:   onHandoverCommand(msg); break;
        case Forwarding_Granted: onForwardingGranted(msg); break;
        default:
            std::cerr << mSession.name() << ": unexpected handover message type "
                      << messageTypeName(msg.getType()) << std::endl;
            break;
    }
}

void HandoverClient::requestPrediction(const std::string& targetRsu)
{
    if (!mSession.isActivated() || targetRsu.empty() || targetRsu == mSession.currentRsu()) {
        return;
    }
    printStep("HandoverPredict");

    HandoverPredictPayload m;
    m.type = Handover_Predict;
    m.targetRsu = targetRsu;
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // M = { Handover_Predict, G_{i+2} } sent to current RSU so it notifies ONLY targetRsu
    mSession.send(Handover_Predict, mSession.currentRsu(), 0, 0, "", pack(m));
}

void HandoverClient::onHandoverCommand(const ProtocolMsg& received)
{
    printStep("HandoverCommand", &received);

    const HandoverCommandPayload m = unpackHandoverCommand(getPayload(received));
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    if (!mSession.isActivated() || !mSession.ecdhKey()) {
        printCheck(false, "not activated with any RSU: ignored");
        return;
    }
    if (received.getSender() != mSession.currentRsu()) {
        printCheck(false, "not from " + mSession.currentRsu() + ", the RSU I am activated with: ignored");
        return;
    }
    printCheck(true, "from " + mSession.currentRsu() + ", the RSU I am activated with");

    const Block tau = forwardingToken(mSession.kDg(), mSession.lastAuthSlot());
    PendingHandover handover;
    handover.target = m.targetRsu;
    handover.keys = handoverKeys(ecdh(mSession.ecdhKey(), publicKeyFromDer(m.targetRsuPublicKey).get()), tau);
    mPending = handover;
    printDetail("tau_{i+2} = Poly1305(K_dg, t_i = " + std::to_string(mSession.lastAuthSlot())
        + ", m); K_dh_i = ECDH(X_V, Y_G_{i+2}); KT_i = Poly1305(K_dh_i, K_dh_i xor tau_{i+2}, m)");

    if (mOnPrefetchReady) {
        mOnPrefetchReady(m.targetRsu);
    }

    if (mDeferHandover) {
        printDetail("Forwarding_Request to " + m.targetRsu + " held until requestForwarding()");
        return;
    }
    requestForwarding();
}

void HandoverClient::requestForwarding()
{
    if (!mPending) {
        throw std::runtime_error(mSession.name() + ": requestForwarding() without a Handover_Command");
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
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    if (CRYPTO_memcmp(m.otp.data(), mPending->otp.data(), m.otp.size()) != 0) {
        printCheck(false, "OTP is not the one I sent: ignored");
        return;
    }
    printCheck(true, "OTP is the one I sent");

    const Sha256 authPrime = sha256(Bytes(mPending->keys.auth.begin(), mPending->keys.auth.end()));
    if (CRYPTO_memcmp(authPrime.data(), m.authPrime.data(), authPrime.size()) != 0) {
        printCheck(false, "auth'_{i+2} != SHA256(auth_{i+2}): ignored");
        return;
    }
    printCheck(true, "auth'_{i+2} = SHA256(auth_{i+2})");

    if (m.kG.size() != kGroupKeySize) {
        printCheck(false, "K_G_{i+2} has " + std::to_string(m.kG.size()) + " bytes: ignored");
        return;
    }

    // Switch active RSU session to G_{i+2}
    const Bytes kDh = mPending->keys.kDh;
    const uint64_t nextAuthSlot = mPending->slot;
    mSession.activateWithRsu(received.getSender(), m.kG, kDh, nextAuthSlot);
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

