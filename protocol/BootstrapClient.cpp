#include "BootstrapClient.h"
#include "BootstrapPayload.h"
#include "MessageType.h"
#include "ProtocolMsg.h"
#include "Trace.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <openssl/crypto.h>

namespace
{

// Auth_d xor t: t, big-endian, XORed into the last 8 bytes of the first AES block of Auth_d
Block authOtpNonce(const Bytes& authD, uint64_t t)
{
    Block nonce;
    if (authD.size() < nonce.size()) {
        throw std::runtime_error("OTP: Auth_d shorter than one block");
    }
    std::copy_n(authD.begin(), nonce.size(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[15 - i] ^= static_cast<uint8_t>(t >> (8 * i));
    }
    return nonce;
}

const Bytes& otpMessage()
{
    static const Bytes m(kOtpMessage, kOtpMessage + std::char_traits<char>::length(kOtpMessage));
    return m;
}

} // namespace

BootstrapClient::BootstrapClient(VehicleSession& session, Config config) :
    mSession(session),
    mConfig(std::move(config))
{
    mSession.setOnBeforeSend([this](int type) {
        if (type == PTP_Delay_Request) {
            const simtime_t queued = mPtpT3;
            mPtpT3 = mSession.localClock();
            printDetail("t_3 stamped on air = " + mPtpT3.str() + " s (queued at " + queued.str() + " s)");
        }
    });
}

void BootstrapClient::trigger()
{
    if (mConfig.autoStart) {
        start();
    }
}

void BootstrapClient::start(BootstrapCallback onCompleted)
{
    if (onCompleted) {
        mOnCompleted = std::move(onCompleted);
    }
    if (!mStarted) {
        mStarted = true;
        activationRequest();
    }
}

void BootstrapClient::handleMessage(const ProtocolMsg& msg)
{
    if (mSession.isActivated()) {
        return;
    }

    // From ECDH on, a message outside the activation window [t_0, t_f] aborts the bootstrap
    if ((msg.getType() == ECDH_Response || msg.getType() == Auth_Granted) && !withinWindow()) {
        return;
    }

    switch (msg.getType()) {
        case PTP_Sync:           ptpDelayRequest(msg); break;
        case PTP_Delay_Response: ecdhRequest(msg); break;
        case ECDH_Response:      authRequest(msg); break;
        case Auth_Granted:       saveVehicle(msg); break;
        default:
            std::cerr << mSession.name() << ": unexpected bootstrap message type "
                      << messageTypeName(msg.getType()) << std::endl;
            break;
    }
}

void BootstrapClient::activationRequest()
{
    printStep("activationRequest");

    ActivationRequestPayload m;
    m.type = Activation_Request;
    m.gatewayPublicKey = mConfig.gatewayPublicKey;
    m.t0 = mSession.localClock();
    m.tf = m.t0 + kActivationWindow;
    mWindow = ActivationWindow{ m.t0, m.tf };
    m.uuid = mSession.traits().uuid;
    m.firmwareHash = mSession.traits().firmwareHash;

    mSession.send(Activation_Request, "esa", 0, 0, "", pack(m));
}

void BootstrapClient::ptpDelayRequest(const ProtocolMsg& received)
{
    printStep("PTPDelayRequest", &received);

    const PtpPayload sync = unpackPtp(getPayload(received));
    for (const std::string& line : describe(sync)) {
        printDetail(line);
    }

    mPtpT1 = sync.timestamp;
    mPtpT2 = mSession.localClock();
    mPtpT3 = mSession.localClock();
    printDetail("kept t_1 = " + mPtpT1.str() + " s, t_2 = " + mPtpT2.str() + " s");

    PtpPayload m;
    m.type = PTP_Delay_Request;

    mSession.send(PTP_Delay_Request, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", pack(m));
}

void BootstrapClient::ecdhRequest(const ProtocolMsg& received)
{
    printStep("ECDHRequest", &received);

    const PtpPayload response = unpackPtp(getPayload(received));
    for (const std::string& line : describe(response)) {
        printDetail(line);
    }
    correctClock(mPtpT1, mPtpT2, mPtpT3, response.timestamp);

    if (!withinWindow()) {
        return;
    }

    // Generate ephemeral ECDH keypair (X_V, Y_V); retained after bootstrap for Secrecy Forwarding handovers
    auto key = newEcKey(kEcdhCurve);
    mSession.setEcdhKey(key);

    EcdhPayload m;
    m.type = ECDH_Request;
    m.publicKey = publicKeyDer(key.get());

    mSession.send(ECDH_Request, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", pack(m));
}

void BootstrapClient::authRequest(const ProtocolMsg& received)
{
    printStep("AuthRequest", &received);

    const EcdhPayload response = unpackEcdh(getPayload(received));
    for (const std::string& line : describe(response)) {
        printDetail(line);
    }

    mPendingKdg = ecdh(mSession.ecdhKey(), publicKeyFromDer(response.publicKey).get());
    printKeep("K_dg", mPendingKdg);

    const uint64_t t = VehicleSession::otpSlot(mSession.localClock());
    const Block nonce = authOtpNonce(mSession.traits().authD, t);

    AuthRequestPayload otp;
    otp.type = Auth_Request;
    otp.otp = poly1305Aes(mPendingKdg, nonce, otpMessage());
    mOtpSent = otp.otp;
    mOtpSlot = t;
    printDetail("t = " + std::to_string(t) + " (slots of " + std::to_string(kOtpTimeStep) + " s), Auth_d xor t = "
        + toHex(nonce.data(), nonce.size()));

    mSession.send(Auth_Request, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", pack(otp));
}

void BootstrapClient::saveVehicle(const ProtocolMsg& received)
{
    printStep("SaveVehicle", &received);

    auto reject = [&](const std::string& reason) {
        printCheck(false, reason);
        if (!mSession.isActivated()) {
            fail(reason);
        }
    };

    if (mPendingKdg.empty()) {
        reject("no K_dg: ignored");
        return;
    }

    const auto plain = aesGcmDecrypt(mPendingKdg, getPayload(received));
    if (!plain) {
        reject("E_K_dg(M) does not decrypt with my K_dg: ignored");
        return;
    }
    printCheck(true, "E_K_dg(M) decrypts with my K_dg (GCM tag valid)");
    const AuthGrantedPayload m = unpackAuthGranted(*plain);
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    if (CRYPTO_memcmp(m.otp.data(), mOtpSent.data(), m.otp.size()) != 0) {
        reject("OTP_dt is not the one I sent: ignored");
        return;
    }
    printCheck(true, "OTP_dt is the one I sent");

    const Sha256 idD = computeIdD(mSession.traits().uuid, mSession.traits().firmwareHash);
    const Bytes authEg = aes256Encrypt(idD, m.esaPublicKey);
    if (authEg.size() != m.authEg.size() || CRYPTO_memcmp(authEg.data(), m.authEg.data(), authEg.size()) != 0) {
        reject("Auth_eg != AES(Id_d, CY_e): CY_e is not the ESA's key, ignored");
        return;
    }
    printCheck(true, "Auth_eg = AES(Id_d, CY_e): CY_e is the ESA's key");

    if (m.kG.size() != kGroupKeySize) {
        reject("K_g has " + std::to_string(m.kG.size()) + " bytes: ignored");
        return;
    }
    mEsaPublicKey = m.esaPublicKey;
    mSession.activateWithRsu(received.getSender(), m.kG, mPendingKdg, mOtpSlot);
    printKeep("K_g", m.kG);
    printDetail("t_i = " + std::to_string(mOtpSlot) + " (the slot of the OTP_dt the RSU matched)");

    mAuthDe = computeAuthDe(idD, mSession.traits().uuid, mSession.traits().firmwareHash, mEsaPublicKey);
    const Sha256 kDe = computeKDe(idD, mSession.traits().authD, mAuthDe, mOtpSent);
    mKde.assign(kDe.begin(), kDe.end());
    printKeep("K_de", mKde);

    active01(received);
}

void BootstrapClient::active01(const ProtocolMsg& received)
{
    printStep("Active01", &received);

    Active01Payload m;
    m.type = Active_01;
    m.authD = mSession.traits().authD;
    m.otp = mOtpSent;
    m.authDe = mAuthDe;
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    const Bytes sealed = aesGcmEncrypt(mSession.kDg(), pack(m));
    printDetail("E_K_dg(M) = AES-256-GCM, " + std::to_string(sealed.size()) + " bytes (nonce | ciphertext | tag)");

    mSession.send(Active_01, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", sealed);

    mWindow.reset();
    trace::end(mSession.name(), "vehicle ready (with " + received.getSender() + ")");

    if (mOnCompleted) {
        BootstrapResult result;
        result.vehicle = mSession.name();
        result.rsu = mSession.currentRsu();
        result.kDg = mSession.kDg();
        result.kG = mSession.groupKey();
        result.kDe = mKde;
        result.authD = mSession.traits().authD;
        mOnCompleted(result);
    }
}

bool BootstrapClient::withinWindow()
{
    const simtime_t now = mSession.localClock();
    if (mWindow && mWindow->t0 <= now && now <= mWindow->tf) {
        printCheck(true, "t_0 = " + mWindow->t0.str() + " s <= t = " + now.str() + " s <= t_f = "
            + mWindow->tf.str() + " s");
        return true;
    }

    const std::string reason = !mWindow
        ? ("no activation window for " + mSession.name())
        : ("t = " + now.str() + " s outside [t_0, t_f] = ["
            + mWindow->t0.str() + " s, " + mWindow->tf.str() + " s]");
    trace::end(mSession.name(), "aborted: " + reason);
    fail(reason);
    return false;
}

void BootstrapClient::fail(const std::string& reason)
{
    mWindow.reset();
    mPendingKdg.clear();
    mSession.clearActiveKeys();
    if (mOnFailed) {
        mOnFailed(reason);
    }
}

void BootstrapClient::correctClock(simtime_t t1, simtime_t t2, simtime_t t3, simtime_t t4)
{
    const simtime_t delay = ((t2 - t1) + (t4 - t3)) / 2;
    const simtime_t offset = ((t2 - t1) - (t4 - t3)) / 2;

    const simtime_t before = mSession.localClock();
    mSession.adjustClock(offset);
    printDetail("correct_clock: delay = " + delay.str() + " s, offset = " + offset.str() + " s");
    printDetail("correct_clock: clock " + before.str() + " s -> " + mSession.localClock().str() + " s");
}

void BootstrapClient::printStep(const char* step, const ProtocolMsg* received) const
{
    if (received) {
        trace::step(mSession.name(), step, messageTypeName(received->getType()),
            received->getSender(), received->getVehicle());
    } else {
        trace::step(mSession.name(), step);
    }
}

void BootstrapClient::printDetail(const std::string& text) const
{
    trace::detail(mSession.name(), text);
}

void BootstrapClient::printCheck(bool ok, const std::string& text) const
{
    trace::check(mSession.name(), ok, text);
}

void BootstrapClient::printKeep(const std::string& name, const Bytes& value) const
{
    trace::keep(mSession.name(), name, value, mSession.name());
}

