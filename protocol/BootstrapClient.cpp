#include "BootstrapClient.h"
#include "BootstrapPayload.h"
#include "MessageType.h"
#include "ProtocolMsg.h"
#include "Trace.h"
#include <iostream>
#include <stdexcept>
#include <openssl/crypto.h>

namespace
{

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
        ptpRequest();
    }
}

void BootstrapClient::handleMessage(const ProtocolMsg& msg)
{
    if (mSession.isActivated()) {
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

void BootstrapClient::ptpRequest()
{
    printStep("PTPRequest");

    PtpPayload m;
    m.type = PTP;
    mSession.send(PTP, mConfig.targetRsu, 0, 0, "", pack(m));
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

    // Step 4: generate ECDH keypair (X_V, Y_V); retained after bootstrap for Secrecy Forwarding handovers
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

    // Step 6: compute OTP_dt = Poly1305(K_dg, Auth_d xor t, m); send ONLY OTP_dt (never Auth_d)
    const uint64_t t = VehicleSession::otpSlot(mSession.localClock());
    const Block nonce = VehicleSession::otpNonce(mSession.traits().authD, t);

    AuthRequestPayload otp;
    otp.type = Auth_Request;
    otp.otp = poly1305Aes(mPendingKdg, nonce, otpMessage());
    mAuthReqOtp = otp.otp;
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
    if (m.type != Auth_Granted) {
        reject("unexpected inner type in Auth_Granted: ignored");
        return;
    }
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // Step 9 Level 1 Verification: verify fresh Gateway Poly1305 OTP_dt over Auth_Granted in [t-1, t+1]
    const uint64_t tNow = VehicleSession::otpSlot(mSession.localClock());
    const uint64_t tMin = tNow >= static_cast<uint64_t>(kOtpWindow) ? tNow - kOtpWindow : 0;
    const uint64_t tMax = tNow + kOtpWindow;
    const Bytes grantedData = authGrantedOtpData(m);
    bool otpValid = false;
    for (uint64_t t = tMin; t <= tMax; ++t) {
        const Block expected = poly1305Aes(mPendingKdg, VehicleSession::otpNonce(mSession.traits().authD, t), grantedData);
        if (CRYPTO_memcmp(expected.data(), m.otp.data(), expected.size()) == 0) {
            otpValid = true;
            break;
        }
    }
    if (!otpValid) {
        reject("OTP_dt in Auth_Granted does not match K_dg and Auth_d in t +- 1: ignored");
        return;
    }
    printCheck(true, "Level 1 OK: fresh Auth_Granted OTP_dt verified with K_dg and Auth_d");

    // Step 9 Level 2 Verification: verify Gateway authenticity via Auth_eg == AES(Id_d, CY_e)
    const Sha256 idD = computeIdD(mSession.traits().uuid, mSession.traits().firmwareHash);
    const Bytes authEg = aes256Encrypt(idD, m.esaPublicKey);
    if (authEg.size() != m.authEg.size() || CRYPTO_memcmp(authEg.data(), m.authEg.data(), authEg.size()) != 0) {
        reject("Auth_eg != AES(Id_d, CY_e): CY_e is not the ESA's key, ignored");
        return;
    }
    printCheck(true, "Level 2 OK: Auth_eg = AES(Id_d, CY_e): CY_e is the ESA's key");

    if (m.kG.size() != kGroupKeySize) {
        reject("K_g has " + std::to_string(m.kG.size()) + " bytes: ignored");
        return;
    }
    mEsaPublicKey = m.esaPublicKey;
    mSession.activateWithRsu(received.getSender(), m.kG, mPendingKdg, mOtpSlot);
    mSession.setNeighborRsus(m.nextRsus);
    printKeep("K_g", m.kG);
    printDetail("t_i = " + std::to_string(mOtpSlot) + " (slot of Auth_Request OTP_dt)");

    // Step 9.4: compute Auth_de, generate FRESH Active-message OTP_dt (Theorem 2), and derive K_de
    mAuthDe = computeAuthDe(idD, mSession.traits().uuid, mSession.traits().firmwareHash, mEsaPublicKey);
    const uint64_t tActive = VehicleSession::otpSlot(mSession.localClock());
    mActiveOtp = poly1305Aes(mPendingKdg, VehicleSession::otpNonce(mSession.traits().authD, tActive),
        activeOtpData(mSession.traits().authD, mAuthDe));
    const Sha256 kDe = computeKDe(idD, mSession.traits().authD, mAuthDe, mActiveOtp);
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
    m.otp = mActiveOtp;
    m.authDe = mAuthDe;
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // Step 10 (Theorem 2): encrypt Active_01 under K_dg so neither OT eavesdroppers nor Gateway REE see OTP_dt
    const Bytes sealed = aesGcmEncrypt(mSession.kDg(), pack(m));
    printDetail("E_K_dg(M) = AES-256-GCM, " + std::to_string(sealed.size()) + " bytes (nonce | ciphertext | tag)");

    mSession.send(Active_01, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", sealed);

    trace::end(mSession.name(), "vehicle ready (with " + received.getSender() + ")");

    if (mOnCompleted) {
        BootstrapResult result;
        result.vehicle = mSession.name();
        result.rsu = mSession.currentRsu();
        result.kDg = mSession.kDg();
        result.kG = mSession.groupKey();
        result.kDe = mKde;
        result.authD = mSession.traits().authD;
        result.authReqOtp = mAuthReqOtp;
        result.activeOtp = mActiveOtp;
        mOnCompleted(result);
    }
}

void BootstrapClient::fail(const std::string& reason)
{
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
