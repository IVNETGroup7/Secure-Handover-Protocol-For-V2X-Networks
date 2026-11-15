#include "BootstrapService.h"
#include "BootstrapMsg.h"
#include "BootstrapPayload.h"
#include "Trace.h"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <stdexcept>
#include <openssl/crypto.h>

const char* stageName(int type)
{
    static const char* names[] = { "Activation_Request", "HTTPS_Session", "Activation_Token", "PTP",
        "ECDH_Request", "ECDH_Response", "Auth_Request", "Save_RSU", "Auth_Granted", "Save_Vehicle",
        "Active_01", "Active_02", "Active_03", "PTP_Sync", "PTP_Delay_Request", "PTP_Delay_Response",
        "Forwarding_Notice", "Handover_Command", "Forwarding_Request", "Forwarding_Granted", "Secure_Data" };
    return (type >= 0 && type < static_cast<int>(sizeof(names) / sizeof(names[0]))) ? names[type] : "?";
}

// OTP_dt = Poly1305(K_dg, Auth_d xor t, m), the same on both sides: vehicle and RSU OP-TEE TA

// t: slot of kOtpTimeStep s of the PTP-synchronized clock (truncated timestamp)
static uint64_t otpSlot(simtime_t clock)
{
    return static_cast<uint64_t>(floor(clock.dbl() / kOtpTimeStep));
}

// Auth_d xor t: t, big endian, into the last 8 bytes of the first AES block of Auth_d
static Block otpNonce(const Bytes& authD, uint64_t t)
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

// m
static const Bytes& otpMessage()
{
    static const Bytes m(kOtpMessage, kOtpMessage + std::char_traits<char>::length(kOtpMessage));
    return m;
}

BootstrapService::BootstrapService(const Config& config) :
    mName(config.name), mRng(config.seed), mAutoStart(config.autoStart),
    mDeferHandover(config.deferHandover), mTraits(manufactureVehicle(mRng)),
    mGatewayPublicKey(config.gatewayPublicKey), mClockOffset(config.clockOffset)
{
}

void BootstrapService::trigger()
{
    if (mAutoStart) {
        start();
    }
}

void BootstrapService::start(BootstrapCallback onCompleted)
{
    if (onCompleted) {
        mOnCompleted = std::move(onCompleted);
    }

    // runs once; every later step is a reaction to a received message
    if (!mStarted) {
        mStarted = true;
        activationRequest();
    }
}

void BootstrapService::indicate(const BootstrapMsg& msg)
{
    // radio: unicast is logical (filter by destination)
    if (isForMe(msg)) {
        ++mReceived;
        dispatch(msg);
    }
}

bool BootstrapService::isForMe(const BootstrapMsg& msg) const
{
    return msg.getDestination() == myName();
}

void BootstrapService::dispatch(const BootstrapMsg& msg)
{
    // from ECDH on, a message outside the activation window [t_0, t_f] ends the protocol
    switch (msg.getType()) {
        case ECDH_Response: case Auth_Granted:
            if (!withinWindow(msg.getVehicle())) {
                return;
            }
            break;
        default:
            break;
    }

    switch (msg.getType()) {
        case PTP_Sync:           PTPDelayRequest(msg); break;
        case PTP_Delay_Response: ECDHRequest(msg); break;
        // from here, everything must happen inside [t_0, t_f]
        case ECDH_Response:      AuthRequest(msg); break;
        case Auth_Granted:       SaveVehicle(msg); break;
        // Secrecy Forwarding, once activated (no activation window: the vehicle is already active)
        case Handover_Command:   HandoverCommand(msg); break;
        case Forwarding_Granted: ForwardingGranted(msg); break;
        default:
            std::cerr << myName() << ": unexpected message type " << stageName(msg.getType()) << std::endl;
            break;
    }
}

void BootstrapService::activationRequest()
{
    printStep("activationRequest");

    // here we are doing an activation request
    // 1. we need to pass the public key of the target gateway's certificate (CY_g): the RSU the operator chose;
    //    the ESA only accepts a gateway that established its HTTPS session with it
    // 2. we need to pass both timestamps for ptp and time to the protocol to realize (t_0 and t_f)
    // 3. we pass the manufacturing-time identification of the device (UUID) and the SHA256 of the firmware signature (SHA256(fw_d)) 
    //    so nobody will forge on ECDH requests, both of those values are exclusive from the vehicle
    
    // the message that will be passed is
    // M = { Activation_Request, CY_g, t_0, t_f, UUID, SHA256(fw_d) }

    // all those values must be stored on a file containing all those informations, split from BootstrapService.cpp
    // since we can use those values on future protocols, make like a traits.h that contains all those information or 
    // other file if you prefer

    ActivationRequestPayload m;
    m.type = Activation_Request;
    m.gatewayPublicKey = mGatewayPublicKey;         // CY_g of the target RSU
    m.t0 = localClock();                            // t_0
    m.tf = m.t0 + kActivationWindow;                // t_f
    mWindows[myName()] = { m.t0, m.tf };
    m.uuid = mTraits.uuid;                          // UUID
    m.firmwareHash = mTraits.firmwareHash;          // SHA256(fw_d)

    sendBootstrap(Activation_Request, "esa", 0, 0, "", pack(m));
}

void BootstrapService::PTPDelayRequest(const BootstrapMsg& received)
{
    // vehicle (slave), on PTP_Sync from the RSU (the sender is my RSU)
    printStep("PTPDelayRequest", &received);

    // M = { PTP_Sync, t_1 }
    const PtpPayload sync = unpackPtp(getPayload(received));
    for (const std::string& line : describe(sync)) {
        printDetail(line);
    }

    // 1. we will keep the t_2 and t_3 values of the PTP (and t_1, needed by correct_clock)
    mPtpT1 = sync.timestamp;
    mPtpT2 = localClock(); // t_2: PTP_Sync received
    mPtpT3 = localClock(); // t_3: queued now; stampTransmission() replaces it when the frame goes on air
    printDetail("kept t_1 = " + mPtpT1.str() + " s, t_2 = " + mPtpT2.str() + " s");

    // the message that will be passed is
    // M = { PTP_Delay_Request }
    PtpPayload m;
    m.type = PTP_Delay_Request;

    sendBootstrap(PTP_Delay_Request, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", pack(m));
}

void BootstrapService::ECDHRequest(const BootstrapMsg& received)
{
    // vehicle, on PTP_Delay_Response from the RSU (PTP done)
    printStep("ECDHRequest", &received);

    // M = { PTP_Delay_Response, t_4 }
    const PtpPayload response = unpackPtp(getPayload(received));
    for (const std::string& line : describe(response)) {
        printDetail(line);
    }
    correct_clock(mPtpT1, mPtpT2, mPtpT3, response.timestamp);

    // from here, everything must happen inside [t_0, t_f] (checked with the corrected clock)
    if (!withinWindow(myName())) {
        return;
    }

    // first we do an Elipte Curve Diffie-Helman by the vehicle side to the RSU
    // at the end we will have
    // K_dg = Y_d^(X_g) mod q = Y_g^(X_d) mod q
    // we will possibly have to pass q or to define on traits (it's a public value so whatever)
    mEcdhKey = newEcKey(kEcdhCurve); // X_d (kept until ECDH_Response) and Y_d

    // the message that will be passed is
    // M = { ECDH_Request, Y_d }

    EcdhPayload m;
    m.type = ECDH_Request;
    m.publicKey = publicKeyDer(mEcdhKey.get()); // Y_d

    sendBootstrap(ECDH_Request, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", pack(m));
}

void BootstrapService::AuthRequest(const BootstrapMsg& received)
{
    // vehicle, on ECDH_Response
    printStep("AuthRequest", &received);

    // M = { ECDH_Response, Y_g }
    const EcdhPayload response = unpackEcdh(getPayload(received));
    for (const std::string& line : describe(response)) {
        printDetail(line);
    }

    // K_dg = Y_g^(X_d): must match the RSU's
    const Bytes kDg = ecdh(mEcdhKey.get(), publicKeyFromDer(response.publicKey).get());
    mKdg[myName()] = kDg;
    printKeep("K_dg", kDg, myName());

    // 1. we must generate a OneTimePassoword (OTP_dt) 
    // OTP_dt = Poly1305(K_dg, Auth_d xor t, m)
    // K_dg is the key we produced
    // Auth_d is a value we produced way back and have stored
    // t is the actual timestamp
    // m is an arbritary message

    // source says
    /*
    "The Poly1305 takes the previously generated ECDH master secret as one of its
    inputs and a combination of Authd and a timestamp t representing the current time
    as the other to produce a MAC on an arbitrary message m"
    */

    // HERE you will have to do a little change, instead of using the exact timestamp, we will
    // be using a truncate timestamp, for example the timestamp marking 10:00:03.203, will be considered 10:00:03.200
    // so the gateway can guess the timestamp it was sent without permitting attackers to guess
    // obs : since we did PTP, both times from RSU and vehicle are well stablished so we are going to
    // "guess" the value of the timestamp: slots of kOtpTimeStep = 100 ms, and the RSU tries its own slot +-kOtpWindow
    // (= 1), as the paper ("running OTP verification with the truncated timestamp +-1"). Ex: the vehicle sends at
    // 10:00:03.420 (t = 10:00:03.400); the RSU, at 10:00:03.460, tries 10:00:03.300 (wrong), 10:00:03.400 (right)
    // and 10:00:03.500, so we have OTP and is valid
    const uint64_t t = otpSlot(localClock());               // PTP-synchronized time slot
    const Block nonce = otpNonce(mTraits.authD, t);         // Auth_d xor t

    AuthRequestPayload otp;
    otp.type = Auth_Request;
    otp.otp = poly1305Aes(mKdg[myName()], nonce, otpMessage()); // OTP_dt
    mOtpSent = otp.otp;                                     // checked against the Auth_Granted (SaveVehicle)
    mOtpSlot = t;                                           // t_i once the RSU echoes this OTP_dt (SaveVehicle)
    // X_d (mEcdhKey) stays: K_dh_i = ECDH(X_V, Y_G_{i+2}) of the Secrecy Forwarding needs it after the bootstrap
    printDetail("t = " + std::to_string(t) + " (slots of " + std::to_string(kOtpTimeStep) + " s), Auth_d xor t = "
        + toHex(nonce.data(), nonce.size()));

    // the message that will be passed is
    // M = { Auth_Request, OTP_dt }        (t is not sent: the RSU tries its own truncated clock +-1)

    sendBootstrap(Auth_Request, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", pack(otp));
}

void BootstrapService::SaveVehicle(const BootstrapMsg& received)
{
    // vehicle, on Auth_Granted
    printStep("SaveVehicle", &received);

    // 1. decrypt the message received using K_dg 
    // 2. check OTP sent is the same as the one he sent(the vehicle keeps it's OTP to check later)
    // 3. verifies if auth_eg is valid (can use CY_e sent) Auth_eg = AES(ID_d, CY_e)
    // 4. save the group key K_g
    // 5. save K_de (this is a key so vehicle can communicate with the ESA)
    // Kde = SHA256(Idd + Authd + Authde + OTPdt )

    // any failed check: the message is ignored (no Active_01)
    const auto kDg = mKdg.find(myName());
    if (kDg == mKdg.end()) {
        printCheck(false, "no K_dg: ignored");
        return;
    }

    // 1. M = D_K_dg(E_K_dg(M)): AES-256-GCM, so a changed message or another key fails here
    const auto plain = aesGcmDecrypt(kDg->second, getPayload(received));
    if (!plain) {
        printCheck(false, "E_K_dg(M) does not decrypt with my K_dg: ignored");
        return;
    }
    printCheck(true, "E_K_dg(M) decrypts with my K_dg (GCM tag valid)");
    const AuthGrantedPayload m = unpackAuthGranted(*plain);
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // 2. the RSU echoes the OTP_dt it matched: it must be the one I sent
    if (CRYPTO_memcmp(m.otp.data(), mOtpSent.data(), m.otp.size()) != 0) {
        printCheck(false, "OTP_dt is not the one I sent: ignored");
        return;
    }
    printCheck(true, "OTP_dt is the one I sent");

    // 3. Auth_eg = AES(Id_d, CY_e): only who knows Id_d (the ESA, from the operator's Activation_Request) makes
    //    it, so recomputing it with Id_d and the CY_e received proves CY_e is the ESA's key (here the vehicle
    //    sends the Activation_Request in the operator's place, so a radio listener could also derive Id_d)
    const Sha256 idD = computeIdD(mTraits.uuid, mTraits.firmwareHash);
    const Bytes authEg = aes256Encrypt(idD, m.esaPublicKey);
    if (authEg.size() != m.authEg.size() || CRYPTO_memcmp(authEg.data(), m.authEg.data(), authEg.size()) != 0) {
        printCheck(false, "Auth_eg != AES(Id_d, CY_e): CY_e is not the ESA's key, ignored");
        return;
    }
    printCheck(true, "Auth_eg = AES(Id_d, CY_e): CY_e is the ESA's key");

    // 4. K_g (and CY_e, now verified)
    if (m.kG.size() != kGroupKeySize) {
        printCheck(false, "K_g has " + std::to_string(m.kG.size()) + " bytes: ignored");
        return;
    }
    mGroupKey = m.kG;
    mEsaPublicKey = m.esaPublicKey;
    printKeep("K_g", mGroupKey, myName());

    // activated with this RSU: the OTP_dt it echoed matched with my slot t, which is t_i of tau_{i+2}, the token
    // of my first handover (Secrecy Forwarding); the RSU kept the same slot
    mCurrentRsu = received.getSender();
    mLastAuthSlot = mOtpSlot;
    printDetail("t_i = " + std::to_string(mLastAuthSlot) + " (the slot of the OTP_dt the RSU matched)");

    // 5. K_de = SHA256(Id_d + Auth_d + Auth_de + OTP_dt), Auth_de with the CY_e verified in 3.
    //    the ESA derives the same key from what the Active_01 carries
    mAuthDe = computeAuthDe(idD, mTraits.uuid, mTraits.firmwareHash, mEsaPublicKey); // also sent in Active_01
    const Sha256 kDe = computeKDe(idD, mTraits.authD, mAuthDe, mOtpSent);
    mKde.assign(kDe.begin(), kDe.end());
    printKeep("K_de", mKde, myName());

    Active01(received);
}

void BootstrapService::Active01(const BootstrapMsg& received)
{
    // vehicle, at the end of SaveVehicle

    // 1. create the message
    // M = { Auth_d, OTP_dt, Auth_de }
    // Auth+de = AES(Idd , SHA256(UUIDd + SHA256(fwd ) + CYe ))
    // 2. encrypt it using the K_dg key (the same AES blocking used on the Auth Granted message sending)
    // 3. send encrypted message

    printStep("Active01", &received);

    Active01Payload m;
    m.type = Active_01;
    m.authD = mTraits.authD;                                // Auth_d
    m.otp = mOtpSent;                                       // OTP_dt
    m.authDe = mAuthDe;                                     // Auth_de: computed in SaveVehicle
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // E_K_dg(M): AES-256-GCM with K_dg, as the Auth_Granted (fresh nonce per message)
    const Bytes sealed = aesGcmEncrypt(mKdg.at(myName()), pack(m));
    printDetail("E_K_dg(M) = AES-256-GCM, " + std::to_string(sealed.size()) + " bytes (nonce | ciphertext | tag)");

    sendBootstrap(Active_01, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", sealed);

    // the protocol ends here for the vehicle
    notifyCompleted(myName(), received.getSender());
}

// ---------------------------------------------------------------------------------------------

bool BootstrapService::withinWindow(const std::string& vehicle)
{
    const simtime_t now = localClock();
    auto window = mWindows.find(vehicle);
    if (window != mWindows.end() && window->second.t0 <= now && now <= window->second.tf) {
        printCheck(true, "t_0 = " + window->second.t0.str() + " s <= t = " + now.str() + " s <= t_f = "
            + window->second.tf.str() + " s");
        return true;
    }

    // outside [t_0, t_f] (or no window known for this vehicle): the protocol ends here for this vehicle
    if (window == mWindows.end()) {
        trace::end(myName(), "aborted: no activation window for " + vehicle);
    } else {
        trace::end(myName(), "aborted: t = " + now.str() + " s outside [t_0, t_f] = [" + window->second.t0.str()
            + " s, " + window->second.tf.str() + " s]");
        mWindows.erase(window);
    }
    mKdg.erase(vehicle); // an aborted bootstrap leaves no key
    mEcdhKey.reset();
    return false;
}

void BootstrapService::correct_clock(simtime_t t1, simtime_t t2, simtime_t t3, simtime_t t4)
{
    // PTP (IEEE 1588) delay request-response, assuming the same delay in both directions:
    //   delay  = ((t_2 - t_1) + (t_4 - t_3)) / 2
    //   offset = ((t_2 - t_1) - (t_4 - t_3)) / 2   (vehicle clock - RSU clock)
    const simtime_t delay = ((t2 - t1) + (t4 - t3)) / 2;
    const simtime_t offset = ((t2 - t1) - (t4 - t3)) / 2;

    const simtime_t before = localClock();
    mClockOffset -= offset;
    printDetail("correct_clock: delay = " + delay.str() + " s, offset = " + offset.str() + " s");
    printDetail("correct_clock: clock " + before.str() + " s -> " + localClock().str() + " s");
}

simtime_t BootstrapService::localClock() const
{
    return simTime() + mClockOffset;
}

void BootstrapService::sendBootstrap(int type, const std::string& destination, int seqNum, int ackNum,
    const std::string& vehicle, const Bytes& payload)
{
    BootstrapMsg msg;
    msg.setType(type);
    msg.setSender(myName());
    msg.setDestination(destination);
    msg.setVehicle(!vehicle.empty() ? vehicle : myName());
    msg.setSeqNum(seqNum);
    msg.setAckNum(ackNum);
    setPayload(msg, payload);
    ++mSent;

    if (!mTransport) {
        throw std::runtime_error(myName() + ": no radio transport");
    }
    if (type == PTP_Delay_Request) {
        const simtime_t queued = mPtpT3;
        mPtpT3 = localClock();
        printDetail("t_3 stamped on air = " + mPtpT3.str() + " s (queued at " + queued.str() + " s)");
    }
    mTransport(msg);
}

void BootstrapService::HandoverCommand(const BootstrapMsg& received)
{
    // vehicle, on Handover_Command from the RSU I am activated with
    printStep("HandoverCommand", &received);

    // M = { Handover_Command, G_{i+2}, Y_G_{i+2} }
    const HandoverCommandPayload m = unpackHandoverCommand(getPayload(received));
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // any failed check: the message is ignored (no Forwarding_Request)
    const auto kDg = mKdg.find(myName());
    if (mCurrentRsu.empty() || kDg == mKdg.end() || !mEcdhKey) {
        printCheck(false, "not activated with any RSU: ignored");
        return;
    }
    if (received.getSender() != mCurrentRsu) {
        printCheck(false, "not from " + mCurrentRsu + ", the RSU I am activated with: ignored");
        return;
    }
    printCheck(true, "from " + mCurrentRsu + ", the RSU I am activated with");

    // tau_{i+2} = Poly1305(K_dg, t_i, m): the token G_{i+1} gave G_{i+2}, from what only G_{i+1} and I know
    const Block tau = forwardingToken(kDg->second, mLastAuthSlot);
    // K_dh_i = ECDH(X_V, Y_G_{i+2}) (X_V: the ECDH key of my bootstrap), then KT_i, KT_i^32 and auth_{i+2}
    Handover handover;
    handover.target = m.targetRsu;
    handover.keys = handoverKeys(ecdh(mEcdhKey.get(), publicKeyFromDer(m.targetRsuPublicKey).get()), tau);
    mHandover = handover;
    printDetail("tau_{i+2} = Poly1305(K_dg, t_i = " + std::to_string(mLastAuthSlot)
        + ", m); K_dh_i = ECDH(X_V, Y_G_{i+2}); KT_i = Poly1305(K_dh_i, K_dh_i xor tau_{i+2}, m)");

    if (mDeferHandover) {
        printDetail("Forwarding_Request to " + m.targetRsu + " held until requestForwarding()");
        return;
    }
    requestForwarding();
}

const std::string& BootstrapService::handoverTarget() const
{
    static const std::string none;
    return mHandover ? mHandover->target : none;
}

void BootstrapService::requestForwarding()
{
    // vehicle, after a Handover_Command: right away, or when its owner decides (deferHandover)
    if (!mHandover) {
        throw std::runtime_error(myName() + ": requestForwarding() without a Handover_Command");
    }
    printStep("ForwardingRequest");

    // OTP = Poly1305(KT_i^32, auth_{i+2} xor t_c, m): t_c, the slot I send it in (G_{i+2} tries its own +-1)
    const uint64_t t = otpSlot(localClock());
    ForwardingRequestPayload m;
    m.type = Forwarding_Request;
    m.auth = mHandover->keys.auth;                          // auth_{i+2} = SHA256(tau_{i+2})
    m.otp = forwardingOtp(mHandover->keys, t);
    mHandover->otp = m.otp;                                 // echoed by the Forwarding_Granted
    mHandover->slot = t;                                    // my t_i once G_{i+2} grants it
    mHandover->requested = true;
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }
    printDetail("t_c = " + std::to_string(t));

    // M = { Forwarding_Request, auth_{i+2}, OTP }
    sendBootstrap(Forwarding_Request, mHandover->target, 0, 0, "", pack(m));
}

void BootstrapService::ForwardingGranted(const BootstrapMsg& received)
{
    // vehicle, on Forwarding_Granted from G_{i+2}
    printStep("ForwardingGranted", &received);

    // any failed check: the message is ignored (I stay with my RSU)
    if (!mHandover || !mHandover->requested) {
        printCheck(false, "no Forwarding_Request sent: ignored");
        return;
    }
    if (received.getSender() != mHandover->target) {
        printCheck(false, "not from " + mHandover->target + ", the RSU I asked: ignored");
        return;
    }

    // 1. M = D_KT_i(E_KT_i(M)): AES-128-GCM, so a changed message or another key fails here
    const Bytes kt(mHandover->keys.kt.begin(), mHandover->keys.kt.end());
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

    // 2. G_{i+2} echoes the OTP it matched: it must be the one I sent
    if (CRYPTO_memcmp(m.otp.data(), mHandover->otp.data(), m.otp.size()) != 0) {
        printCheck(false, "OTP is not the one I sent: ignored");
        return;
    }
    printCheck(true, "OTP is the one I sent");

    // 3. auth'_{i+2} = SHA256(auth_{i+2}): G_{i+2} knew auth_{i+2} before my request (from tau_{i+2})
    const Sha256 authPrime = sha256(Bytes(mHandover->keys.auth.begin(), mHandover->keys.auth.end()));
    if (CRYPTO_memcmp(authPrime.data(), m.authPrime.data(), authPrime.size()) != 0) {
        printCheck(false, "auth'_{i+2} != SHA256(auth_{i+2}): ignored");
        return;
    }
    printCheck(true, "auth'_{i+2} = SHA256(auth_{i+2})");

    // 4. K_G_{i+2}
    if (m.kG.size() != kGroupKeySize) {
        printCheck(false, "K_G_{i+2} has " + std::to_string(m.kG.size()) + " bytes: ignored");
        return;
    }

    // activated with G_{i+2}: its K_g, K_dh_i as my K_dg with it, and t_c as t_i of my next handover
    mGroupKey = m.kG;
    mKdg[myName()] = mHandover->keys.kDh;
    mCurrentRsu = received.getSender();
    mLastAuthSlot = mHandover->slot;
    mHandover.reset();
    printKeep("K_g", mGroupKey, myName());
    printKeep("K_dg", mKdg[myName()], myName());
    trace::end(myName(), "handover done (now with " + mCurrentRsu + ")");

    if (mOnHandoverCompleted) {
        mOnHandoverCompleted(result(myName(), mCurrentRsu));
    }
}

SmartData BootstrapService::sendSecureData(const Bytes& value, uint32_t location, uint32_t metadata)
{
    // vehicle, once activated: the data path after the bootstrap (tee.pdf step 4), to the RSU I am activated with
    const auto kDg = mKdg.find(myName());
    if (mCurrentRsu.empty() || kDg == mKdg.end()) {
        throw std::runtime_error(myName() + ": Secure_Data before the bootstrap");
    }

    SmartData data;
    data.location = location;
    data.timing = static_cast<uint64_t>(localClock().ns());
    data.metadata = metadata;
    data.value = value;
    data.authD = mTraits.authD;

    // Message(AES(K_G, Data), Auth_d, OTP_dt), OTP_dt over AES(K_G, Data) with my PTP-synchronized clock
    const DataMessage message = sealSmartData(data, mGroupKey, kDg->second, localClock().ns());
    SecureDataPayload m;
    m.type = Secure_Data;
    m.cipherData = message.sealedData;
    m.authD = message.authD;
    m.otp = message.otp;
    sendBootstrap(Secure_Data, mCurrentRsu, 0, 0, "", pack(m));
    return data;
}

void BootstrapService::printStep(const char* step, const BootstrapMsg* received)
{
    // test output: shows that the flow reached this step
    if (received) {
        trace::step(myName(), step, stageName(received->getType()), received->getSender(), received->getVehicle());
    } else {
        trace::step(myName(), step);
    }
}

void BootstrapService::printDetail(const std::string& text) const
{
    // extra line under the last printStep
    trace::detail(myName(), text);
}

void BootstrapService::printCheck(bool ok, const std::string& text) const
{
    trace::check(myName(), ok, text);
}

void BootstrapService::printKeep(const std::string& name, const Bytes& value, const std::string& vehicle) const
{
    trace::keep(myName(), name, value, vehicle);
}

void BootstrapService::notifyCompleted(const std::string& vehicle, const std::string& rsu)
{
    mWindows.erase(vehicle);

    trace::end(myName(), "vehicle ready (with " + rsu + ")");

    if (mOnCompleted) {
        mOnCompleted(result(vehicle, rsu));
    }
}

BootstrapResult BootstrapService::result(const std::string& vehicle, const std::string& rsu)
{
    BootstrapResult result;
    result.vehicle = vehicle;
    result.rsu = rsu;
    result.kDg = mKdg[vehicle];
    result.kG = mGroupKey;
    result.kDe = mKde;
    result.authD = mTraits.authD;
    return result;
}

std::string BootstrapService::myName() const
{
    return mName; // "node[3]" or "rsu[0]"
}
