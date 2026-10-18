#include "BootstrapService.h"
#include "BootstrapMsg.h"
#include "BootstrapPayload.h"
#include "Trace.h"
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <openssl/crypto.h>

const char* stageName(int type)
{
    static const char* names[] = { "Activation_Request", "HTTPS_Session", "Activation_Token", "PTP",
        "ECDH_Request", "ECDH_Response", "Auth_Request", "Save_RSU", "Auth_Granted", "Save_Vehicle",
        "Active_01", "Active_02", "Active_03", "PTP_Sync", "PTP_Delay_Request", "PTP_Delay_Response",
        "Forwarding_Notice", "Handover_Command", "Forwarding_Request", "Forwarding_Granted" };
    return (type >= 0 && type < 20) ? names[type] : "?";
}

// OTP_dt = Poly1305(K_dg, Auth_d xor t, m), the same on both sides: the vehicle (AuthRequest) and the RSU (SaveRSU)

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
    mName(config.name), mRole(config.role), mRng(config.seed)
{
    if (mRole == Role::Vehicle) {
        mAutoStart = config.autoStart;
        mClockOffset = config.clockOffset;
        mTraits = manufactureVehicle(myName(), mRng);
    } else {
        mHttpsSessionKey = config.httpsSessionKey;
        if (mHttpsSessionKey.empty()) {
            // random 256-bit key (seeded RNG, reproducible)
            std::ostringstream key;
            for (int i = 0; i < 32; ++i) {
                key << std::hex << std::setw(2) << std::setfill('0') << intuniform(mRng, 0, 255);
            }
            mHttpsSessionKey = key.str();
        }
        mGroupKey = config.groupKey;
        if (mGroupKey.empty()) {
            mGroupKey = randomBytes(kGroupKeySize);
        }
        if (mGroupKey.size() != kGroupKeySize) {
            throw std::runtime_error(myName() + ": K_g must have " + std::to_string(kGroupKeySize) + " bytes");
        }
        // the HTTPS session with the ESA is pre-established by the owner of the node
        // (ExternalSecurityAgent::registerRsu with httpsSessionKey())
    }
}

void BootstrapService::trigger()
{
    // autoStart: start when the vehicle enters the network
    if (mRole == Role::Vehicle && mAutoStart) {
        start();
    }
}

void BootstrapService::start(BootstrapCallback onCompleted)
{
    if (mRole != Role::Vehicle) {
        throw std::runtime_error("initBootstrap() is only for vehicles");
    }
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

void BootstrapService::handleHttps(const BootstrapMsg& msg)
{
    // HTTPS: replies of the ESA
    ++mReceived;
    dispatch(msg);
}

void BootstrapService::stampTransmission(BootstrapMsg& msg)
{
    // "hardware" timestamps: taken when the frame is handed to the transport, not when it was built
    // (a delay between both would break PTP's symmetric-delay assumption)
    if (msg.getType() == PTP_Sync) {
        // one-step PTP: t_1 is rewritten inside the frame before it goes on air
        PtpPayload m = unpackPtp(getPayload(msg));
        const simtime_t queued = m.timestamp;
        m.timestamp = localClock();
        setPayload(msg, pack(m));
        printDetail("t_1 stamped on air = " + m.timestamp.str() + " s (queued at " + queued.str() + " s)");
    } else if (msg.getType() == PTP_Delay_Request) {
        const simtime_t queued = mPtpT3;
        mPtpT3 = localClock();
        printDetail("t_3 stamped on air = " + mPtpT3.str() + " s (queued at " + queued.str() + " s)");
    }
}

bool BootstrapService::isForMe(const BootstrapMsg& msg) const
{
    // destination "esa": the ESA has no radio, so any RSU in range relays it over HTTPS
    const std::string destination = msg.getDestination();
    return destination == myName() || (destination == "esa" && mRole == Role::Rsu);
}

void BootstrapService::dispatch(const BootstrapMsg& msg)
{
    // no stages: the message was already filtered by destination (isForMe),
    // so its type alone says which step to run

    // from ECDH on, a message that arrives after t_f ends the protocol for that vehicle
    switch (msg.getType()) {
        case ECDH_Request: case ECDH_Response: case Auth_Request: case Auth_Granted:
        case Active_01: case Active_02: case Active_03:
            if (!withinDeadline(msg.getVehicle())) {
                return;
            }
            break;
        default:
            break;
    }

    switch (msg.getType()) {
        case Activation_Request: HTTPSEstablishment(msg); break; // RSU
        case Activation_Token:   PTP(msg); break;                // RSU (from the ESA)
        case PTP_Sync:           PTPDelayRequest(msg); break;    // vehicle
        case PTP_Delay_Request:  PTPDelayResponse(msg); break;   // RSU
        case PTP_Delay_Response: ECDHRequest(msg); break;        // vehicle
        // from here, everything must happen before arriving in t_f
        case ECDH_Request:       ECDHResponse(msg); break;       // RSU
        case ECDH_Response:      AuthRequest(msg); break;        // vehicle
        case Auth_Request:       SaveRSU(msg); break;            // RSU
        case Auth_Granted:       SaveVehicle(msg); break;        // vehicle
        case Active_01:          Active02(msg); break;           // RSU
        case Handover_Command:   HandoverCommand(msg); break;    // vehicle
        case Forwarding_Granted: ForwardingGranted(msg); break;  // vehicle
        default:
            // HTTPS_Session, ::PTP, Save_RSU and Save_Vehicle are never sent;
            // Active_02 (RSU -> ESA) and Active_03 (ESA -> user) never reach a vehicle or an RSU
            std::cerr << myName() << ": unexpected message type " << stageName(msg.getType()) << std::endl;
            break;
    }
}

void BootstrapService::activationRequest()
{
    // vehicle, on start(); goes to the ESA through the RSU in range (relayed in HTTPSEstablishment)
    printStep("activationRequest");

    // here we are doing an activation request
    // 1. we need to pass the public key of the gateway certificate (CY_g)
    // 2. we need to pass both timestamps for ptp and time to the protocol to realize (t_0 and t_f)
    // 3. we pass the manufacturing-time identification of the device (UUID) and the SHA256 of the firmware signature (SHA256(f_w)) 
    //    so nobody will forge on ECDH requests, both of those values are exclusive from the vehicle
    
    // the message that will be passed is
    // M = { Activation_Request, CY_g, t_0, t_f, UUID, SHA256(f_w) }

    // all those values must be stored on a file containing all those informations, split from BootstrapService.cpp
    // since we can use those values on future protocols, make like a traits.h that contains all those information or 
    // other file if you prefer

    ActivationRequestPayload m;
    m.type = Activation_Request;
    m.gatewayPublicKey = mTraits.gatewayPublicKey;  // CY_g
    m.t0 = localClock();                            // t_0
    m.tf = m.t0 + kActivationWindow;                // t_f
    mDeadlines[myName()] = m.tf;
    m.uuid = mTraits.uuid;                          // UUID
    m.firmwareHash = mTraits.firmwareHash;          // SHA256(f_w)

    sendBootstrap(Activation_Request, "esa", 0, 0, "", pack(m));
}

void BootstrapService::HTTPSEstablishment(const BootstrapMsg& received)
{
    // RSU, on Activation_Request from the vehicle to the ESA:
    // relays it unchanged (same type and payload M) over the HTTPS session; the ESA unpacks M
    printStep("HTTPSEstablishment", &received);
    sendBootstrap(Activation_Request, "esa", received.getSeqNum(), received.getAckNum(), received.getVehicle(),
        getPayload(received));
}

// PTP (IEEE 1588, delay request-response): the RSU is the master, the vehicle the slave
//   RSU -> vehicle: PTP_Sync -> RSU: PTP_Delay_Request -> vehicle: PTP_Delay_Response

void BootstrapService::PTP(const BootstrapMsg& received)
{
    // RSU, on Activation_Token from the ESA: starts the PTP exchange
    printStep("PTP", &received);

    const ActivationTokenPayload token = unpackActivationToken(getPayload(received));
    for (const std::string& line : describe(token)) {
        printDetail(line);
    }
    mDeadlines[received.getVehicle()] = token.tf; // checked from ECDH on (see dispatch)
    
    // save in a struct called PendingVehicles (on BootstrapService.h)
    // pending until an Auth_Request's OTP matches its Auth_d (SaveRSU)
    mPending[received.getVehicle()] = PendingVehicles{ token.authD, token.t0, token.tf, token.authEg };


    PTPSync(received);
}

void BootstrapService::PTPSync(const BootstrapMsg& received)
{
    // RSU (master), at the end of PTP
    printStep("PTPSync", &received);

    // 1. extract the exact timestamp from the RSU (t1)

    // the message that will be passed is
    // M = { PTP_Sync, t_1 }

    PtpPayload m;
    m.type = PTP_Sync;
    m.timestamp = localClock(); // t_1

    sendBootstrap(PTP_Sync, received.getVehicle(), received.getAckNum(), received.getSeqNum() + 1, "", pack(m));
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

void BootstrapService::PTPDelayResponse(const BootstrapMsg& received)
{
    // RSU (master), on PTP_Delay_Request
    printStep("PTPDelayResponse", &received);

    // M = { PTP_Delay_Request }
    for (const std::string& line : describe(unpackPtp(getPayload(received)))) {
        printDetail(line);
    }

    // 1. we will send the exact timestamp from now (t_4)

    // the message that will be passed is
    // M = { PTP_Delay_Response, t_4 }

    PtpPayload m;
    m.type = PTP_Delay_Response;
    m.timestamp = localClock(); // t_4: PTP_Delay_Request received

    sendBootstrap(PTP_Delay_Response, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", pack(m));
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

    // from here, everything must happen before t_f (checked with the corrected clock)
    if (!withinDeadline(myName())) {
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

void BootstrapService::ECDHResponse(const BootstrapMsg& received)
{
    // RSU, on ECDH_Request
    printStep("ECDHResponse", &received);

    // M = { ECDH_Request, Y_d }
    const EcdhPayload request = unpackEcdh(getPayload(received));
    for (const std::string& line : describe(request)) {
        printDetail(line);
    }

    // as the other step we will now give the value of it
    // we calculate the K_dg (as we have the X_g and Y_d) (Y is public and X is private)
    const auto keyG = newEcKey(kEcdhCurve); // X_g and Y_g, fresh for this vehicle
    const Bytes kDg = ecdh(keyG.get(), publicKeyFromDer(request.publicKey).get());
    mKdg[received.getVehicle()] = kDg;
    printKeep("K_dg", kDg, received.getVehicle());

    // the message that will be passed is
    // M = { ECDH_Response, Y_g }

    EcdhPayload m;
    m.type = ECDH_Response;
    m.publicKey = publicKeyDer(keyG.get()); // Y_g

    sendBootstrap(ECDH_Response, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", pack(m));
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
    // "guess" the value of the timestamp (ex : the timestamp is at 10:00:03.420) (we would do a window of 1 second and 100ms each),
    // so we calculate OTP guessing t -> 10:00:03.100 (wrong), 10:00:03.200 (right), so we have OTP and is valid 
    const uint64_t t = otpSlot(localClock());               // PTP-synchronized time slot
    const Block nonce = otpNonce(mTraits.authD, t);         // Auth_d xor t

    AuthRequestPayload otp;
    otp.type = Auth_Request;
    otp.otp = poly1305Aes(mKdg[myName()], nonce, otpMessage()); // OTP_dt
    mOtpSent = otp.otp;                                     // checked against the Auth_Granted (SaveVehicle)
    printDetail("t = " + std::to_string(t) + " (slots of " + std::to_string(kOtpTimeStep) + " s), Auth_d xor t = "
        + toHex(nonce.data(), nonce.size()));

    // the message that will be passed is
    // M = { Auth_Request, OTP_dt , t}

    sendBootstrap(Auth_Request, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", pack(otp));
}

void BootstrapService::SaveRSU(const BootstrapMsg& received)
{
    // RSU, on Auth_Request
    printStep("SaveRSU", &received);

    // M = { Auth_Request, OTP_dt }: t is not sent, the RSU guesses it with its own clock (PTP master)
    const AuthRequestPayload request = unpackAuthRequest(getPayload(received));
    for (const std::string& line : describe(request)) {
        printDetail(line);
    }

    // 1. we calculate the OTP that was
    // no identifier goes in clear, so the session (the K_dg of the ECDH made in it) does not say which
    // pending activation it belongs to: the RSU tries every pending Auth_d with every t in a window of
    // +-kOtpWindow slots around its own truncated clock, and a match binds the session to that Auth_d
    //   OTP_candidate = Poly1305(K_dg, Auth_d_pending xor t_candidate, m)
    auto kDg = mKdg.find(received.getVehicle());
    if (kDg == mKdg.end()) {
        printCheck(false, "no K_dg for this session: ignored");
        return;
    }

    const simtime_t now = localClock();
    const uint64_t tNow = otpSlot(now);

    // past its t_f an activation is no longer pending
    for (auto pending = mPending.begin(); pending != mPending.end();) {
        pending = now > pending->second.tf ? mPending.erase(pending) : std::next(pending);
    }

    auto match = mPending.end();
    uint64_t tMatch = 0;
    for (auto pending = mPending.begin(); pending != mPending.end() && match == mPending.end(); ++pending) {
        for (uint64_t t = tNow - kOtpWindow; t <= tNow + kOtpWindow; ++t) {
            const Block candidate = poly1305Aes(kDg->second, otpNonce(pending->second.authD, t), otpMessage());
            if (CRYPTO_memcmp(candidate.data(), request.otp.data(), candidate.size()) == 0) { // constant time
                match = pending;
                tMatch = t;
                break;
            }
        }
    }

    if (match == mPending.end()) {
        // no combination matches: the message is ignored
        printCheck(false, "OTP_dt matches no pending Auth_d (" + std::to_string(mPending.size()) + " pending x "
            + std::to_string(2 * kOtpWindow + 1) + " slots around t = " + std::to_string(tNow) + "): ignored");
        return;
    }

    const long long slotOffset = static_cast<long long>(tMatch) - static_cast<long long>(tNow);
    printCheck(true, "OTP_dt matches the Auth_d of the activation of " + match->first + " with t = "
        + std::to_string(tMatch) + " (my slot " + (slotOffset >= 0 ? "+" : "") + std::to_string(slotOffset) + ")");

    // the session (and its K_dg) is now bound to that Auth_d: status active
    mActive[received.getVehicle()] = match->second;
    mPending.erase(match);

    AuthGranted(received);
}

void BootstrapService::AuthGranted(const BootstrapMsg& received)
{
    // RSU, at the end of SaveRSU
    printStep("AuthGranted", &received);

    // the RSU confirmed it's the vehicle
    // 1. generate message
    // all the informations being passed on the message is available
    // M = { Auth_Granted, OTP_dt, K_dg, K_g, CY_e }

    AuthGrantedPayload m;
    m.type = Auth_Granted;
    m.otp = unpackAuthRequest(getPayload(received)).otp;    // OTP_dt: the one SaveRSU matched
    m.kDg = mKdg.at(received.getVehicle());                 // K_dg: of this session
    m.kG = mGroupKey;                                       // K_g
    m.esaPublicKey = mEsaPublicKey;                         // CY_e
    m.authEg = mActive.at(received.getVehicle()).authEg;    // Auth_eg: lets the vehicle check CY_e (SaveVehicle)
    if (m.esaPublicKey.empty()) {
        throw std::runtime_error(myName() + ": no CY_e (HTTPS session with the ESA not established)");
    }
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // 2. Encrypt the message M using K_dg (key formed on ECDH)
    // you can use AES-128 CBC for example or other chain considered better
    // AES-256-GCM with the whole K_dg (32 bytes): authenticated, so the vehicle also detects any change on air
    const Bytes sealed = aesGcmEncrypt(m.kDg, pack(m));
    printDetail("E_K_dg(M) = AES-256-GCM, " + std::to_string(sealed.size()) + " bytes (nonce | ciphertext | tag)");

    sendBootstrap(Auth_Granted, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", sealed);
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

    // 3. Auth_eg = AES(Id_d, CY_e): only who knows Id_d (the ESA, from my Activation_Request) makes it,
    //    so recomputing it with my Id_d and the CY_e received proves CY_e is the ESA's key
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

void BootstrapService::Active02(const BootstrapMsg& received)
{
    // RSU, on Active_01
    printStep("Active02", &received);

    // 1. Decrypt the message from the vehicle (AES-256-GCM) with K_dg
    // 2. repass the same message M 
    // M = { Auth_d, OTP_dt, Auth_de }
    // 3. here in theory it would be no need to encrypt since HTTPS is already
    // stablished between ESA and RSU

    const auto kDg = mKdg.find(received.getVehicle());
    if (kDg == mKdg.end()) {
        printCheck(false, "no K_dg for this session: ignored");
        return;
    }

    // 1. M = D_K_dg(E_K_dg(M)): a changed message or another key fails here
    const auto plain = aesGcmDecrypt(kDg->second, getPayload(received));
    if (!plain) {
        printCheck(false, "E_K_dg(M) does not decrypt with the K_dg of this session: ignored");
        return;
    }
    printCheck(true, "E_K_dg(M) decrypts with the K_dg of this session (GCM tag valid)");
    Active01Payload m = unpackActive01(*plain);
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // 2. the same M (Auth_d, OTP_dt, Auth_de) to the ESA, over the HTTPS session (3. no extra encryption)
    m.type = Active_02;
    sendBootstrap(Active_02, "esa", received.getAckNum(), received.getSeqNum() + 1, received.getVehicle(), pack(m));

    // the protocol ends here for the RSU (the ESA ends it with the Active_03)
    notifyCompleted(received.getVehicle(), myName());
}

// ---------------------------------------------------------------------------------------------

bool BootstrapService::withinDeadline(const std::string& vehicle)
{
    auto deadline = mDeadlines.find(vehicle);
    if (deadline != mDeadlines.end() && localClock() <= deadline->second) {
        printCheck(true, "t = " + localClock().str() + " s <= t_f = " + deadline->second.str() + " s");
        return true;
    }

    // past t_f (or no t_f known for this vehicle): the protocol ends here for this vehicle
    if (deadline == mDeadlines.end()) {
        trace::end(myName(), "aborted: no t_f for " + vehicle);
    } else {
        trace::end(myName(), "aborted: t_f exceeded (" + localClock().str() + " s > t_f = " + deadline->second.str() + " s)");
        mDeadlines.erase(deadline);
    }
    mKdg.erase(vehicle); // an aborted bootstrap leaves no key
    mPending.erase(vehicle);
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
    return mRole == Role::Vehicle ? simTime() + mClockOffset : simTime();
}

void BootstrapService::sendBootstrap(int type, const std::string& destination, int seqNum, int ackNum,
    const std::string& vehicle, const Bytes& payload)
{
    BootstrapMsg msg;
    msg.setType(type);
    msg.setSender(myName());
    msg.setDestination(destination);
    msg.setVehicle(!vehicle.empty() ? vehicle : mRole == Role::Vehicle ? myName() : destination);
    msg.setSeqNum(seqNum);
    msg.setAckNum(ackNum);
    setPayload(msg, payload);
    ++mSent;

    if (destination == "esa" && mRole == Role::Rsu) {
        // pre-established HTTPS session: bypasses the radio (a vehicle's "esa" goes over the radio to the RSU)
        if (vehicle.empty()) {
            throw std::runtime_error("HTTPS: sendBootstrap to the ESA needs the vehicle");
        }
        if (!mTransport.https) {
            throw std::runtime_error(myName() + ": no HTTPS transport");
        }
        mTransport.https(msg);
        return;
    }

    if (!mTransport.radio) {
        throw std::runtime_error(myName() + ": no radio transport");
    }
    stampTransmission(msg); // PTP: timestamps of the moment the message leaves
    mTransport.radio(msg);
}

void BootstrapService::HandoverCommand(const BootstrapMsg& received)
{
    printStep("HandoverCommand", &received);
    const HandoverCommandPayload m = unpackHandoverCommand(getPayload(received));

    // K_dh_i = Y_G_next ^ X_V[cite: 39]
    const Bytes kDh = ecdh(mEcdhKey.get(), publicKeyFromDer(m.targetRsuPublicKey).get());

    // tau is derived exactly as the source RSU did (using K_dg and the recorded t_i)
    Block nonce{};
    for (int i = 0; i < 8; ++i) nonce[15 - i] = static_cast<uint8_t>(mTi >> (8 * i));
    Block tau = poly1305Aes(mKdg[myName()], nonce, otpMessage());

    // KT_i = Poly1305(K_dh, K_dh xor tau)[cite: 39]
    Block ktNonce{};
    for(int i=0; i<16; ++i) ktNonce[i] = kDh[i] ^ tau[i];
    const Block kt = poly1305Aes(kDh, ktNonce, otpMessage());
    mKt = Bytes(kt.begin(), kt.end());

    Bytes tauBytes(tau.begin(), tau.end());
    Sha256 auth = sha256(tauBytes);

    ForwardingRequestPayload req;
    req.type = Forwarding_Request;
    req.auth = auth;
    req.otp = poly1305Aes(mKt, otpNonce(Bytes(auth.begin(), auth.end()), otpSlot(localClock())), otpMessage());

    sendBootstrap(Forwarding_Request, "target_rsu", received.getAckNum(), received.getSeqNum() + 1, "", pack(req));
}

void BootstrapService::ForwardingGranted(const BootstrapMsg& received)
{
    printStep("ForwardingGranted", &received);
    
    // D_KT_i(E_KT_i(M))[cite: 39]
    const auto plain = aesGcmDecrypt(mKt, getPayload(received));
    if (!plain) {
        printCheck(false, "Forwarding_Granted decryption failed");
        return;
    }
    
    const ForwardingGrantedPayload m = unpackForwardingGranted(*plain);
    mGroupKey = m.kG;
    printKeep("New K_g", mGroupKey, myName());
    
    // Handover complete. Vehicle resumes normal CAM operation with target RSU.
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
    mDeadlines.erase(vehicle);

    trace::end(myName(), mRole == Role::Vehicle ? "vehicle ready (with " + rsu + ")" : "RSU ready (" + vehicle + ")");

    if (mOnCompleted) {
        BootstrapResult result;
        result.vehicle = vehicle;
        result.rsu = rsu;
        result.kDg = mKdg[vehicle];
        result.kG = mGroupKey;
        result.kDe = mKde;
        if (mRole == Role::Vehicle) {
            result.authD = mTraits.authD;
        }
        mOnCompleted(result);
    }
}

std::string BootstrapService::myName() const
{
    return mName; // "node[3]" or "rsu[0]"
}
