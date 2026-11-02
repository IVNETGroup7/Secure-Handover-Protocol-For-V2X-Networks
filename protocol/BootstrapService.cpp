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
        "Forwarding_Notice", "Handover_Command", "Forwarding_Request", "Forwarding_Granted", "Secure_Data" };
    return (type >= 0 && type < static_cast<int>(sizeof(names) / sizeof(names[0]))) ? names[type] : "?";
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
        mDeferHandover = config.deferHandover;
        mClockOffset = config.clockOffset;
        mGatewayPublicKey = config.gatewayPublicKey;
        mTraits = manufactureVehicle(mRng);
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

    // from ECDH on, a message outside the activation window [t_0, t_f] ends the protocol for that vehicle
    switch (msg.getType()) {
        case ECDH_Request: case ECDH_Response: case Auth_Request: case Auth_Granted:
        case Active_01: case Active_02: case Active_03:
            if (!withinWindow(msg.getVehicle())) {
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
        // from here, everything must happen inside [t_0, t_f]
        case ECDH_Request:       ECDHResponse(msg); break;       // RSU
        case ECDH_Response:      AuthRequest(msg); break;        // vehicle
        case Auth_Request:       SaveRSU(msg); break;            // RSU
        case Auth_Granted:       SaveVehicle(msg); break;        // vehicle
        case Active_01:          Active02(msg); break;           // RSU
        // Secrecy Forwarding, once activated (no activation window: the vehicle is already active)
        case Handover_Command:   HandoverCommand(msg); break;    // vehicle
        case Forwarding_Granted: ForwardingGranted(msg); break;  // vehicle
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
    mWindows[received.getVehicle()] = { token.t0, token.tf }; // checked from ECDH on (see dispatch)
    
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
    mActive.erase(received.getVehicle()); // a new K_dg, not yet authenticated: the old one's binding goes with it
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
    // as the paper: "It then computes OTP_dt for each combination of ECDH master secrets not yet authenticated
    // and Auth_d pending activation using (8)": every K_dg of an ECDH not yet bound to an activation, with every
    // pending Auth_d and every t in +-kOtpWindow slots around the RSU's own truncated clock; a match binds that
    // K_dg to that Auth_d (status active)
    //   OTP_candidate = Poly1305(K_dg_unauthenticated, Auth_d_pending xor t_candidate, m)
    const simtime_t now = localClock();
    const uint64_t tNow = otpSlot(now);

    // past its t_f an activation is no longer pending
    for (auto pending = mPending.begin(); pending != mPending.end();) {
        pending = now > pending->second.tf ? mPending.erase(pending) : std::next(pending);
    }

    std::string session;            // the ECDH session whose K_dg matched
    auto match = mPending.end();
    uint64_t tMatch = 0;
    size_t unauthenticated = 0;
    for (const auto& [candidateSession, kDg] : mKdg) {
        if (mActive.count(candidateSession) != 0) {
            continue; // K_dg already bound to an activation
        }
        ++unauthenticated;
        for (auto pending = mPending.begin(); pending != mPending.end() && match == mPending.end(); ++pending) {
            for (uint64_t t = tNow - kOtpWindow; t <= tNow + kOtpWindow; ++t) {
                const Block candidate = poly1305Aes(kDg, otpNonce(pending->second.authD, t), otpMessage());
                if (CRYPTO_memcmp(candidate.data(), request.otp.data(), candidate.size()) == 0) { // constant time
                    session = candidateSession;
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
        // no combination matches: the message is ignored
        printCheck(false, "OTP_dt matches no combination (" + std::to_string(unauthenticated)
            + " K_dg not yet authenticated x " + std::to_string(mPending.size()) + " pending Auth_d x "
            + std::to_string(2 * kOtpWindow + 1) + " slots around t = " + std::to_string(tNow) + "): ignored");
        return;
    }

    const long long slotOffset = static_cast<long long>(tMatch) - static_cast<long long>(tNow);
    printCheck(true, "OTP_dt matches the K_dg of the ECDH with " + session + " and the Auth_d of the activation of "
        + match->first + ", with t = " + std::to_string(tMatch) + " (my slot " + (slotOffset >= 0 ? "+" : "")
        + std::to_string(slotOffset) + ")");

    // that K_dg is now bound to that Auth_d: status active
    mActive[session] = match->second;
    mPending.erase(match);

    AuthGranted(received, session);
}

void BootstrapService::AuthGranted(const BootstrapMsg& received, const std::string& session)
{
    // RSU, at the end of SaveRSU; "session": the ECDH session whose K_dg the OTP matched
    printStep("AuthGranted", &received);

    // the RSU confirmed it's the vehicle
    // 1. generate message
    // all the informations being passed on the message is available
    // M = { Auth_Granted, OTP_dt, K_g, CY_e, Auth_eg }     (the paper's (10): Auth_Granted(Auth_eg, OTP_dt, K_G, CY_e))

    const Bytes& kDg = mKdg.at(session);
    AuthGrantedPayload m;
    m.type = Auth_Granted;
    m.otp = unpackAuthRequest(getPayload(received)).otp;    // OTP_dt: the one SaveRSU matched
    m.kG = mGroupKey;                                       // K_g
    m.esaPublicKey = mEsaPublicKey;                         // CY_e
    m.authEg = mActive.at(session).authEg;                  // Auth_eg: lets the vehicle check CY_e (SaveVehicle)
    if (m.esaPublicKey.empty()) {
        throw std::runtime_error(myName() + ": no CY_e (HTTPS session with the ESA not established)");
    }
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // 2. Encrypt the message M using K_dg (key formed on ECDH)
    // AES-256-GCM with the whole K_dg (32 bytes): authenticated, so the vehicle also detects any change on air
    const Bytes sealed = aesGcmEncrypt(kDg, pack(m));
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
    if (mRole != Role::Vehicle || mCurrentRsu.empty() || kDg == mKdg.end()) {
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

    trace::end(myName(), mRole == Role::Vehicle ? "vehicle ready (with " + rsu + ")" : "RSU ready (" + vehicle + ")");

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
    if (mRole == Role::Vehicle) {
        result.authD = mTraits.authD;
    }
    return result;
}

std::string BootstrapService::myName() const
{
    return mName; // "node[3]" or "rsu[0]"
}
