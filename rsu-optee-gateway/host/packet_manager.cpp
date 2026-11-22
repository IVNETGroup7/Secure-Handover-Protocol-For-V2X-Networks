#include "packet_manager.h"
#include "BootstrapPayload.h"
#include "HandoverPayload.h"
#include "MessageType.h"
#include "ProtocolMsg.h"
#include "SimTime.h"
#include "Trace.h"
#include "gateway_ta.h"
#include <chrono>
#include <cstdio>
#include <exception>
#include <stdexcept>

// the RSU is the PTP master: its clock is the reference (default: SimTime::now(), or anchored clock in HIL)
uint64_t PacketManager::now() const
{
    if (mClock) {
        return mClock();
    }
    return static_cast<uint64_t>(SimTime::now().ns());
}

// OT queue

void PacketManager::onOtPacket(const OtPacket& packet)
{
    if (packet.kind == OtPacket::Kind::SmartData) {
        onSmartData(packet);
        return;
    }
    ProtocolMsg msg;
    try {
        msg = deserialize(packet.bytes);
    } catch (const std::exception& e) { // another program on the link: reported, not fatal
        std::fprintf(stderr, "[%s] frame dropped: %s\n", mName.c_str(), e.what());
        return;
    }
    if (msg.getSender() != mName) { // the link also returns our own frames
        onRadio(msg);
    }
}

// Secure Marshaling (Fig. 5): Message(AES(K_G, Data), Auth_d, OTP_dt) into the OP-TEE TA, which returns the packet
// for the cloud (or refuses it); the first packet of each size is traced, every one measured
void PacketManager::onSmartData(const OtPacket& packet)
{
    using std::chrono::duration_cast;
    using std::chrono::nanoseconds;
    const auto dequeued = Clock::now();
    const bool traced = mTracedSizes.insert(packet.bytes.size()).second;
    if (traced) {
        trace::step(mName, "SecureMarshaling (OP-TEE TA)", "SmartData", packet.from, packet.from);
        const bool message = !packet.bytes.empty() && packet.bytes[0] == Secure_Data;
        trace::detail(mName, "OT packet = " + std::to_string(packet.bytes.size()) + " B, "
            + (message ? "in a Secure_Data message" : "reassembled from the radio frames")
            + " -> OT queue -> TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT");
    }

    const auto start = std::chrono::high_resolution_clock::now();
    const Reply reply = marshal(packet.bytes, now());
    const auto taCall = duration_cast<nanoseconds>(std::chrono::high_resolution_clock::now() - start);
    mBenchmark.taCall(packet.bytes.size(), taCall, reply.status);
    if (traced) {
        char text[96];
        std::snprintf(text, sizeof(text), "TA Invoke: %.1f us, %s", taCall.count() / 1e3, statusName(reply.status));
        trace::detail(mName, text);
    }

    switch (reply.status) {
        case GW_OK:
            break;
        case GW_IGNORED:
            ++mIgnored;
            if (traced) {
                trace::detail(mName, "the TA refused it: nothing for the cloud"); // its reason: the TA's own check
            }
            if (mTransport.cloudRefused) {
                mTransport.cloudRefused();
            }
            return;
        default:
            if (traced) {
                trace::check(mName, false, std::string("TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT: ") + statusName(reply.status));
            }
            if (mTransport.cloudRefused) {
                mTransport.cloudRefused();
            }
            return;
    }

    if (!mTransport.cloud) {
        if (traced) {
            trace::detail(mName, "IT packet = " + std::to_string(reply.payload.size()) + " B, but no cloud: dropped");
        }
        return;
    }
    if (traced) {
        trace::detail(mName, "IT packet = HTTPS Header | AES(K_eg, JSON) = " + std::to_string(reply.payload.size())
            + " B (made in the TA: Normal World cannot read the JSON) -> IT queue -> cloud");
    }
    ItPacket it;
    it.to = ItPacket::To::Cloud;
    it.vehicle = packet.from;
    it.bytes = reply.payload;
    it.received = packet.received;
    it.otSize = packet.bytes.size();
    it.traced = traced;
    mTransport.cloud(std::move(it));
    mBenchmark.queued(packet.bytes.size(), duration_cast<nanoseconds>(Clock::now() - dequeued));
}

void PacketManager::onRadio(const ProtocolMsg& msg)
{
    // OT radio is strictly for Vehicle <-> RSU traffic (Activation_Request is strictly IT: Operator -> ESA)
    if (msg.getDestination() != mName) {
        return;
    }

    switch (msg.getType()) {
        case PTP: {
            // Vehicle initiated IEEE 1588 PTP clock synchronization: reply with PTP_Sync(t_1)
            trace::step(mName, "PTPSync", messageTypeName(msg.getType()), msg.getSender(), msg.getVehicle());
            PtpPayload m;
            m.type = PTP_Sync;
            m.timestamp = SimTime::fromNs(static_cast<int64_t>(now()));
            send(PTP_Sync, msg.getSender(), msg.getAckNum(), msg.getSeqNum() + 1, "", pack(m), Via::Radio);
            break;
        }
        case PTP_Delay_Request: {
            // PTPDelayResponse: M = { PTP_Delay_Response, t_4 }
            trace::step(mName, "PTPDelayResponse", messageTypeName(msg.getType()), msg.getSender(), msg.getVehicle());
            PtpPayload m;
            m.type = PTP_Delay_Response;
            m.timestamp = SimTime::fromNs(static_cast<int64_t>(now())); // t_4: PTP_Delay_Request received
            send(PTP_Delay_Response, msg.getSender(), msg.getAckNum(), msg.getSeqNum() + 1, "", pack(m), Via::Radio);
            break;
        }
        case ECDH_Request:       onBootstrapStep("ECDHResponse", msg); break;
        case Auth_Request:       onBootstrapStep("SaveRSU + AuthGranted", msg); break;
        case Active_01:          onBootstrapStep("Active02", msg); break;
        case Forwarding_Request: onForwardingRequest(msg); break;   // Secrecy Forwarding, target RSU
        case Handover_Predict:   onHandoverPredict(msg); break;     // Encrypted CTRA Handover_Predict -> OP-TEE TA
        case Secure_Data:
            // the OT packet in a bootstrap message (no reassembly): the Secure Marshaling as for the data frames
            onSmartData({ OtPacket::Kind::SmartData, msg.getSender(), getPayload(msg), Clock::now() });
            break;
        default: break;
    }
}

void PacketManager::onHttps(const ProtocolMsg& msg)
{
    if (msg.getDestination() != mName) {
        return;
    }
    switch (msg.getType()) {
        case Activation_Token:  activationToken(msg); break;    // from the ESA (encrypted under K_esa)
        case Forwarding_Notice: forwardingNotice(msg); break;   // from peer RSU (encrypted under K_rsu)
        default: break;
    }
}

void PacketManager::activationToken(const ProtocolMsg& msg)
{
    // Step 3: opaque E_K_esa(Activation_Token) passed straight into OP-TEE TA; Normal World cannot read Auth_d/Auth_eg
    trace::step(mName, "ActivationToken (OP-TEE TA)", messageTypeName(msg.getType()), msg.getSender());
    const int status = addActivationToken(getPayload(msg), now());
    if (status == GW_IGNORED) {
        ++mIgnored;
        trace::detail(mName, "the TA refused the Activation_Token");
        return;
    }
    if (status != GW_OK) {
        trace::check(mName, false, std::string("TA_GATEWAY_CMD_ADD_ACTIVATION_TOKEN: ") + statusName(status));
    }
}

void PacketManager::onHandoverPredict(const ProtocolMsg& received)
{
    // Vehicle CTRA predictor sent E_K_dg(Handover_Predict, Auth_d, targetRsu, OTP_dt) -> verify & seal E_K_rsu inside TA
    trace::step(mName, "HandoverPredict (OP-TEE TA)", messageTypeName(received.getType()),
        received.getSender(), received.getVehicle());
    std::string targetRsu;
    Bytes sealedNotice;
    const int status = handleHandoverPredict(getPayload(received), now(), targetRsu, sealedNotice);
    if (status == GW_IGNORED) {
        ++mIgnored;
        trace::detail(mName, "the TA refused Handover_Predict");
        return;
    }
    if (status != GW_OK) {
        trace::check(mName, false, std::string("TA_GATEWAY_CMD_HANDLE_HANDOVER_PREDICT: ") + statusName(status));
        return;
    }
    send(Forwarding_Notice, targetRsu, 0, 0, received.getVehicle(), sealedNotice, Via::Https);
}

void PacketManager::forwardingNotice(const ProtocolMsg& msg)
{
    // target RSU G_{i+2}: opaque E_K_rsu(Forwarding_Notice) decrypted inside OP-TEE TA; pre-computes
    // K_dh_i = ECDH(X_gw, Y_V), KT_i, auth_{i+2}, and auth'_{i+2} inside TA (no Handover_Command sent)
    trace::step(mName, "ForwardingNotice (OP-TEE TA)", messageTypeName(msg.getType()), msg.getSender(), msg.getVehicle());
    const int status = receiveForwardingNotice(msg.getSender(), getPayload(msg), now());
    if (status == GW_IGNORED) {
        ++mIgnored;
        trace::detail(mName, "the TA refused Forwarding_Notice");
        return;
    }
    if (status != GW_OK) {
        trace::check(mName, false, std::string("TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE: ") + statusName(status));
    }
}

// ECDH_Request, Auth_Request, Active_01: into the TA; its reply goes where its type says
void PacketManager::onBootstrapStep(const char* step, const ProtocolMsg& received)
{
    trace::step(mName, std::string(step) + " (OP-TEE TA)", messageTypeName(received.getType()), received.getSender(),
        received.getVehicle());
    const Reply reply = handleBootstrap(received.getType(), received.getVehicle(), getPayload(received), now());
    if (reply.status == GW_IGNORED) {
        ++mIgnored;
        trace::detail(mName, "the TA refused it: nothing sent"); // its reason: the TA's own check
        return;
    }
    if (reply.status != GW_OK) {
        trace::check(mName, false, std::string("TA_GATEWAY_CMD_HANDLE_BOOTSTRAP: ") + statusName(reply.status));
        return;
    }

    if (reply.type == Active_02) {
        // E_K_esa(Active_02) sealed inside the TA -> forwarded opaque over backhaul to ESA
        send(Active_02, "esa", received.getAckNum(), received.getSeqNum() + 1, "", reply.payload, Via::Https);
        trace::end(mName, "RSU ready (" + received.getVehicle() + ")");
        return;
    }
    send(reply.type, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", reply.payload,
        Via::Radio);
}

// Forwarding_Request (Secrecy Forwarding, target RSU): into the TA -> Forwarding_Granted
void PacketManager::onForwardingRequest(const ProtocolMsg& received)
{
    trace::step(mName, "ForwardingGranted (OP-TEE TA)", messageTypeName(received.getType()), received.getSender(),
        received.getVehicle());
    const Reply reply = handleForwardingRequest(received.getVehicle(), getPayload(received), now());
    if (reply.status == GW_IGNORED) {
        ++mIgnored;
        trace::detail(mName, "the TA refused it: nothing sent");
        return;
    }
    if (reply.status != GW_OK) {
        trace::check(mName, false,
            std::string("TA_GATEWAY_CMD_HANDLE_FORWARDING_REQUEST: ") + statusName(reply.status));
        return;
    }
    send(Forwarding_Granted, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", reply.payload,
        Via::Radio);
    trace::end(mName, "handover done (" + received.getVehicle() + " now with " + mName + ")");
}

// send over the HTTPS sessions (the ESA, another RSU) or over the radio (the vehicles)
void PacketManager::send(int type, const std::string& destination, int seqNum, int ackNum, const std::string& vehicle,
    const Bytes& payload, Via via)
{
    ProtocolMsg msg;
    msg.setType(type);
    msg.setSender(mName);
    msg.setDestination(destination);
    msg.setVehicle(!vehicle.empty() ? vehicle : destination);
    msg.setSeqNum(seqNum);
    msg.setAckNum(ackNum);
    setPayload(msg, payload);

    const bool https = via == Via::Https;
    const auto& transport = https ? mTransport.https : mTransport.radio;
    if (!transport) {
        throw std::runtime_error(mName + ": no " + (https ? "HTTPS" : "radio") + " transport");
    }
    transport(msg);
}

int PacketManager::initIdentity(Bytes& outGatewayPubKey)
{
    return mTee.initIdentity(outGatewayPubKey);
}

int PacketManager::initGateway(const Bytes& caPubKey, const Bytes& gatewayCert, const Bytes& esaCert,
    const Bytes& groupKey)
{
    return mTee.initGateway(caPubKey, gatewayCert, esaCert, groupKey);
}

int PacketManager::registerPeerRsu(const std::string& peerName, const Bytes& peerCertDer)
{
    return mTee.registerPeerRsu(peerName, peerCertDer);
}

int PacketManager::initCloudSession(const std::string& certificatePem, const std::string& host)
{
    return mTee.initCloudSession(certificatePem, host, mName);
}

int PacketManager::addActivationToken(const Bytes& encryptedToken, uint64_t ptpTimeNs)
{
    return mTee.addActivationToken(encryptedToken, ptpTimeNs);
}

Reply PacketManager::handleBootstrap(int type, const std::string& session, const Bytes& payload, uint64_t ptpTimeNs)
{
    Reply reply;
    reply.status = mTee.handleBootstrap(type, session, payload, ptpTimeNs, reply.payload, reply.type);
    return reply;
}

int PacketManager::handleHandoverPredict(const Bytes& payload, uint64_t ptpTimeNs, std::string& outTargetRsu,
    Bytes& outSealedNotice)
{
    return mTee.handleHandoverPredict(payload, ptpTimeNs, outTargetRsu, outSealedNotice);
}

Reply PacketManager::handleForwardingRequest(const std::string& session, const Bytes& payload, uint64_t ptpTimeNs)
{
    Reply reply;
    reply.type = Forwarding_Granted;
    reply.status = mTee.handleForwardingRequest(session, payload, ptpTimeNs, reply.payload);
    return reply;
}

Reply PacketManager::marshal(const Bytes& otPacket, uint64_t ptpTimeNs)
{
    Reply reply;
    reply.status = mTee.secureMarshalOtToIt(otPacket, ptpTimeNs, reply.payload);
    return reply;
}

int PacketManager::triggerHandover(const std::string& session, const std::string& targetRsu, uint64_t authSlot,
    Bytes& outSealedNotice)
{
    return mTee.triggerHandover(session, targetRsu, authSlot, outSealedNotice);
}

int PacketManager::receiveForwardingNotice(const std::string& senderRsu, const Bytes& sealedNotice,
    uint64_t ptpTimeNs)
{
    return mTee.receiveForwardingNotice(senderRsu, sealedNotice, ptpTimeNs);
}

const char* statusName(int status)
{
    switch (status) {
        case GW_OK: return "GW_OK";
        case GW_IGNORED: return "GW_IGNORED";
        case GW_ERR_ARGS: return "GW_ERR_ARGS";
        case GW_ERR_BUFFER: return "GW_ERR_BUFFER";
        case GW_ERR_CRYPTO: return "GW_ERR_CRYPTO";
        case GW_ERR_STATE: return "GW_ERR_STATE";
        default: return "?";
    }
}

