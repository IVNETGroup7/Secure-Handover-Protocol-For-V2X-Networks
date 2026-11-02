#include "packet_manager.h"
#include "BootstrapPayload.h"
#include "BootstrapService.h"
#include "SimTime.h"
#include "Trace.h"
#include "gateway_ta.h"
#include <chrono>
#include <cstdio>
#include <exception>
#include <stdexcept>

namespace
{

// the RSU is the PTP master: its clock is the reference
uint64_t now()
{
    return static_cast<uint64_t>(SimTime::now().ns());
}

} // namespace

// OT queue

void PacketManager::onOtPacket(const OtPacket& packet)
{
    if (packet.kind == OtPacket::Kind::SmartData) {
        onSmartData(packet);
        return;
    }
    BootstrapMsg msg;
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
            return;
        default:
            if (traced) {
                trace::check(mName, false, std::string("TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT: ") + statusName(reply.status));
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

void PacketManager::onRadio(const BootstrapMsg& msg)
{
    // radio: unicast is logical (BootstrapService::isForMe); "esa": the ESA has no radio, the RSU relays it
    if (msg.getDestination() != mName && msg.getDestination() != "esa") {
        return;
    }

    switch (msg.getType()) {
        case Activation_Request: {
            // HTTPSEstablishment: relayed unchanged over the HTTPS session; the ESA unpacks M
            trace::step(mName, "HTTPSEstablishment", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
            send(Activation_Request, "esa", msg.getSeqNum(), msg.getAckNum(), msg.getVehicle(), getPayload(msg),
                Via::Https);
            break;
        }
        case PTP_Delay_Request: {
            // PTPDelayResponse: M = { PTP_Delay_Response, t_4 }
            trace::step(mName, "PTPDelayResponse", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
            PtpPayload m;
            m.type = PTP_Delay_Response;
            m.timestamp = SimTime::fromNs(static_cast<int64_t>(now())); // t_4: PTP_Delay_Request received
            send(PTP_Delay_Response, msg.getSender(), msg.getAckNum(), msg.getSeqNum() + 1, "", pack(m), Via::Radio);
            break;
        }
        case ECDH_Request:       teeStep("ECDHResponse", msg); break;
        case Auth_Request:       teeStep("SaveRSU + AuthGranted", msg); break;
        case Active_01:          teeStep("Active02", msg); break;
        case Forwarding_Request: teeStep("ForwardingGranted", msg); break;   // Secrecy Forwarding, target RSU
        case Secure_Data:
            // the OT packet in a bootstrap message (no reassembly): the Secure Marshaling as for the data frames
            onSmartData({ OtPacket::Kind::SmartData, msg.getSender(), getPayload(msg), Clock::now() });
            break;
        default: break;
    }
}

void PacketManager::onHttps(const BootstrapMsg& msg)
{
    if (msg.getDestination() != mName) {
        return;
    }
    switch (msg.getType()) {
        case Activation_Token:  activationToken(msg); break;    // from the ESA
        case Forwarding_Notice: forwardingNotice(msg); break;   // from the source RSU (I am the target)
        case Handover_Command:
            // from the target RSU (I am the source): to the vehicle, still in my range (maybe not yet in the target's)
            trace::step(mName, "HandoverCommand (relay)", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
            send(Handover_Command, msg.getVehicle(), msg.getAckNum(), msg.getSeqNum() + 1, "", getPayload(msg),
                Via::Radio);
            break;
        default: break;
    }
}

void PacketManager::activationToken(const BootstrapMsg& msg)
{
    // PTP: the activation goes into the TA (pending until its OTP), then PTPSync starts the clock exchange
    trace::step(mName, "PTP", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
    const ActivationTokenPayload token = unpackActivationToken(getPayload(msg));
    const int status = addActivationToken(msg.getVehicle(), static_cast<uint64_t>(token.t0.ns()),
        static_cast<uint64_t>(token.tf.ns()), token.authD, token.authEg);
    if (status != GW_OK) {
        trace::check(mName, false, std::string("TA_GATEWAY_CMD_ADD_ACTIVATION_TOKEN: ") + statusName(status));
        return;
    }

    // PTPSync: M = { PTP_Sync, t_1 }, t_1 taken as it goes out
    trace::step(mName, "PTPSync", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
    PtpPayload m;
    m.type = PTP_Sync;
    m.timestamp = SimTime::fromNs(static_cast<int64_t>(now()));
    send(PTP_Sync, msg.getVehicle(), msg.getAckNum(), msg.getSeqNum() + 1, "", pack(m), Via::Radio);
}

bool PacketManager::startHandover(const std::string& session, const std::string& targetRsu)
{
    // source RSU G_{i+1}: { Y_V, tau_{i+2}, Auth_d } from the TA (K_dg stays there), over HTTPS to G_{i+2}
    trace::step(mName, "SecrecyForwarding (OP-TEE TA): " + session + " -> " + targetRsu);
    ForwardingNoticePayload notice;
    const int status = triggerHandover(session, 0, notice);
    if (status != GW_OK) {
        if (status == GW_IGNORED) {
            ++mIgnored;
        }
        trace::check(mName, false, std::string("TA_GATEWAY_CMD_TRIGGER_HANDOVER: ") + statusName(status));
        return false;
    }
    for (const std::string& line : describe(notice)) {
        trace::detail(mName, line);
    }
    send(Forwarding_Notice, targetRsu, 0, 0, session, pack(notice), Via::Https);
    return true;
}

void PacketManager::forwardingNotice(const BootstrapMsg& msg)
{
    // target RSU G_{i+2}: K_dh_i, KT_i and auth_{i+2} pre-computed in the TA; Y_G_{i+2} goes back to the
    // source in a Handover_Command for the vehicle
    trace::step(mName, "ForwardingNotice (OP-TEE TA)", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
    const ForwardingNoticePayload notice = unpackForwardingNotice(getPayload(msg));
    for (const std::string& line : describe(notice)) {
        trace::detail(mName, line);
    }
    const Reply reply = receiveForwardingNotice(msg.getVehicle(), notice);
    if (reply.status != GW_OK) {
        trace::check(mName, false, std::string("TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE: ") + statusName(reply.status));
        return;
    }

    // M = { Handover_Command, G_{i+2}, Y_G_{i+2} }
    HandoverCommandPayload command;
    command.type = Handover_Command;
    command.targetRsu = mName;
    command.targetRsuPublicKey = reply.payload;
    send(Handover_Command, msg.getSender(), msg.getAckNum(), msg.getSeqNum() + 1, msg.getVehicle(), pack(command),
        Via::Https);
}

// ECDH_Request, Auth_Request, Active_01: into the TA; its reply goes where its type says
void PacketManager::teeStep(const char* step, const BootstrapMsg& received)
{
    trace::step(mName, std::string(step) + " (OP-TEE TA)", stageName(received.getType()), received.getSender(),
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
        // the same M to the ESA, over the HTTPS session; the protocol ends here for the RSU
        send(Active_02, "esa", received.getAckNum(), received.getSeqNum() + 1, received.getVehicle(), reply.payload,
            Via::Https);
        trace::end(mName, "RSU ready (" + received.getVehicle() + ")");
        return;
    }
    send(reply.type, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", reply.payload,
        Via::Radio);
    if (reply.type == Forwarding_Granted) {
        trace::end(mName, "handover done (" + received.getVehicle() + " now with " + mName + ")");
    }
}

// BootstrapService::sendBootstrap (RSU): the ESA and the other RSUs over HTTPS, the vehicles over the radio
void PacketManager::send(int type, const std::string& destination, int seqNum, int ackNum, const std::string& vehicle,
    const Bytes& payload, Via via)
{
    BootstrapMsg msg;
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

int PacketManager::initGateway(const Bytes& gatewayCert, const Bytes& esaPublicKey, const Bytes& groupKey)
{
    return mTee.initGateway(gatewayCert, esaPublicKey, groupKey);
}

int PacketManager::initCloudSession(const std::string& certificatePem, const std::string& host)
{
    return mTee.initCloudSession(certificatePem, host, mName);
}

int PacketManager::addActivationToken(const std::string& session, uint64_t t0, uint64_t tf, const Bytes& authD,
    const Bytes& authEg)
{
    return mTee.addActivationToken(session, t0, tf, authD, authEg);
}

Reply PacketManager::handleBootstrap(int type, const std::string& session, const Bytes& payload, uint64_t ptpTimeNs)
{
    Reply reply;
    reply.status = mTee.handleBootstrap(type, session, payload, ptpTimeNs, reply.payload, reply.type);
    return reply;
}

Reply PacketManager::marshal(const Bytes& otPacket, uint64_t ptpTimeNs)
{
    Reply reply;
    reply.status = mTee.secureMarshalOtToIt(otPacket, ptpTimeNs, reply.payload);
    return reply;
}

int PacketManager::triggerHandover(const std::string& session, uint64_t authSlot, ForwardingNoticePayload& notice)
{
    Block tau{};
    Bytes yv, authD;
    const int ret = mTee.triggerHandover(session, authSlot, tau, yv, authD);
    if (ret == GW_OK) {
        notice = ForwardingNoticePayload{ Forwarding_Notice, std::move(yv), tau, std::move(authD) };
    }
    return ret;
}

Reply PacketManager::receiveForwardingNotice(const std::string& session, const ForwardingNoticePayload& notice)
{
    Reply reply;
    reply.status = mTee.receiveForwardingNotice(session, notice.vehiclePublicKey, notice.tau, notice.authD,
        reply.payload);
    if (reply.status == GW_OK) {
        reply.type = Handover_Command;
    }
    return reply;
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

