// Self-test of the port (tee.pdf step 5): the bootstrap of a vehicle with the RSU running in the enclave.
// The vehicle and the ESA are the repository's own (protocol/BootstrapService, protocol/ExternalSecurityAgent),
// so the enclave must speak exactly their protocol; the network is in memory. Scenarios:
//   1. normal                        the vehicle gets ready, the ESA ends the protocol
//   2. OTP changed on the air        the enclave finds no matching Auth_d: ignored, nothing more
//   3. Auth_Request after t_f        the enclave aborts the session
//   4. Secrecy Forwarding + Secure Marshaling, with this test as the cloud
//      4a-4g  SmartData of the vehicle of 1 (tee.pdf step 4): the IT packet is HTTPS Header | AES(K_eg, JSON),
//             with no JSON in clear, and the cloud's K_eg opens it to exactly what the vehicle sent; a changed
//             OTP_dt, a changed AES(K_G, Data), an unknown Auth_d or an old t are refused; a new K_eg every
//             kMessagesPerSession packets
//      4h-4m  rsu[1]: a second enclave in this process (its own memory, sealed state and K_g). node[0] bootstraps
//             with rsu[0] and sends it SmartData; rsu[0] hands it over to rsu[1] (Forwarding_Notice,
//             Handover_Command, Forwarding_Request, Forwarding_Granted: common/Handover.h); node[0] then holds
//             rsu[1]'s K_g and its SmartData is marshaled by rsu[1]; a replayed Forwarding_Request and SmartData
//             with the keys of before the handover are refused by rsu[1]
//   5. CY_g of no gateway            the ESA issues no Activation_Token: nothing starts
//   6. before t_0                    the vehicle's window starts in the future: the enclave aborts at ECDH

#include "modes.h"
#include "Bootstrap.h"
#include "BootstrapMsg.h"
#include "BootstrapPayload.h"
#include "BootstrapService.h"
#include "ExternalSecurityAgent.h"
#include "Https.h"
#include "Link.h"
#include "SimTime.h"
#include "SmartData.h"
#include "Traits.h"
#include "gateway.h"
#include "ocalls.h"
#include "packet_manager.h"
#include <sgx_urts.h>
#include <chrono>
#include <cstdio>
#include <deque>
#include <exception>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace
{

// the links of the in-memory network; Https: the backhaul by destination (the ESA or an RSU)
enum class Link { Radio, ToEsa, ToRsu, Https };

struct Frame
{
    Link link;
    Bytes bytes;    // serialize(BootstrapMsg): as on a socket
};

struct Outcome
{
    bool vehicleReady = false;
    bool protocolEnded = false;     // the ESA sent the Active_03
    int ignored = 0;                // messages the enclave refused
    BootstrapResult result;         // the vehicle's keys (K_dg, K_g, Auth_d), when it got ready
};

// one vehicle's bootstrap against the gateway; "gatewayPublicKey": the CY_g its Activation_Request names;
// "onAir" may change (or delay) a frame before it is delivered; "clockOffset": the vehicle clock's error
Outcome bootstrap(const std::string& vehicleName, unsigned seed, PacketManager& gateway, ExternalSecurityAgent& esa,
    const Bytes& gatewayPublicKey, const std::function<void(BootstrapMsg&)>& onAir = nullptr, double clockOffset = 0)
{
    std::deque<Frame> air;
    Outcome outcome;
    const int ignoredBefore = gateway.ignored();

    BootstrapService::Config config;
    config.name = vehicleName;
    config.role = BootstrapService::Role::Vehicle;
    config.seed = seed;
    config.gatewayPublicKey = gatewayPublicKey;
    config.clockOffset = clockOffset;
    BootstrapService vehicle(config);

    BootstrapService::Transport vehicleLinks;
    vehicleLinks.radio = [&](const BootstrapMsg& msg) { air.push_back({ Link::Radio, serialize(msg) }); };
    vehicle.setTransport(vehicleLinks);

    PacketManager::Transport gatewayLinks;
    gatewayLinks.radio = [&](const BootstrapMsg& msg) { air.push_back({ Link::Radio, serialize(msg) }); };
    gatewayLinks.https = [&](const BootstrapMsg& msg) { air.push_back({ Link::ToEsa, serialize(msg) }); };
    gateway.setTransport(gatewayLinks);

    esa.setTransport([&](const BootstrapMsg& msg) {
        if (msg.getType() == Active_03) {
            outcome.protocolEnded = msg.getVehicle() == vehicleName; // to the user: nobody here receives it
        } else {
            air.push_back({ Link::ToRsu, serialize(msg) });
        }
    });

    initBootstrap(vehicle, [&](const BootstrapResult& result) {
        outcome.vehicleReady = true;
        outcome.result = result;
    });
    while (!air.empty()) {
        Frame frame = std::move(air.front());
        air.pop_front();
        BootstrapMsg msg = deserialize(frame.bytes);
        if (onAir) {
            onAir(msg);
        }
        switch (frame.link) {
            case Link::Radio: vehicle.indicate(msg); gateway.onRadio(msg); break;
            case Link::ToEsa: esa.handleMessage(msg); break;
            case Link::ToRsu: gateway.onHttps(msg); break;
            case Link::Https: break;
        }
    }
    outcome.ignored = gateway.ignored() - ignoredBefore;
    return outcome;
}

bool report(const char* scenario, bool ok, const Outcome& outcome)
{
    std::printf("  %-34s vehicle ready: %-3s  protocol ended: %-3s  ignored by the enclave: %d   %s\n", scenario,
        outcome.vehicleReady ? "yes" : "no", outcome.protocolEnded ? "yes" : "no", outcome.ignored,
        ok ? "ok" : "UNEXPECTED");
    return ok;
}

// the JSON the cloud must get for "data" (Fig. 5; the format of Enclave/marshaling.cpp)
std::string expectedJson(const SmartData& data)
{
    return "{\"Location\":" + std::to_string(data.location) + ",\"Timing\":" + std::to_string(data.timing)
        + ",\"Metadata\":" + std::to_string(data.metadata) + ",\"Value\":\"" + base64Encode(data.value)
        + "\",\"Trust\":\"" + toHex(data.authD.data(), data.authD.size()) + "\"}";
}

// what the cloud does with an IT packet (HTTPS Header | AES(K_eg, JSON)): K_eg from Y_s and its own X_e,
// then the JSON. "ys": the session key of the header. nullopt: not such a packet, or it does not open
std::optional<std::string> openAsCloud(const CloudIdentity& cloud, const Bytes& itPacket, std::string* ys = nullptr)
{
    const std::string text(itPacket.begin(), itPacket.end());
    const size_t end = text.find("\r\n\r\n");
    const std::string field = std::string("\r\n") + kSessionKeyHeader + ": ";
    const size_t start = text.find(field);
    if (end == std::string::npos || start == std::string::npos || start > end) {
        return std::nullopt;
    }
    const std::string key = text.substr(start + field.size(), text.find("\r\n", start + 2) - start - field.size());
    const auto der = base64Decode(key);
    if (!der) {
        return std::nullopt;
    }
    const Bytes kEg = computeKEg(cloud.key.get(), publicKeyFromDer(*der).get());
    const auto json = aesGcmDecrypt(kEg, Bytes(itPacket.begin() + end + 4, itPacket.end()));
    if (!json) {
        return std::nullopt;
    }
    if (ys) {
        *ys = key;
    }
    return std::string(json->begin(), json->end());
}

// one OT packet through ecall_secure_marshal_ot_to_it: its status must be "expected" and, for GW_OK, the IT
// packet must carry no JSON in clear and open, with the cloud's key, to the JSON of "data"
bool marshalCase(PacketManager& gateway, const CloudIdentity& cloud, const char* name, const Bytes& packet,
    int expected, const SmartData* data = nullptr)
{
    const Reply reply = gateway.marshal(packet, static_cast<uint64_t>(SimTime::now().ns()));
    bool ok = reply.status == expected;
    std::string detail = statusName(reply.status);
    if (ok && expected == GW_OK && data) {
        const std::string json = expectedJson(*data);
        const std::string it(reply.payload.begin(), reply.payload.end());
        const bool clear = it.find("\"Location\"") != std::string::npos || it.find(base64Encode(data->value)) != std::string::npos;
        const auto opened = openAsCloud(cloud, reply.payload);
        ok = !clear && opened && *opened == json;
        detail += clear ? ", JSON IN CLEAR in the IT packet" : !opened ? ", the cloud CANNOT OPEN it"
            : *opened != json ? ", JSON DIFFERS from what the vehicle sent"
            : ", no JSON in clear; K_eg opens it to what the vehicle sent (" + std::to_string(reply.payload.size()) + " B)";
    }
    std::printf("  %-34s %s   %s\n", name, detail.c_str(), ok ? "ok" : "UNEXPECTED");
    return ok;
}

bool secureMarshaling(PacketManager& gateway, const CloudIdentity& cloud, const BootstrapResult& vehicle)
{
    if (vehicle.authD.empty()) {
        std::printf("  (the vehicle of 1 did not get ready: nothing to send)\n");
        return false;
    }
    auto smartData = [&](size_t size) {
        SmartData data;
        data.location = 4242;
        data.timing = static_cast<uint64_t>(SimTime::now().ns());
        data.metadata = 1;
        data.value = randomBytes(size);
        data.authD = vehicle.authD;
        return data;
    };
    auto seal = [&](const SmartData& data, int64_t at) {
        return sealSmartData(data, vehicle.kG, vehicle.kDg, at);
    };
    const int64_t now = SimTime::now().ns();
    bool ok = true;

    const SmartData small = smartData(32);
    ok &= marshalCase(gateway, cloud, "4a. SmartData 32 B", packDataMessage(seal(small, now)), GW_OK, &small);
    const SmartData large = smartData(kMaxSmartDataValue);
    ok &= marshalCase(gateway, cloud, "4b. SmartData 64 KB - 1", packDataMessage(seal(large, now)), GW_OK, &large);

    DataMessage otp = seal(small, now);
    otp.otp[3] ^= 1;
    ok &= marshalCase(gateway, cloud, "4c. OTP_dt changed", packDataMessage(otp), GW_IGNORED);

    // the data changed and its OTP_dt made again over it (as the vehicle could): only the GCM tag catches it
    DataMessage data = seal(small, now);
    data.sealedData[20] ^= 1;
    data.otp = dataOtp(vehicle.kDg, data.authD, dataOtpSlot(now), data.sealedData);
    ok &= marshalCase(gateway, cloud, "4d. AES(K_G, Data) changed", packDataMessage(data), GW_IGNORED);

    SmartData stranger = small;
    stranger.authD = randomBytes(vehicle.authD.size());
    ok &= marshalCase(gateway, cloud, "4e. Auth_d of no activated vehicle", packDataMessage(seal(stranger, now)),
        GW_IGNORED);

    const int64_t old = now - static_cast<int64_t>((kOtpWindow + 2) * kOtpTimeStep * 1e9);
    ok &= marshalCase(gateway, cloud, "4f. t outside the OTP window", packDataMessage(seal(small, old)), GW_IGNORED);

    // a new HTTPS session (Y_s, K_eg) once kMessagesPerSession packets used the current one
    std::string first, ys;
    int packets = 0;
    bool renewed = false, opened = true;
    for (; packets <= kMessagesPerSession && !renewed; ++packets) {
        const Reply reply = gateway.marshal(packDataMessage(seal(small, SimTime::now().ns())),
            static_cast<uint64_t>(SimTime::now().ns()));
        opened = opened && reply.status == GW_OK && openAsCloud(cloud, reply.payload, &ys).has_value();
        if (first.empty()) {
            first = ys;
        }
        renewed = ys != first;
    }
    const bool sessionOk = renewed && opened;
    std::printf("  %-34s %s   %s\n", "4g. new K_eg per session", (renewed ? "new Y_s after " + std::to_string(packets - 1)
        + " more packet(s), every one opened by the cloud" : std::string("NO NEW SESSION")).c_str(),
        sessionOk ? "ok" : "UNEXPECTED");
    return ok && sessionOk;
}

// 4h-4m: node[0] from rsu[0] to rsu[1] (Secrecy Forwarding), SmartData to each; "kG1": rsu[1]'s K_g
bool secrecyForwarding(PacketManager& rsu0, PacketManager& rsu1, const Bytes& kG1, ExternalSecurityAgent& esa,
    const Bytes& cyG, const CloudIdentity& cloud)
{
    std::deque<Frame> air;
    std::vector<std::pair<std::string, Bytes>> toCloud;     // IT packets, with the RSU that made them
    std::optional<Bytes> forwardingRequest;                 // as it went on air (replayed in 4l)
    const std::map<std::string, PacketManager*> rsus = { { rsu0.name(), &rsu0 }, { rsu1.name(), &rsu1 } };

    // node[0] again (the same seed as in 1: the same UUID and Auth_d), a new bootstrap
    BootstrapService::Config config;
    config.name = "node[0]";
    config.role = BootstrapService::Role::Vehicle;
    config.seed = 1;
    config.gatewayPublicKey = cyG;
    BootstrapService vehicle(config);
    BootstrapService::Transport vehicleLinks;
    vehicleLinks.radio = [&](const BootstrapMsg& msg) { air.push_back({ Link::Radio, serialize(msg) }); };
    vehicle.setTransport(vehicleLinks);

    // both RSUs hear the whole radio (logical unicast); their HTTPS sessions reach the ESA and each other
    for (const auto& [name, rsu] : rsus) {
        PacketManager::Transport links;
        links.radio = [&](const BootstrapMsg& msg) { air.push_back({ Link::Radio, serialize(msg) }); };
        links.https = [&](const BootstrapMsg& msg) { air.push_back({ Link::Https, serialize(msg) }); };
        links.cloud = [&toCloud, name = name](ItPacket packet) { toCloud.emplace_back(name, std::move(packet.bytes)); };
        rsu->setTransport(links);
    }
    esa.setTransport([&](const BootstrapMsg& msg) {
        if (msg.getType() != Active_03) { // Active_03: to the user, nobody here receives it
            air.push_back({ Link::Https, serialize(msg) });
        }
    });
    auto run = [&] {
        while (!air.empty()) {
            Frame frame = std::move(air.front());
            air.pop_front();
            const BootstrapMsg msg = deserialize(frame.bytes);
            if (frame.link == Link::Radio) {
                if (msg.getType() == Forwarding_Request) {
                    forwardingRequest = frame.bytes;
                }
                vehicle.indicate(msg);
                rsu0.onRadio(msg);
                rsu1.onRadio(msg);
            } else if (msg.getDestination() == esa.getFullName()) {
                esa.handleMessage(msg);
            } else if (auto rsu = rsus.find(msg.getDestination()); rsu != rsus.end()) {
                rsu->second->onHttps(msg);
            }
        }
    };

    bool ok = true;
    auto result = [&](const char* name, bool passed, const std::string& detail) {
        std::printf("  %-34s %s   %s\n", name, detail.c_str(), passed ? "ok" : "UNEXPECTED");
        std::fflush(stdout);
        ok &= passed;
        return passed;
    };
    // one SmartData of node[0] over the radio: "rsu" must marshal it, and the cloud open it to what was sent
    auto smartData = [&](const char* name, const std::string& rsu) {
        const size_t before = toCloud.size();
        const SmartData data = vehicle.sendSecureData(randomBytes(32), 4242, 1);
        run();
        const bool marshaled = toCloud.size() == before + 1 && toCloud.back().first == rsu;
        const auto opened = marshaled ? openAsCloud(cloud, toCloud.back().second) : std::nullopt;
        const bool same = opened && *opened == expectedJson(data);
        return result(name, same, !marshaled ? "NOT MARSHALED by " + rsu : !opened ? "the cloud CANNOT OPEN it"
            : !same ? "JSON DIFFERS from what node[0] sent"
            : "marshaled by " + rsu + ", the cloud's K_eg opens it to what node[0] sent");
    };

    std::optional<BootstrapResult> ready, handedOver;
    vehicle.setHandoverCallback([&](const BootstrapResult& r) { handedOver = r; });
    initBootstrap(vehicle, [&](const BootstrapResult& r) { ready = r; });
    run();
    if (result("4h. node[0] bootstraps with rsu[0]", ready && ready->rsu == rsu0.name()
        && vehicle.currentRsu() == rsu0.name(), ready ? "ready with " + ready->rsu : std::string("NOT READY"))) {
        smartData("4i. SmartData to rsu[0]", rsu0.name());

        rsu0.startHandover("node[0]", rsu1.name());
        run();
        const bool moved = handedOver && handedOver->rsu == rsu1.name() && vehicle.currentRsu() == rsu1.name();
        const bool keys = moved && vehicle.groupKey() == kG1 && kG1 != ready->kG && handedOver->kDg != ready->kDg;
        result("4j. Secrecy Forwarding to rsu[1]", keys, !handedOver ? "NO Forwarding_Granted accepted"
            : !moved ? "node[0] is NOT with rsu[1]" : !keys ? "node[0] does NOT hold rsu[1]'s K_g"
            : "node[0] with rsu[1]: holds its K_g, K_dh_i as K_dg");

        if (keys) {
            smartData("4k. SmartData to rsu[1]", rsu1.name());

            const int ignored = rsu1.ignored();
            const size_t onAir = air.size();
            if (forwardingRequest) {
                rsu1.onRadio(deserialize(*forwardingRequest));
            }
            const bool refused = forwardingRequest && rsu1.ignored() == ignored + 1 && air.size() == onAir;
            air.clear();
            result("4l. Forwarding_Request replayed", refused, refused ? "refused by rsu[1] (handover used)"
                : std::string("NOT REFUSED"));

            // as the vehicle had it before the handover: rsu[0]'s K_g and K_dg
            SmartData data;
            data.timing = static_cast<uint64_t>(SimTime::now().ns());
            data.value = randomBytes(32);
            data.authD = ready->authD;
            ok &= marshalCase(rsu1, cloud, "4m. rsu[0]'s keys at rsu[1]",
                packDataMessage(sealSmartData(data, ready->kG, ready->kDg, SimTime::now().ns())), GW_IGNORED);
        }
    }

    // the transports point at this function's locals
    rsu0.setTransport({});
    rsu1.setTransport({});
    esa.setTransport(nullptr);
    return ok;
}

void title(const char* text)
{
    std::printf("\n=== %s ===\n", text);
    std::fflush(stdout);
}

} // namespace

int runSelfTest(sgx_enclave_id_t eid, const std::string& enclavePath, const std::string& sealedPath)
{
    bool ok = true;
    bool marshaling = false;
    bool forwarding = false;
    Outcome normal, tampered, late, stranger, early;
    sgx_enclave_id_t eid1 = 0;
    try {
        ExternalSecurityAgent esa("esa");
        PacketManager gateway(eid, "rsu[0]");
        const CloudIdentity cloud = newCloudIdentity(kCloudAddress); // this test plays the cloud of 4

        // the HTTPS session with the ESA (main.cpp of the repository root): my certificate (CY_g) goes to the ESA,
        // CY_e comes in its Session_Ack
        const GatewayCertificate certificate = newGatewayCertificate(gateway.name());
        esa.registerRsu(gateway.name(), "gateway-session", certificate.publicKey);
        const Bytes& cyG = certificate.publicKey; // what the operator (here, the vehicle) names in Activation_Request
        const int init = gateway.initGateway(certificate.certificate, esa.publicKey());
        if (init != GW_OK) {
            throw std::runtime_error(std::string("ecall_init_gateway: ") + statusName(init));
        }
        const int session = gateway.initCloudSession(cloud.pem(), kCloudAddress);
        if (session != GW_OK) {
            throw std::runtime_error(std::string("ecall_init_cloud_session: ") + statusName(session));
        }

        title("1. normal bootstrap (node[0] with rsu[0])");
        normal = bootstrap("node[0]", 1, gateway, esa, cyG);

        title("2. OTP changed on the air (rejected by enclave)");
        tampered = bootstrap("node[1]", 7, gateway, esa, cyG, [](BootstrapMsg& msg) {
            if (msg.getType() == Auth_Request) {
                Bytes payload = getPayload(msg);
                payload[5] ^= 1; // one bit of OTP_dt
                setPayload(msg, payload);
            }
        });

        title("3. Auth_Request after t_f (aborted by enclave)");
        late = bootstrap("node[2]", 11, gateway, esa, cyG, [](BootstrapMsg& msg) {
            if (msg.getType() == Auth_Request) {
                std::this_thread::sleep_for(std::chrono::duration<double>(kActivationWindow + 0.1));
            }
        });

        title("4. Secrecy Forwarding handover (node[0]: rsu[0] -> rsu[1]) + Secure Marshaling (OT -> IT)");
        marshaling = secureMarshaling(gateway, cloud, normal.result);

        // rsu[1]: a second enclave from the same file, in this process (Option A: one enclave per RSU), with its
        // own sealed state (fresh every run) and its own K_g; the same cloud
        const sgx_status_t created = sgx_create_enclave(enclavePath.c_str(), SGX_DEBUG_FLAG, nullptr, nullptr, &eid1,
            nullptr);
        if (created != SGX_SUCCESS) {
            char text[128];
            std::snprintf(text, sizeof(text), "sgx_create_enclave (rsu[1]) failed: sgx_status_t 0x%04x",
                static_cast<unsigned>(created));
            throw std::runtime_error(text);
        }
        const std::string sealed1 = sealedPath + ".rsu1";
        std::remove(sealed1.c_str());
        setSealedStatePath(eid1, sealed1);
        std::printf("enclave %s created again for rsu[1] (eid %llu, sealed state %s)\n", enclavePath.c_str(),
            static_cast<unsigned long long>(eid1), sealed1.c_str());
        PacketManager target(eid1, "rsu[1]");
        const Bytes kG1 = randomBytes(kGroupKeySize);
        const int init1 = target.initGateway(newGatewayCertificate(target.name()).certificate, esa.publicKey(), kG1);
        const int session1 = target.initCloudSession(cloud.pem(), kCloudAddress);
        if (init1 != GW_OK || session1 != GW_OK) {
            throw std::runtime_error(std::string("rsu[1]: ") + statusName(init1) + ", " + statusName(session1));
        }
        forwarding = secrecyForwarding(gateway, target, kG1, esa, cyG, cloud);

        title("5. CY_g of no gateway (node[3])");
        stranger = bootstrap("node[3]", 13, gateway, esa, newGatewayCertificate("rogue").publicKey);

        title("6. before t_0: the window opens 2 s later (node[4])");
        early = bootstrap("node[4]", 17, gateway, esa, cyG, nullptr, 2.0);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        ok = false;
    }
    if (eid1 != 0) {
        sgx_destroy_enclave(eid1);
    }

    std::printf("\nresults:\n");
    ok &= report("1. normal", normal.vehicleReady && normal.protocolEnded && normal.ignored == 0, normal);
    ok &= report("2. OTP changed on the air", !tampered.vehicleReady && !tampered.protocolEnded
        && tampered.ignored == 1, tampered);
    ok &= report("3. Auth_Request after t_f", !late.vehicleReady && !late.protocolEnded && late.ignored == 1, late);
    std::printf("  %-34s Secure Marshaling (4a-4g): %s, Secrecy Forwarding (4h-4m): %s   %s\n",
        "4. handover rsu[0] -> rsu[1]", marshaling ? "ok" : "FAILED", forwarding ? "ok" : "FAILED",
        marshaling && forwarding ? "ok" : "UNEXPECTED");
    ok &= marshaling && forwarding;
    ok &= report("5. CY_g of no gateway", !stranger.vehicleReady && !stranger.protocolEnded, stranger);
    ok &= report("6. before t_0", !early.vehicleReady && !early.protocolEnded, early);

    std::printf("%s\n", ok ? "gateway OK" : "gateway FAILED");
    return ok ? 0 : 1;
}
