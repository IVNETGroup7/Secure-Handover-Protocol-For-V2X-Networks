// Self-test of the port (tee.pdf step 5): the bootstrap of a vehicle with the RSU running in the enclave.
// The vehicle and the ESA are the repository's own (protocol/BootstrapService, protocol/ExternalSecurityAgent),
// so the enclave must speak exactly their protocol; the network is in memory. Scenarios:
//   1. normal                        the vehicle gets ready, the ESA ends the protocol
//   2. OTP changed on the air        the enclave finds no matching Auth_d: ignored, nothing more
//   3. Auth_Request after t_f        the enclave aborts the session
//   4. Secure Marshaling             SmartData of the vehicle of 1 (tee.pdf step 4), with this test as the cloud:
//                                    the IT packet is HTTPS Header | AES(K_eg, JSON), with no JSON in clear, and
//                                    the cloud's K_eg opens it to exactly what the vehicle sent; a changed OTP_dt,
//                                    a changed AES(K_G, Data), an unknown Auth_d or an old t are refused; a new
//                                    K_eg every kMessagesPerSession packets

#include "modes.h"
#include "Bootstrap.h"
#include "BootstrapMsg.h"
#include "BootstrapPayload.h"
#include "BootstrapService.h"
#include "ExternalSecurityAgent.h"
#include "Https.h"
#include "SimTime.h"
#include "SmartData.h"
#include "Traits.h"
#include "gateway.h"
#include "packet_manager.h"
#include <chrono>
#include <cstdio>
#include <deque>
#include <exception>
#include <functional>
#include <optional>
#include <stdexcept>
#include <thread>

namespace
{

// the links of the in-memory network
enum class Link { Radio, ToEsa, ToRsu };

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

// one vehicle's bootstrap against the gateway; "onAir" may change (or delay) a frame before it is delivered
Outcome bootstrap(const std::string& vehicleName, unsigned seed, PacketManager& gateway, ExternalSecurityAgent& esa,
    const std::function<void(BootstrapMsg&)>& onAir = nullptr)
{
    std::deque<Frame> air;
    Outcome outcome;
    const int ignoredBefore = gateway.ignored();

    BootstrapService::Config config;
    config.name = vehicleName;
    config.role = BootstrapService::Role::Vehicle;
    config.seed = seed;
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

// what the cloud does with an IT packet (HTTPS Header | AES(K_eg, JSON)): K_eg from Y_s and its own X_c,
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

void title(const char* text)
{
    std::printf("\n=== %s ===\n", text);
    std::fflush(stdout);
}

} // namespace

int runSelfTest(sgx_enclave_id_t eid)
{
    bool ok = true;
    bool marshaling = false;
    Outcome normal, tampered, late;
    try {
        ExternalSecurityAgent esa("esa");
        PacketManager gateway(eid, "rsu[0]");
        const CloudIdentity cloud = newCloudIdentity(kCloudAddress); // this test plays the cloud of 4

        // the HTTPS session with the ESA: CY_e comes in its Session_Ack (main.cpp of the repository root)
        esa.registerRsu(gateway.name(), "gateway-session");
        const int init = gateway.initGateway({}, esa.publicKey());
        if (init != GW_OK) {
            throw std::runtime_error(std::string("ecall_init_gateway: ") + statusName(init));
        }
        const int session = gateway.initCloudSession(cloud.pem(), kCloudAddress);
        if (session != GW_OK) {
            throw std::runtime_error(std::string("ecall_init_cloud_session: ") + statusName(session));
        }

        title("1. normal bootstrap (node[0])");
        normal = bootstrap("node[0]", 1, gateway, esa);

        title("2. OTP changed on the air (node[1])");
        tampered = bootstrap("node[1]", 7, gateway, esa, [](BootstrapMsg& msg) {
            if (msg.getType() == Auth_Request) {
                Bytes payload = getPayload(msg);
                payload[5] ^= 1; // one bit of OTP_dt
                setPayload(msg, payload);
            }
        });

        title("3. Auth_Request after t_f (node[2])");
        late = bootstrap("node[2]", 11, gateway, esa, [](BootstrapMsg& msg) {
            if (msg.getType() == Auth_Request) {
                std::this_thread::sleep_for(std::chrono::duration<double>(kActivationWindow + 0.1));
            }
        });

        title("4. Secure Marshaling (SmartData of node[0])");
        marshaling = secureMarshaling(gateway, cloud, normal.result);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        ok = false;
    }

    std::printf("\nresults:\n");
    ok &= report("1. normal", normal.vehicleReady && normal.protocolEnded && normal.ignored == 0, normal);
    ok &= report("2. OTP changed on the air", !tampered.vehicleReady && !tampered.protocolEnded
        && tampered.ignored == 1, tampered);
    ok &= report("3. Auth_Request after t_f", !late.vehicleReady && !late.protocolEnded && late.ignored == 1, late);
    std::printf("  %-34s %s\n", "4. Secure Marshaling", marshaling ? "ok" : "UNEXPECTED");
    ok &= marshaling;

    std::printf("%s\n", ok ? "gateway OK" : "gateway FAILED");
    return ok ? 0 : 1;
}
