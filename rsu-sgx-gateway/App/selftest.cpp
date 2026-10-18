// Self-test of the port (tee.pdf step 5): the bootstrap of a vehicle with the RSU running in the enclave.
// The vehicle and the ESA are the repository's own (protocol/BootstrapService, protocol/ExternalSecurityAgent),
// so the enclave must speak exactly their protocol; the network is in memory. Scenarios:
//   1. normal                        the vehicle gets ready, the ESA ends the protocol
//   2. OTP changed on the air        the enclave finds no matching Auth_d: ignored, nothing more
//   3. Auth_Request after t_f        the enclave aborts the session

#include "modes.h"
#include "Bootstrap.h"
#include "BootstrapMsg.h"
#include "BootstrapPayload.h"
#include "BootstrapService.h"
#include "ExternalSecurityAgent.h"
#include "Traits.h"
#include "gateway.h"
#include "packet_manager.h"
#include <chrono>
#include <cstdio>
#include <deque>
#include <exception>
#include <functional>
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

    initBootstrap(vehicle, [&](const BootstrapResult&) { outcome.vehicleReady = true; });
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

void title(const char* text)
{
    std::printf("\n=== %s ===\n", text);
    std::fflush(stdout);
}

} // namespace

int runSelfTest(sgx_enclave_id_t eid)
{
    bool ok = true;
    Outcome normal, tampered, late;
    try {
        ExternalSecurityAgent esa("esa");
        PacketManager gateway(eid, "rsu[0]");

        // the HTTPS session with the ESA: CY_e comes in its Session_Ack (main.cpp of the repository root)
        esa.registerRsu(gateway.name(), "gateway-session");
        const int init = gateway.initGateway({}, esa.publicKey());
        if (init != GW_OK) {
            throw std::runtime_error(std::string("ecall_init_gateway: ") + statusName(init));
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
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        ok = false;
    }

    std::printf("\nresults:\n");
    ok &= report("1. normal", normal.vehicleReady && normal.protocolEnded && normal.ignored == 0, normal);
    ok &= report("2. OTP changed on the air", !tampered.vehicleReady && !tampered.protocolEnded
        && tampered.ignored == 1, tampered);
    ok &= report("3. Auth_Request after t_f", !late.vehicleReady && !late.protocolEnded && late.ignored == 1, late);

    std::printf("%s\n", ok ? "gateway OK" : "gateway FAILED");
    return ok ? 0 : 1;
}
