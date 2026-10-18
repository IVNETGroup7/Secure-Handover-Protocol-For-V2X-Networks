// RSU gateway, Non-Secure World: creates the enclave (Secure World) and talks to it only through the ECALLs
// of Enclave/Enclave.edl (via PacketManager).
//
//   ./app [selftest]       the bootstrap of the repository's vehicle and ESA against the enclave, in memory
//   ./app rsu [--iface lo] [--name rsu[0]] [--ready-fd <fd>]
//             [--cloud-cert <cloud.crt> [--cloud-address 127.0.0.1] [--cloud-port 8443]]
//                          the gateway as the RSU node on the raw sockets (needs CAP_NET_RAW);
//                          ../bootstrap --rsu-exec <this app> runs it in place of its own RSU;
//                          with --cloud-cert, the marshaled SmartData goes to the cloud (HTTPS)
//   common options: [--enclave <enclave.signed.so>] [--sealed <file>]   (default: next to this program)

#include "modes.h"
#include <sgx_urts.h>
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <exception>
#include <map>
#include <stdexcept>
#include <string>

namespace
{

// the folder of this program: the enclave and the sealed state live next to it, wherever it is run from
std::string programDir()
{
    char path[PATH_MAX];
    const ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n <= 0) {
        return ".";
    }
    const std::string self(path, static_cast<size_t>(n));
    return self.substr(0, self.rfind('/'));
}

} // namespace

int main(int argc, char** argv)
{
    const std::string mode = argc > 1 && argv[1][0] != '-' ? argv[1] : "selftest";
    const int first = argc > 1 && argv[1][0] != '-' ? 2 : 1;

    // --key value options
    std::map<std::string, std::string> options;
    for (int i = first; i < argc; ++i) {
        const std::string key = argv[i];
        if (key.rfind("--", 0) == 0 && i + 1 < argc) {
            options[key] = argv[++i];
        } else {
            std::fprintf(stderr, "error: unexpected argument '%s'\n", key.c_str());
            return 1;
        }
    }
    auto option = [&](const std::string& key, const std::string& fallback) {
        auto value = options.find(key);
        return value != options.end() ? value->second : fallback;
    };
    if (mode != "selftest" && mode != "rsu") {
        std::fprintf(stderr, "error: unknown mode '%s' (selftest or rsu)\n", mode.c_str());
        return 1;
    }

    const std::string dir = programDir();
    const std::string enclavePath = option("--enclave", dir + "/enclave.signed.so");
    setSealedStatePath(option("--sealed", dir + "/gateway.sealed"));
    const std::string label = mode == "rsu" ? option("--name", "rsu[0]") : "gateway";

    sgx_enclave_id_t eid = 0;
    const sgx_status_t created = sgx_create_enclave(enclavePath.c_str(), SGX_DEBUG_FLAG, nullptr, nullptr, &eid,
        nullptr);
    if (created != SGX_SUCCESS) {
        std::fprintf(stderr, "[%s] error: sgx_create_enclave(%s) failed: sgx_status_t 0x%04x\n", label.c_str(),
            enclavePath.c_str(), static_cast<unsigned>(created));
        return 1;
    }

    int code = 1;
    try {
        if (mode == "rsu") {
            RsuOptions rsu;
            rsu.iface = option("--iface", rsu.iface);
            rsu.name = option("--name", rsu.name);
            rsu.readyFd = std::stoi(option("--ready-fd", "-1"));
            rsu.cloudCertificate = option("--cloud-cert", "");
            rsu.cloudAddress = option("--cloud-address", rsu.cloudAddress);
            rsu.cloudPort = static_cast<uint16_t>(std::stoi(option("--cloud-port", std::to_string(rsu.cloudPort))));
            code = runRsuNode(eid, rsu);
        } else {
            std::printf("enclave %s created (eid %llu)\n", enclavePath.c_str(), static_cast<unsigned long long>(eid));
            code = runSelfTest(eid);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[%s] error: %s\n", label.c_str(), e.what());
        code = 1;
    }
    std::fflush(stdout);
    sgx_destroy_enclave(eid);
    return code;
}
