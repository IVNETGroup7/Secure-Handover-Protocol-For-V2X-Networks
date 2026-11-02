#include "modes.h"
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <exception>
#include <map>
#include <stdexcept>
#include <string>

namespace
{

// the folder of this program: the sealed state fallback in host-sim mode lives next to it
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

#ifdef USE_OPTEE
    const std::string defaultStorage = "gateway.sealed";
#else
    const std::string defaultStorage = programDir() + "/gateway.sealed";
#endif
    const std::string storageId = option("--sealed", defaultStorage);
    const std::string label = mode == "rsu" ? option("--name", "rsu[0]") : "gateway";

    int code = 1;
    try {
        TeeSession tee(storageId, false);
        if (mode == "rsu") {
            RsuOptions rsu;
            rsu.iface = option("--iface", rsu.iface);
            rsu.name = option("--name", rsu.name);
            rsu.readyFd = std::stoi(option("--ready-fd", "-1"));
            rsu.cloudCertificate = option("--cloud-cert", "");
            rsu.cloudAddress = option("--cloud-address", rsu.cloudAddress);
            rsu.cloudPort = static_cast<uint16_t>(std::stoi(option("--cloud-port", std::to_string(rsu.cloudPort))));
            code = runRsuNode(tee, rsu);
        } else {
            std::printf("OP-TEE TA session opened (session %llu, storage %s)\n",
                static_cast<unsigned long long>(tee.sessionId()), storageId.c_str());
            code = runSelfTest(tee, storageId);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[%s] error: %s\n", label.c_str(), e.what());
        code = 1;
    }
    std::fflush(stdout);
    return code;
}

