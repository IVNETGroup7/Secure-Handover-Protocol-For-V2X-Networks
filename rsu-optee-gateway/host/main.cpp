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
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            std::printf("Usage:\n"
                "  %s [selftest] [--otp ascon|poly1305] [--sealed <id>] [--fresh]\n"
                "  %s rsu [--otp ascon|poly1305] [--name <rsu>] [--iface <nic>] [--sealed <id>] [--fresh] [--session-timeout <sec>]\n",
                argv[0], argv[0]);
            return 0;
        }
    }

    const std::string mode = argc > 1 && argv[1][0] != '-' ? argv[1] : "selftest";
    const int first = argc > 1 && argv[1][0] != '-' ? 2 : 1;

    // --key value options (plus optional valueless --fresh)
    std::map<std::string, std::string> options;
    for (int i = first; i < argc; ++i) {
        const std::string key = argv[i];
        if (key == "--fresh" && (i + 1 >= argc || argv[i + 1][0] == '-')) {
            options[key] = "1";
        } else if (key.rfind("--", 0) == 0 && i + 1 < argc) {
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
    const bool freshState = option("--fresh", "0") == "1" || option("--fresh", "") == "true";
    const std::string label = mode == "rsu" ? option("--name", "rsu[0]") : "gateway";

    std::optional<OtpAlgo> requestedOtp;
    if (const auto it = options.find("--otp"); it != options.end()) {
        requestedOtp = parseOtpAlgo(it->second);
        if (!requestedOtp) {
            std::fprintf(stderr, "error: invalid --otp '%s' (expected 'ascon' or 'poly1305')\n",
                it->second.c_str());
            return 1;
        }
        setOtpAlgorithm(*requestedOtp);
    } else {
        setOtpAlgorithm(OtpAlgo::Ascon);
    }

    int code = 1;
    try {
        TeeSession tee(storageId, freshState, otpAlgorithm());
        if (mode == "rsu") {
            RsuOptions rsu;
            rsu.iface = option("--iface", rsu.iface);
            rsu.name = option("--name", rsu.name);
            rsu.sessionTimeoutSeconds = static_cast<unsigned>(
                std::stoul(option("--session-timeout", std::to_string(rsu.sessionTimeoutSeconds))));
            rsu.otpAlgo = requestedOtp;
            code = runRsuNode(tee, rsu);
        } else {
            std::printf("OP-TEE TA session opened (session %llu, storage %s, otp %s)\n",
                static_cast<unsigned long long>(tee.sessionId()), storageId.c_str(),
                otpAlgoName(otpAlgorithm()));
            code = runSelfTest(tee, storageId);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[%s] error: %s\n", label.c_str(), e.what());
        code = 1;
    }
    std::fflush(stdout);
    return code;
}

