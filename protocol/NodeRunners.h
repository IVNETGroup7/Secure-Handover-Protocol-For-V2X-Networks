#ifndef PROTOCOL_NODERUNNERS_H_
#define PROTOCOL_NODERUNNERS_H_

#include <csignal>
#include <map>
#include <string>
#include <stdexcept>

extern volatile std::sig_atomic_t gStop;

// Command line key-value options parser (--key value)
class Options
{
    public:
        Options(int argc, char** argv, int first)
        {
            for (int i = first; i < argc; ++i) {
                const std::string key = argv[i];
                if (key.rfind("--", 0) != 0) {
                    throw std::runtime_error("unexpected argument '" + key + "'");
                }
                if (i + 1 >= argc) {
                    throw std::runtime_error("missing value for " + key);
                }
                mValues[key] = argv[++i];
            }
        }

        std::string get(const std::string& key, const std::string& fallback) const
        {
            auto value = mValues.find(key);
            return value != mValues.end() ? value->second : fallback;
        }

    private:
        std::map<std::string, std::string> mValues;
};

void signalReady(const Options& options);
int runEsa(const Options& options);
int runRsu(const Options& options);
int runVehicle(const Options& options);
int runCloud(const Options& options);
int runNode(const std::string& role, const Options& options);
int runHandoverTest();
int runFullNetworkHandoverTest();

#endif /* PROTOCOL_NODERUNNERS_H_ */
