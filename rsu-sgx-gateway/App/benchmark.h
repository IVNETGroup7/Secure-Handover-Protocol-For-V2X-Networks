#ifndef GATEWAY_BENCHMARK_H_
#define GATEWAY_BENCHMARK_H_

// Turn-around times of the Secure Marshaling (tee.pdf step 6.3, Fig. 6 of the paper), per OT packet size:
//   ECALL          ecall_secure_marshal_ot_to_it alone (std::chrono::high_resolution_clock around it)
//   OT -> IT       from the OT queue to the IT queue: unpack, ECALL, push (the paper's "marshaling procedure":
//                  18.4 us for 32 B up to 4307.4 us for 64 KB - 1)
//   radio -> cloud from the whole packet received to the cloud's answer (the paper's complete turn-around:
//                  receive, marshal, HTTPS POST)

#include <chrono>
#include <cstdio>
#include <map>
#include <string>

class Benchmark
{
    public:
        using Duration = std::chrono::nanoseconds;

        void ecall(size_t size, Duration ecall, int status);
        void queued(size_t size, Duration otToIt);          // the IT packet went into the IT queue
        void posted(size_t size, Duration radioToCloud);    // the cloud answered 2xx
        void postFailed(size_t size);

        bool empty() const { return mRows.empty(); }
        void print(std::FILE* out, const std::string& node) const;

    private:
        struct Stat
        {
            size_t n = 0;
            double sum = 0;     // us
            double min = 0;
            double max = 0;
            void add(Duration d);
        };
        struct Row
        {
            Stat ecall, otToIt, radioToCloud;
            std::map<int, size_t> statuses;     // gateway.h status -> packets
            size_t postFailures = 0;
        };

        std::map<size_t, Row> mRows;    // OT packet size -> its times
};

#endif /* GATEWAY_BENCHMARK_H_ */
