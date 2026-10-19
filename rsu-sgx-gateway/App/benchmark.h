#ifndef GATEWAY_BENCHMARK_H_
#define GATEWAY_BENCHMARK_H_

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
