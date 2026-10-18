#include "benchmark.h"
#include "packet_manager.h"

void Benchmark::Stat::add(Duration d)
{
    const double us = std::chrono::duration<double, std::micro>(d).count();
    min = n == 0 || us < min ? us : min;
    max = n == 0 || us > max ? us : max;
    sum += us;
    ++n;
}

void Benchmark::ecall(size_t size, Duration ecall, int status)
{
    Row& row = mRows[size];
    row.ecall.add(ecall);
    ++row.statuses[status];
}

void Benchmark::queued(size_t size, Duration otToIt)
{
    mRows[size].otToIt.add(otToIt);
}

void Benchmark::posted(size_t size, Duration radioToCloud)
{
    mRows[size].radioToCloud.add(radioToCloud);
}

void Benchmark::postFailed(size_t size)
{
    ++mRows[size].postFailures;
}

void Benchmark::print(std::FILE* out, const std::string& node) const
{
    auto cell = [](const Stat& stat) {
        char text[48];
        if (stat.n == 0) {
            return std::string("-");
        }
        std::snprintf(text, sizeof(text), "%.1f (%.1f-%.1f)", stat.sum / stat.n, stat.min, stat.max);
        return std::string(text);
    };

    std::fprintf(out, "[%s] Secure Marshaling turn-around, us: average (min-max) per OT packet size\n", node.c_str());
    std::fprintf(out, "  %8s %7s  %-24s %-24s %-24s %s\n", "OT B", "packets", "ECALL", "OT -> IT queue",
        "radio -> cloud", "enclave status");
    for (const auto& [size, row] : mRows) {
        std::string statuses;
        for (const auto& [status, n] : row.statuses) {
            statuses += (statuses.empty() ? "" : ", ") + std::string(statusName(status)) + " x" + std::to_string(n);
        }
        if (row.postFailures > 0) {
            statuses += ", POST failed x" + std::to_string(row.postFailures);
        }
        std::fprintf(out, "  %8zu %7zu  %-24s %-24s %-24s %s\n", size, row.ecall.n, cell(row.ecall).c_str(),
            cell(row.otToIt).c_str(), cell(row.radioToCloud).c_str(), statuses.c_str());
    }
    std::fflush(out);
}
