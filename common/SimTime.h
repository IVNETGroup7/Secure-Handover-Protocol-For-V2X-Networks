#ifndef BOOTSTRAP_SIMTIME_H_
#define BOOTSTRAP_SIMTIME_H_

// Time used by the bootstrap protocols (replaces omnetpp::simtime_t): signed nanoseconds
// Compiled with -DWITH_OMNETPP (artery-sim/), now() is OMNeT++'s simulation time instead of the wall clock

#ifdef WITH_OMNETPP
#include <omnetpp/csimulation.h>
#endif
#include <chrono>
#include <cmath>
#include <cstdint>
#include <ostream>
#include <string>

class SimTime
{
    public:
        SimTime() = default;
        SimTime(double seconds) : mNs(std::llround(seconds * 1e9)) {}

        static SimTime fromNs(int64_t ns) { SimTime t; t.mNs = ns; return t; }

        // wall clock (CLOCK_REALTIME): the same in every process of the machine;
        // in an OMNeT++ simulation (WITH_OMNETPP), the simulation time: the same for every module
        static SimTime now()
        {
#ifdef WITH_OMNETPP
            return fromNs(omnetpp::simTime().inUnit(omnetpp::SIMTIME_NS));
#else
            using namespace std::chrono;
            return fromNs(duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count());
#endif
        }

        int64_t ns() const { return mNs; }
        double dbl() const { return mNs / 1e9; }

        // seconds, without trailing zeros (e.g. "1.5", "-0.003", "2")
        std::string str() const
        {
            const uint64_t abs = mNs < 0 ? -static_cast<uint64_t>(mNs) : static_cast<uint64_t>(mNs);
            std::string out = (mNs < 0 ? "-" : "") + std::to_string(abs / 1000000000);
            std::string frac = std::to_string(abs % 1000000000);
            frac.insert(0, 9 - frac.size(), '0');
            frac.erase(frac.find_last_not_of('0') + 1);
            return frac.empty() ? out : out + "." + frac;
        }

        SimTime& operator+=(const SimTime& o) { mNs += o.mNs; return *this; }
        SimTime& operator-=(const SimTime& o) { mNs -= o.mNs; return *this; }
        friend SimTime operator+(SimTime a, const SimTime& b) { return a += b; }
        friend SimTime operator-(SimTime a, const SimTime& b) { return a -= b; }
        friend SimTime operator/(const SimTime& a, int64_t d) { return fromNs(a.mNs / d); }

        friend bool operator==(const SimTime& a, const SimTime& b) { return a.mNs == b.mNs; }
        friend bool operator!=(const SimTime& a, const SimTime& b) { return a.mNs != b.mNs; }
        friend bool operator<(const SimTime& a, const SimTime& b) { return a.mNs < b.mNs; }
        friend bool operator<=(const SimTime& a, const SimTime& b) { return a.mNs <= b.mNs; }
        friend bool operator>(const SimTime& a, const SimTime& b) { return a.mNs > b.mNs; }
        friend bool operator>=(const SimTime& a, const SimTime& b) { return a.mNs >= b.mNs; }

        friend std::ostream& operator<<(std::ostream& os, const SimTime& t) { return os << t.str(); }

    private:
        int64_t mNs = 0;
};

using simtime_t = SimTime;

// current time of this process (wall clock, or the simulation time with WITH_OMNETPP); replaces OMNeT++'s simTime()
inline SimTime simTime()
{
    return SimTime::now();
}

#endif /* BOOTSTRAP_SIMTIME_H_ */
