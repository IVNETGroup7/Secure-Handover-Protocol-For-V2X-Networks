// The wired side of the scenario: the HTTPS sessions RSU <-> ESA and RSU <-> RSU, the ESA, the cloud,
// and the academic V2X evaluation metrics collector + CSV exporter (BackhaulBroker.h)
simple BackhaulBroker
{
    parameters:
        @display("i=block/network2");
        @signal[cloudJsonBytes](type=long);
        @statistic[cloudJsonBytes](title="SmartData JSON the cloud opened"; unit=B; record=count,sum,vector);
        double latency @unit(s) = default(20ms);    // one way, per message (as the HTTPS channel of the bootstrap)
        string esaName = default("esa");            // the ESA's name: the destination the RSUs relay to
        string otpAlgo = default("");               // "ascon" (default) or "poly1305" (also via OTP_ALGO env var)
        string csvOutputPrefix = default("");       // "": <resultdir>/<configname>-<otp> (also via CSV_PREFIX env var)
        bool quietTrace = default(false);           // true: suppress verbose crypto hex dumps for focused HIL evaluation output
}
