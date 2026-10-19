// The wired side of the scenario: the HTTPS sessions RSU <-> ESA and RSU <-> RSU, the ESA and the cloud
// (BackhaulBroker.h)
simple BackhaulBroker
{
    parameters:
        @display("i=block/network2");
        @signal[cloudJsonBytes](type=long);
        @statistic[cloudJsonBytes](title="SmartData JSON the cloud opened"; unit=B; record=count,sum,vector);
        double latency @unit(s) = default(20ms);    // one way, per message (as the HTTPS channel of the bootstrap)
        string esaName = default("esa");             // the ESA's name: the destination the RSUs relay to
}
