// The wired and cellular core side of the scenario: the HTTPS sessions RSU <-> ESA and RSU <-> RSU, the ESA, the cloud,
// and the Simu5G 5G New Radio broker (BackhaulBroker.h)
simple BackhaulBroker
{
    parameters:
        @display("i=block/network2");
        @signal[cloudJsonBytes](type=long);
        @statistic[cloudJsonBytes](title="SmartData JSON the cloud opened"; unit=B; record=count,sum,vector);
        double latency @unit(s) = default(20ms);    // one way, per message (as the HTTPS channel of the bootstrap)
        string esaName = default("esa");             // the ESA's name: the destination the RSUs relay to

        // Simu5G 5G New Radio parameters
        double nr5gLatency @unit(s) = default(2ms);  // 5G NR Uu scheduling & transmission latency (30 kHz SCS numerology 1)
        double nrCellRadius @unit(m) = default(500m);// 5G NR gNodeB microcell coverage radius (3.5 GHz, 30 dBm EIRP)
        double gnb0X @unit(m) = default(250m);       // Position of gNodeB 0 (RSU 0) along highway
        double gnb1X @unit(m) = default(750m);       // Position of gNodeB 1 (RSU 1) along highway
}
