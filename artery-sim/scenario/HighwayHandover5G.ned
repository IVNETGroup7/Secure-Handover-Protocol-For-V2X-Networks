import simu5g.common.binder.Binder;
import simu5g.common.carrierAggregation.CarrierAggregation;
import simu5g.nodes.NR.gNodeB;
import simu5g.nodes.Upf;
import inet.node.ethernet.Eth10G;

// 1 km highway along x with 5G New Radio (NR) via Simu5G:
// Extends HighwayHandover with two 5G gNodeBs (gnb[0] at x=250m, gnb[1] at x=750m),
// 5G Core User Plane Function (UPF), CarrierAggregation, and the global Binder registry.
// Vehicles connect to the gNodeBs via 5G NR Uu interface, with X2-based handover at x=500m.
network HighwayHandover5G extends HighwayHandover
{
    submodules:
        binder: Binder {
            parameters:
                @display("p=50,20");
        }
        carrierAggregation: CarrierAggregation {
            parameters:
                @display("p=50,70");
        }
        gnb[2]: gNodeB {
            parameters:
                @display("p=250,50;p=750,50");
        }
        upf: Upf {
            parameters:
                @display("p=500,20");
        }

    connections allowunconnected:
        gnb[0].x2++ <--> Eth10G <--> gnb[1].x2++;
        gnb[0].ppp++ <--> Eth10G <--> upf.pppg++;
        gnb[1].ppp++ <--> Eth10G <--> upf.pppg++;
}

