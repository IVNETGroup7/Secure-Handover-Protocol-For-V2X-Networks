import artery.utility.IdentityRegistry;
import crownet.common.ICoordConverter;
import crownet.nodes.ApplicationLayerVehicle;
import inet.environment.common.PhysicalEnvironment;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.networklayer.ipv4.RoutingTableRecorder;
import inet.node.ethernet.Eth10G;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import simu5g.common.binder.Binder;
import simu5g.common.carrierAggregation.CarrierAggregation;
import simu5g.nodes.Upf;
import simu5g.nodes.gNodeB;
import simu5g.world.radio.LteChannelControl;
import traci.TraCiManager;

// 400 m x 400 m Manhattan Grid (highway.net.xml) coupled via CrowNet (OMNeT++ 6.3 + INET 4 + Artery + Simu5G):
//   - 4 5G NR gNodeBs (gNB[0..3]) with full-mesh X2/Xn links on the 4 edges of the Manhattan Grid
//   - 5G Core UPF + Edge Router + 4 co-located OP-TEE RSU Gateways (rsu[0..3], each with its own TrustZone TA session)
//   - Dynamically spawned SUMO vehicles (ApplicationLayerVehicle: Simu5G NrNicUe + Artery VehicleMiddleware)
//   - BackhaulBroker hosting Root CA, Human Operator, ESA, Cloud sink, and RSU <-> ESA / RSU <-> RSU HTTPS sessions
network HighwayHandover
{
    parameters:
        @display("bgb=450,450;bgu=m");
        int numGnb = default(4);
        int numRoadSideUnits = default(4);

    submodules:
        coordConverter: <default("OsgCoordConverterLocal")> like ICoordConverter if typename != "" {
            @display("p=420,40;is=s");
        }
        physicalEnvironment: PhysicalEnvironment {
            @display("p=420,90;is=s");
        }
        routingRecorder: RoutingTableRecorder {
            @display("p=420,140;is=s");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=420,190;is=s");
            config = xmldoc("demo.xml");
        }
        channelControl: LteChannelControl {
            @display("p=420,240;is=s");
        }
        binder: Binder {
            @display("p=420,290;is=s");
        }
        carrierAggregation: CarrierAggregation {
            @display("p=420,340;is=s");
        }
        traci: <default("traci.Manager")> like TraCiManager {
            @display("p=420,390;is=s");
        }
        identityRegistry: IdentityRegistry {
            @display("p=370,40;is=s");
        }
        backhaulBroker: BackhaulBroker {
            @display("p=200,200;i=block/network2");
        }
        router: Router {
            @display("p=200,150;i=device/smallrouter");
        }
        upf: Upf {
            @display("p=200,250");
        }
        gNB[numGnb]: gNodeB {
            @display("is=l");
        }
        rsu[numRoadSideUnits]: StandardHost {
            @display("i=device/accesspoint");
        }

    connections allowunconnected:
        router.pppg++ <--> Eth10G <--> upf.filterGate;

        for i=0..numRoadSideUnits-1 {
            rsu[i].pppg++ <--> Eth10G <--> router.pppg++;
        }

        for i=0..numGnb-1 {
            upf.pppg++ <--> Eth10G <--> gNB[i].ppp;
        }

        // Full-mesh X2/Xn links between all 4 gNodeBs for 5G NR cellular handover
        for i=0..numGnb-1, for j=0..numGnb-1 {
            gNB[i].x2++ <--> Eth10G <--> gNB[j].x2++ if i < j;
        }
}
