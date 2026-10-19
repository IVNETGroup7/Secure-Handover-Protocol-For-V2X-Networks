import artery.inet.World;

// 1 km highway along x (highway.net.xml), two RSUs with their SGX enclaves (rsu[0] at x = 250 m, rsu[1] at
// x = 750 m, omnetpp.ini) and the backhaul between them, the ESA and the cloud
network HighwayHandover extends World
{
    parameters:
        numRoadSideUnits = 2;

    submodules:
        backhaulBroker: BackhaulBroker {
            parameters:
                @display("p=140,20");
        }
}
