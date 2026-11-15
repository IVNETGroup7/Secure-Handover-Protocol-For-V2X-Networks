import artery.inet.World;

// 400 m x 400 m Manhattan Grid (highway.net.xml), 4 RSUs (one on each edge of the grid: West rsu[0], North rsu[1],
// East rsu[2], South rsu[3]), each with its own isolated Arm TrustZone OP-TEE TA session (rsu0.sealed .. rsu3.sealed),
// and the backhaul between them, the ESA and the cloud
network HighwayHandover extends World
{
    parameters:
        numRoadSideUnits = 4;

    submodules:
        backhaulBroker: BackhaulBroker {
            parameters:
                @display("p=200,200");
        }
}
