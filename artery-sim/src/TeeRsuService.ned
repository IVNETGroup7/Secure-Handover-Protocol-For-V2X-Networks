import inet.applications.contract.IApp;

// 5G NR Edge RSU Gateway with its secrets in an Arm TrustZone OP-TEE TA session of its own (TeeRsuService.h).
// Supports both host-simulated OP-TEE TAs (HOST_SIM) and Hardware-in-the-Loop (physical RPi3 / OP-TEE VM).
simple TeeRsuService like IApp
{
    parameters:
        @signal[marshalLatencyUs](type=double);
        @statistic[marshalLatencyUs](title="Secure Marshaling TA Invoke (wall clock)"; unit=us; record=vector,stats);
        @signal[handoverGranted](type=long);
        @statistic[handoverGranted](title="Forwarding_Granted sent"; record=count,vector);

        int localPort = default(2025);
        int vehiclePort = default(2025);
        string sealedStatePath = default("");       // "": <RSU name, no brackets>.sealed, e.g. rsu0.sealed
        bool freshState = default(true);            // drop the sealed state an earlier run left
        string groupKey = default("");              // K_g, 32 hex digits; "": generated inside the TA
        string backhaulModule = default("backhaulBroker");
        bool enableHil = default(false);            // Hardware-in-the-Loop: bridge this RSU to physical hardware
        string hilIface = default("");              // network interface connected to the physical RSU (or set HIL_IFACE env var)
        double hilHandshakeTimeout @unit(s) = default(60s); // max wait for physical RSU Session_Hello on startup

    gates:
        input socketIn;
        output socketOut;
}
