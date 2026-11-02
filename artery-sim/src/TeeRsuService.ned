import artery.application.ItsG5Service;

// RSU with its secrets in an Arm TrustZone OP-TEE TA session of its own (TeeRsuService.h)
simple TeeRsuService like ItsG5Service
{
    parameters:
        @signal[marshalLatencyUs](type=double);
        @statistic[marshalLatencyUs](title="Secure Marshaling TA Invoke (wall clock)"; unit=us; record=vector,stats);
        @signal[handoverGranted](type=long);
        @statistic[handoverGranted](title="Forwarding_Granted sent"; record=count,vector);
        bool useSimu5g = default(false);            // true: 5G NR via Simu5G; false: IEEE 802.11p (ITS-G5)
        string sealedStatePath = default("");       // "": <RSU name, no brackets>.sealed, e.g. rsu0.sealed
        bool freshState = default(true);            // drop the sealed state an earlier run left
        string groupKey = default("");              // K_g, 32 hex digits; "": generated inside the TA
        string nextRsu = default("");               // Secrecy Forwarding: where the vehicles activated here go next
        double handoverDelay @unit(s) = default(0s);    // from the vehicle's activation to its Forwarding_Notice
        string backhaulModule = default("backhaulBroker");
}
