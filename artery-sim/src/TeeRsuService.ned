import artery.application.ItsG5Service;

// RSU with its secrets in an Intel SGX enclave of its own (TeeRsuService.h)
simple TeeRsuService like ItsG5Service
{
    parameters:
        @signal[marshalLatencyUs](type=double);
        @statistic[marshalLatencyUs](title="Secure Marshaling ECALL (wall clock)"; unit=us; record=vector,stats);
        @signal[handoverGranted](type=long);
        @statistic[handoverGranted](title="Forwarding_Granted sent"; record=count,vector);
        string enclavePath = default("../../rsu-sgx-gateway/enclave.signed.so");   // from the working directory
        string sealedStatePath = default("");       // "": <RSU name, no brackets>.sealed, e.g. rsu0.sealed
        bool freshState = default(true);            // drop the sealed state an earlier run left
        string groupKey = default("");              // K_g, 32 hex digits; "": generated inside the enclave
        string nextRsu = default("");               // Secrecy Forwarding: where the vehicles activated here go next
        double handoverDelay @unit(s) = default(0s);    // from the vehicle's activation to its Forwarding_Notice
        string backhaulModule = default("backhaulBroker");
}
