import artery.application.ItsG5Service;

// Vehicle: bootstrap, Secure_Data at 10 Hz, Secrecy Forwarding to the next RSU (VehicleTeeService.h)
simple VehicleTeeService like ItsG5Service
{
    parameters:
        @signal[bootstrapDelay](type=simtime_t);
        @statistic[bootstrapDelay](title="Activation_Request -> vehicle ready"; unit=s; record=last,vector);
        @signal[handoverE2EDelayMs](type=double);
        @statistic[handoverE2EDelayMs](title="Forwarding_Request -> Forwarding_Granted accepted"; unit=ms; record=last,vector,stats);
        @signal[secureDataSent](type=long);
        @statistic[secureDataSent](title="Secure_Data sent"; record=last,vector);
        string firstRsu = default("rsu[0]");        // the RSU of the bootstrap (its CY_g in the Activation_Request)
        double startDelay @unit(s) = default(0.5s); // entering the road -> Activation_Request
        double dataInterval @unit(s) = default(100ms);  // Secure_Data period (10 Hz, as CAMs)
        int dataSize @unit(B) = default(200B);      // SmartData value per Secure_Data
        double handoverX @unit(m) = default(500m);  // x where the Forwarding_Request goes; < 0: on Handover_Command
        double clockOffset @unit(s) = default(0s);  // initial error of the vehicle clock (PTP corrects it)
        string backhaulModule = default("backhaulBroker");
}
