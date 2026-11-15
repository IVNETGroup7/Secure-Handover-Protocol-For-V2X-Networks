import artery.application.ItsG5Service;

// Vehicle: bootstrap, Secure_Data at 10 Hz, CTRA trajectory prediction & Secrecy Forwarding (VehicleTeeService.h)
simple VehicleTeeService like ItsG5Service
{
    parameters:
        @signal[bootstrapDelay](type=simtime_t);
        @statistic[bootstrapDelay](title="Activation_Request -> vehicle ready"; unit=s; record=last,vector);
        @signal[handoverE2EDelayMs](type=double);
        @statistic[handoverE2EDelayMs](title="Forwarding_Request -> Forwarding_Granted accepted"; unit=ms; record=last,vector,stats);
        @signal[prefetchLeadTimeMs](type=double);
        @statistic[prefetchLeadTimeMs](title="Handover_Command pre-fetched -> Forwarding_Request sent"; unit=ms; record=last,vector,stats);
        @signal[ctraPredictions](type=long);
        @statistic[ctraPredictions](title="CTRA Handover_Predict sent"; record=last,vector);
        @signal[secureDataSent](type=long);
        @statistic[secureDataSent](title="Secure_Data sent"; record=last,vector);
        string firstRsu = default("rsu[0]");            // the RSU of the bootstrap (its CY_g in the Activation_Request)
        double startDelay @unit(s) = default(0.5s);     // entering the road -> Activation_Request
        double dataInterval @unit(s) = default(100ms);  // Secure_Data period (10 Hz, as CAMs)
        int dataSize @unit(B) = default(200B);          // SmartData value per Secure_Data
        bool enableCtra = default(true);                // CTRA trajectory predictor selects single target RSU & pre-fetches
        double predictionHorizon @unit(s) = default(8.0s);  // CTRA lookahead horizon
        double predictionStep @unit(s) = default(0.1s);     // CTRA integration step
        double predictRadius @unit(m) = default(80m);       // max trajectory-to-RSU distance to trigger pre-fetch
        double handoverRadius @unit(m) = default(160m);     // distance to pre-fetched RSU to execute Forwarding_Request
        double handoverX @unit(m) = default(-1m);       // fallback x threshold when enableCtra = false
        double clockOffset @unit(s) = default(0s);      // initial error of the vehicle clock (PTP corrects it)
        string backhaulModule = default("backhaulBroker");
}
