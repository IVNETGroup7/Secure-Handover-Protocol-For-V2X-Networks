import inet.applications.contract.IApp;

// Vehicle (5G NR UE + Artery VehicleMiddleware): bootstrap, Secure_Data at 10 Hz,
// purely kinematic CTRA trajectory prediction & Secrecy Forwarding over 5G NR UDP/IP (VehicleTeeService.h)
simple VehicleTeeService like IApp
{
    parameters:
        @signal[bootstrapDelay](type=simtime_t);
        @statistic[bootstrapDelay](title="Activation_Request -> vehicle ready"; unit=s; record=last,vector);
        @signal[handoverE2EDelayMs](type=double);
        @statistic[handoverE2EDelayMs](title="Forwarding_Request -> Forwarding_Granted accepted"; unit=ms; record=last,vector,stats);
        @signal[prefetchLeadTimeMs](type=double);
        @statistic[prefetchLeadTimeMs](title="CTRA pre-fetch -> Forwarding_Request sent"; unit=ms; record=last,vector,stats);
        @signal[ctraPredictions](type=long);
        @statistic[ctraPredictions](title="CTRA Handover_Predict sent"; record=last,vector);
        @signal[secureDataSent](type=long);
        @statistic[secureDataSent](title="Secure_Data sent"; record=last,vector);
        @signal[nrServingCellId](type=long);
        @statistic[nrServingCellId](title="5G NR Serving gNodeB MacNodeId"; record=last,vector);
        @signal[nrRadioHandovers](type=long);
        @statistic[nrRadioHandovers](title="5G NR Radio gNodeB Handovers"; record=last,vector);

        int localPort = default(2025);
        int destPort = default(2025);
        string firstRsu = default("rsu[0]");            // the RSU of the bootstrap (its CY_g in the Activation_Request)
        double startDelay @unit(s) = default(0.5s);     // entering the road -> Activation_Request
        double bootstrapTimeout @unit(s) = default(6s); // max wait for bootstrap completion before failing simulation
        double dataInterval @unit(s) = default(100ms);  // Secure_Data period (10 Hz, as CAMs)
        int dataSize @unit(B) = default(200B);          // SmartData value per Secure_Data
        bool enableCtra = default(true);                // CTRA trajectory predictor selects single target RSU & pre-fetches
        double predictionHorizon @unit(s) = default(8.0s);  // CTRA lookahead horizon
        double predictionStep @unit(s) = default(0.1s);     // CTRA integration step
        double predictRadius @unit(m) = default(80m);       // max trajectory-to-RSU distance to trigger pre-fetch
        double handoverRadius @unit(m) = default(160m);     // distance to pre-fetched RSU to execute Forwarding_Request
        double clockOffset @unit(s) = default(0s);      // initial error of the vehicle clock (PTP corrects it)
        string backhaulModule = default("backhaulBroker");
        string middlewareModule = default("^.middleware");

    gates:
        input socketIn;
        output socketOut;
}
