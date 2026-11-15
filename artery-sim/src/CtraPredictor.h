#ifndef TEE_V2X_CTRAPREDICTOR_H_
#define TEE_V2X_CTRAPREDICTOR_H_

// Constant Turn Rate and Acceleration (CTRA) trajectory predictor for vehicle-side proactive RSU selection and
// single-target Secrecy Forwarding token pre-fetching in a multi-RSU road network (e.g., Manhattan grid).
//
// State vector:
//   X = [x, y, v, psi, a, omega]^T
// where:
//   (x, y) : 2D Cartesian position (m, OMNeT++ frame)
//   v      : longitudinal speed (m/s)
//   psi    : heading angle in rad (dx/dt = v*cos(psi), dy/dt = v*sin(psi))
//   a      : longitudinal acceleration dv/dt (m/s^2)
//   omega  : yaw / turn rate d(psi)/dt (rad/s)
//
// CTRA transition over step dt (omega != 0):
//   v(t+dt)   = max(0, v + a*dt)
//   psi(t+dt) = psi + omega*dt
//   x(t+dt)   = x + (v(t+dt)*sin(psi(t+dt)) - v*sin(psi)) / omega
//                 + a*(cos(psi(t+dt)) - cos(psi)) / omega^2
//   y(t+dt)   = y + (-v(t+dt)*cos(psi(t+dt)) + v*cos(psi)) / omega
//                 + a*(sin(psi(t+dt)) - sin(psi)) / omega^2

#include <optional>
#include <string>
#include <vector>

class CtraPredictor
{
    public:
        struct RsuCandidate
        {
            std::string name;
            double x = 0.0;
            double y = 0.0;
        };

        struct State
        {
            double x = 0.0;
            double y = 0.0;
            double v = 0.0;
            double psi = 0.0;       // rad
            double a = 0.0;         // m/s^2
            double omega = 0.0;     // rad/s
            double timestamp = -1.0;
        };

        struct Prediction
        {
            std::string targetRsu;
            double minDistance = 0.0;
            double timeToClosest = 0.0;
            double predictedX = 0.0;
            double predictedY = 0.0;
            double currentDistance = 0.0;
        };

        void setCandidates(std::vector<RsuCandidate> candidates);
        const std::vector<RsuCandidate>& candidates() const { return mCandidates; }

        // Update vehicle kinematic state from VehicleDataProvider
        void update(double x, double y, double speed, double psiRad, double accel, double simTimeSec);

        const State& state() const { return mState; }
        bool ready() const { return mSamples >= 2; }

        // Single analytical CTRA integration step over dt seconds
        static State stepCtra(const State& s, double dt);

        // Roll out predicted CTRA trajectory over horizonSec with stepSec increments
        std::vector<State> rollout(double horizonSec, double stepSec) const;

        // Predict the single most likely next RSU to hand over to (excluding currentRsu)
        std::optional<Prediction> predictNextRsu(const std::string& currentRsu, double horizonSec,
            double stepSec, double predictRadius) const;

        // True when the vehicle has entered targetRsu's handover zone (time to send Forwarding_Request)
        bool shouldExecuteHandover(const std::string& currentRsu, const std::string& targetRsu,
            double handoverRadius) const;

        double distanceToRsu(const std::string& rsuName) const;

    private:
        const RsuCandidate* findRsu(const std::string& name) const;
        static double wrapAngle(double rad);

        std::vector<RsuCandidate> mCandidates;
        State mState{};
        double mTurnAnchorPsi = 0.0;
        int mSamples = 0;
};

#endif /* TEE_V2X_CTRAPREDICTOR_H_ */

