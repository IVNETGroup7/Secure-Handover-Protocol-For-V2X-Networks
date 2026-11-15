#include "CtraPredictor.h"
#include <algorithm>
#include <cmath>
#include <limits>

namespace
{

constexpr double kPi = 3.14159265358979323846;
constexpr double kOmegaEps = 1e-4;          // rad/s threshold between curved and straight CTRA equations
constexpr double kTurnActiveOmega = 0.05;   // rad/s threshold indicating an active junction turn
constexpr double kMaxTurnExcursion = kPi / 2.0; // max 90 deg turn per intersection in a Manhattan grid
constexpr double kMaxSpeed = 35.0;          // m/s cap during lookahead rollout

double euclidean(double x1, double y1, double x2, double y2)
{
    return std::hypot(x1 - x2, y1 - y2);
}

} // namespace

double CtraPredictor::wrapAngle(double rad)
{
    while (rad > kPi) {
        rad -= 2.0 * kPi;
    }
    while (rad <= -kPi) {
        rad += 2.0 * kPi;
    }
    return rad;
}

void CtraPredictor::setCandidates(std::vector<RsuCandidate> candidates)
{
    mCandidates = std::move(candidates);
}

const CtraPredictor::RsuCandidate* CtraPredictor::findRsu(const std::string& name) const
{
    for (const auto& c : mCandidates) {
        if (c.name == name) {
            return &c;
        }
    }
    return nullptr;
}

double CtraPredictor::distanceToRsu(const std::string& rsuName) const
{
    const auto* rsu = findRsu(rsuName);
    if (!rsu) {
        return std::numeric_limits<double>::infinity();
    }
    return euclidean(mState.x, mState.y, rsu->x, rsu->y);
}

void CtraPredictor::update(double x, double y, double speed, double psiRad, double accel, double simTimeSec)
{
    const double psi = wrapAngle(psiRad);
    if (mSamples == 0 || simTimeSec <= mState.timestamp) {
        mState.x = x;
        mState.y = y;
        mState.v = std::max(0.0, speed);
        mState.psi = psi;
        mState.a = std::isnan(accel) ? 0.0 : std::clamp(accel, -8.0, 5.0);
        mState.omega = 0.0;
        mState.timestamp = simTimeSec;
        mTurnAnchorPsi = psi;
        mSamples = 1;
        return;
    }

    const double dt = simTimeSec - mState.timestamp;
    const double dPsi = wrapAngle(psi - mState.psi);
    const double rawOmega = dPsi / dt;
    const double rawAccel = std::isnan(accel) ? ((speed - mState.v) / dt) : accel;

    mState.x = x;
    mState.y = y;
    mState.v = std::max(0.0, speed);
    mState.psi = psi;
    mState.a = std::clamp(rawAccel, -8.0, 5.0);
    mState.omega = std::clamp(rawOmega, -2.5, 2.5);
    mState.timestamp = simTimeSec;
    ++mSamples;

    if (std::abs(mState.omega) < kTurnActiveOmega) {
        mTurnAnchorPsi = psi;
    }
}

CtraPredictor::State CtraPredictor::stepCtra(const State& s, double dt)
{
    State next = s;
    if (dt <= 0.0) {
        return next;
    }

    const double v0 = std::max(0.0, s.v);
    const double v1 = std::clamp(v0 + s.a * dt, 0.0, kMaxSpeed);
    const double effDt = (s.a < 0.0 && v0 + s.a * dt < 0.0) ? (-v0 / s.a) : dt;
    const double a = (effDt < dt) ? 0.0 : s.a;
    const double psi0 = s.psi;
    const double omega = s.omega;
    const double psi1 = wrapAngle(psi0 + omega * effDt);

    if (std::abs(omega) > kOmegaEps) {
        const double invW = 1.0 / omega;
        const double invW2 = invW * invW;
        next.x = s.x + (v1 * std::sin(psi1) - v0 * std::sin(psi0)) * invW
                     + a * (std::cos(psi1) - std::cos(psi0)) * invW2;
        next.y = s.y + (-v1 * std::cos(psi1) + v0 * std::cos(psi0)) * invW
                     + a * (std::sin(psi1) - std::sin(psi0)) * invW2;
    } else {
        const double dist = v0 * effDt + 0.5 * a * effDt * effDt;
        next.x = s.x + dist * std::cos(psi0);
        next.y = s.y + dist * std::sin(psi0);
    }

    next.v = v1;
    next.psi = psi1;
    next.timestamp = s.timestamp + dt;
    return next;
}

std::vector<CtraPredictor::State> CtraPredictor::rollout(double horizonSec, double stepSec) const
{
    std::vector<State> trajectory;
    if (horizonSec <= 0.0 || stepSec <= 0.0) {
        return trajectory;
    }

    const int steps = std::max(1, static_cast<int>(std::ceil(horizonSec / stepSec)));
    trajectory.reserve(static_cast<size_t>(steps));

    State cur = mState;
    for (int i = 0; i < steps; ++i) {
        // Cap cumulative turn excursion to 90 deg (kMaxTurnExcursion) per intersection turn
        if (std::abs(cur.omega) >= kTurnActiveOmega) {
            const double turned = std::abs(wrapAngle(cur.psi + cur.omega * stepSec - mTurnAnchorPsi));
            if (turned >= kMaxTurnExcursion) {
                const double sign = cur.omega >= 0.0 ? 1.0 : -1.0;
                cur.psi = wrapAngle(mTurnAnchorPsi + sign * kMaxTurnExcursion);
                cur.omega = 0.0;
            }
        }
        cur = stepCtra(cur, stepSec);
        trajectory.push_back(cur);
    }
    return trajectory;
}

std::optional<CtraPredictor::Prediction> CtraPredictor::predictNextRsu(const std::string& currentRsu,
    double horizonSec, double stepSec, double predictRadius) const
{
    if (!ready() || mCandidates.size() < 2 || mState.v < 0.5) {
        return std::nullopt;
    }

    const RsuCandidate* curr = findRsu(currentRsu);
    const std::vector<State> traj = rollout(horizonSec, stepSec);
    if (traj.empty()) {
        return std::nullopt;
    }

    std::optional<Prediction> best;
    int bestDwell = 0;

    for (const auto& candidate : mCandidates) {
        if (candidate.name == currentRsu) {
            continue;
        }

        const double d0 = euclidean(mState.x, mState.y, candidate.x, candidate.y);
        double minDist = std::numeric_limits<double>::infinity();
        double minTime = 0.0;
        double minX = mState.x;
        double minY = mState.y;
        int dwellInZone = 0;

        for (size_t i = 0; i < traj.size(); ++i) {
            const State& pt = traj[i];
            const double dCand = euclidean(pt.x, pt.y, candidate.x, candidate.y);
            const double dCurr = curr ? euclidean(pt.x, pt.y, curr->x, curr->y)
                                      : std::numeric_limits<double>::infinity();

            if (dCand < minDist) {
                minDist = dCand;
                minTime = static_cast<double>(i + 1) * stepSec;
                minX = pt.x;
                minY = pt.y;
            }
            if (dCand <= predictRadius && dCand < dCurr) {
                ++dwellInZone;
            }
        }

        // Select candidate only if the CTRA trajectory genuinely approaches it and enters its prediction zone
        if (dwellInZone > 0 && minDist <= predictRadius && minDist < d0 - 5.0) {
            if (!best || dwellInZone > bestDwell || (dwellInZone == bestDwell && minDist < best->minDistance)) {
                bestDwell = dwellInZone;
                best = Prediction{
                    candidate.name,
                    minDist,
                    minTime,
                    minX,
                    minY,
                    d0
                };
            }
        }
    }

    return best;
}

bool CtraPredictor::shouldExecuteHandover(const std::string& currentRsu, const std::string& targetRsu,
    double handoverRadius) const
{
    const RsuCandidate* target = findRsu(targetRsu);
    if (!target) {
        return false;
    }
    const double dTarget = euclidean(mState.x, mState.y, target->x, target->y);
    if (dTarget > handoverRadius) {
        return false;
    }
    const RsuCandidate* curr = findRsu(currentRsu);
    if (!curr) {
        return true;
    }
    const double dCurr = euclidean(mState.x, mState.y, curr->x, curr->y);
    return dTarget <= dCurr;
}

