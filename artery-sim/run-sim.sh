#!/usr/bin/env bash
set -euo pipefail

# Launcher for CrowNet 5G NR (OMNeT++ 6.3.0 + INET 4 + Artery + Simu5G) simulations
# and 5G NR Hardware-in-the-Loop (HIL) runs.
#
# Runs host SUMO (sumo / sumo-gui) on a local TraCI TCP port and connects opp_run_release
# inside the v2x-crownet:6.3.0 container (--network=host) to it via traci.ConnectLauncher.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SCENARIO_DIR="$SCRIPT_DIR/scenario"
CROWNET_DIR="$SCRIPT_DIR/deps/crownet"
IMAGE_NAME="v2x-crownet:6.3.0"

CONFIG=""
OTP_ALGO="${OTP_ALGO:-${OTP:-ascon}}"
IFACE="${HIL_IFACE:-}"
CSV_PREFIX="${CSV_PREFIX:-}"
VERBOSE="${V2X_VERBOSE:-0}"
QUIET=0
USE_GUI=0
REBUILD=0
EXTRA_FLAGS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] [-- <extra opp_run flags>]

Options:
  --config <name>        OMNeT++ config (default: NR_5G, or NR_5G_GUI with --gui)
  --otp ascon|poly1305   Select OTP/MAC algorithm for the whole run (default: ascon)
  --iface <nic>          Host Ethernet interface for HIL configs (or export HIL_IFACE=<nic>)
  --csv-prefix <path>    Prefix for CSV exports (<prefix>-{summary,handovers,packets}.csv)
  --quiet                Focused evaluation output (suppress verbose per-step crypto hex trace)
  --verbose              Enable full per-step cryptographic trace (overrides quietTrace in HIL)
  --gui                  Launch host sumo-gui (--start) instead of headless sumo
  --rebuild              Rebuild libtee_v2x.so before running
  -h, --help             Show this help message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --config)
            [ $# -ge 2 ] || { echo "error: --config requires an argument" >&2; exit 2; }
            CONFIG="$2"
            shift 2
            ;;
        --otp)
            [ $# -ge 2 ] || { echo "error: --otp requires an argument" >&2; exit 2; }
            OTP_ALGO="$2"
            shift 2
            ;;
        --iface)
            [ $# -ge 2 ] || { echo "error: --iface requires an argument" >&2; exit 2; }
            IFACE="$2"
            shift 2
            ;;
        --csv-prefix)
            [ $# -ge 2 ] || { echo "error: --csv-prefix requires an argument" >&2; exit 2; }
            CSV_PREFIX="$2"
            shift 2
            ;;
        --quiet)
            QUIET=1
            VERBOSE=0
            shift
            ;;
        --verbose)
            VERBOSE=1
            QUIET=0
            shift
            ;;
        --gui)
            USE_GUI=1
            shift
            ;;
        --rebuild)
            REBUILD=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            EXTRA_FLAGS+=("$@")
            break
            ;;
        *)
            echo "error: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$OTP_ALGO" != "ascon" ] && [ "$OTP_ALGO" != "poly1305" ]; then
    echo "error: invalid --otp '$OTP_ALGO' (expected 'ascon' or 'poly1305')" >&2
    exit 2
fi

if [ -z "$CONFIG" ]; then
    if [ "$USE_GUI" -eq 1 ]; then
        CONFIG="NR_5G_GUI"
    else
        CONFIG="NR_5G"
    fi
fi

IS_HIL=0
case "$CONFIG" in
    *HIL*) IS_HIL=1 ;;
esac

if [ "$IS_HIL" -eq 1 ] && [ -z "$IFACE" ]; then
    echo "error: HIL config '$CONFIG' requires --iface <nic> (or HIL_IFACE=<nic>)" >&2
    exit 2
fi

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "error: Docker image '$IMAGE_NAME' not found; run $SCRIPT_DIR/setup_artery.sh first" >&2
    exit 1
fi

if [ ! -f "$CROWNET_DIR/crownet/src/libCROWNET.so" ]; then
    echo "error: CrowNet libraries not built ($CROWNET_DIR/crownet/src/libCROWNET.so missing); run $SCRIPT_DIR/setup_artery.sh first" >&2
    exit 1
fi

if [ "$REBUILD" -eq 1 ] || [ ! -f "$SCRIPT_DIR/build/libtee_v2x.so" ]; then
    echo "[run-sim] building libtee_v2x.so..."
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -e CCACHE_DISABLE=1 \
        -v "$REPO_ROOT:$REPO_ROOT" \
        -w "$SCRIPT_DIR" \
        "$IMAGE_NAME" \
        make -j"$(nproc)"
fi

# Pick a free localhost TCP port for SUMO TraCI
TRACI_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

SUMO_BIN="sumo"
SUMO_ARGS=(-c "$SCENARIO_DIR/highway.sumocfg" --remote-port "$TRACI_PORT" --no-step-log)
if [ "$USE_GUI" -eq 1 ] || [[ "$CONFIG" == *_GUI ]]; then
    SUMO_BIN="sumo-gui"
    SUMO_ARGS+=(--start --quit-on-end)
fi

command -v "$SUMO_BIN" >/dev/null 2>&1 || { echo "error: '$SUMO_BIN' not found in PATH" >&2; exit 1; }

SUMO_PID=""
cleanup() {
    if [ -n "$SUMO_PID" ] && kill -0 "$SUMO_PID" 2>/dev/null; then
        kill "$SUMO_PID" 2>/dev/null || true
        wait "$SUMO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

"$SUMO_BIN" "${SUMO_ARGS[@]}" >/dev/null 2>&1 &
SUMO_PID=$!

# Wait up to 10 s for SUMO TraCI TCP socket to enter LISTEN state without connecting
# (connecting & closing a probe socket causes SUMO --remote-port to exit immediately).
python3 - "$TRACI_PORT" "$SUMO_PID" <<'PY'
import os, sys, time
port_hex = f"{int(sys.argv[1]):04X}"
pid = int(sys.argv[2])
deadline = time.monotonic() + 10.0
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except OSError:
        sys.exit("error: SUMO exited before opening TraCI port")
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if len(cols) >= 4 and cols[3] == "0A" and cols[1].endswith(":" + port_hex):
                        sys.exit(0)
        except OSError:
            pass
    time.sleep(0.05)
sys.exit(f"error: timed out waiting for SUMO TraCI on port {sys.argv[1]}")
PY

NED_PATH="\
$SCENARIO_DIR:\
$SCRIPT_DIR/src:\
$CROWNET_DIR/inet4/src:\
$CROWNET_DIR/veins/src/veins:\
$CROWNET_DIR/veins/subprojects/veins_inet/src/veins_inet:\
$CROWNET_DIR/artery/src:\
$CROWNET_DIR/simu5g/src:\
$CROWNET_DIR/crownet/src"

LD_PATH="\
/root/omnetpp/lib:\
/usr/local/lib:\
$CROWNET_DIR/inet4/src:\
$CROWNET_DIR/veins/src:\
$CROWNET_DIR/veins/subprojects/veins_inet/src:\
$CROWNET_DIR/artery/build/Release/lib:\
$CROWNET_DIR/artery/extern/vanetza/build/Release/lib:\
$CROWNET_DIR/simu5g/src:\
$CROWNET_DIR/crownet/src:\
$SCRIPT_DIR/build"

DOCKER_ARGS=(
    --rm
    --network=host
    --user "$(id -u):$(id -g)"
    -e HOME=/tmp
    -e "OTP_ALGO=$OTP_ALGO"
    -e "LD_LIBRARY_PATH=$LD_PATH"
    -v "$REPO_ROOT:$REPO_ROOT"
    -w "$SCENARIO_DIR"
)

RUN_TS="$(date +%Y%m%d-%H%M%S)"
RESULT_STEM="${CSV_PREFIX:-results/${CONFIG}-${OTP_ALGO}-${RUN_TS}}"

OPP_ARGS=(
    -u Cmdenv
    -c "$CONFIG"
    -n "$NED_PATH"
    -l "$CROWNET_DIR/inet4/src/INET"
    -l "$CROWNET_DIR/veins/src/veins"
    -l "$CROWNET_DIR/veins/subprojects/veins_inet/src/veins_inet"
    -l "$CROWNET_DIR/artery/build/Release/lib/artery_core"
    -l "$CROWNET_DIR/artery/build/Release/lib/traci"
    -l "$CROWNET_DIR/simu5g/src/simu5g"
    -l "$CROWNET_DIR/crownet/src/CROWNET"
    -l "$SCRIPT_DIR/build/tee_v2x"
    "--output-scalar-file=${RESULT_STEM}.sca"
    "--output-vector-file=${RESULT_STEM}.vec"
    "--*.traci.launcher.port=$TRACI_PORT"
)

if [ "$IS_HIL" -eq 1 ]; then
    DOCKER_ARGS+=(--cap-add=NET_RAW -e "HIL_IFACE=$IFACE")
    OPP_ARGS+=(--scheduler-class=omnetpp::cRealTimeScheduler)
fi

DOCKER_ARGS+=(-e "CSV_PREFIX=$RESULT_STEM")

if [ "$VERBOSE" = "1" ]; then
    DOCKER_ARGS+=(-e "V2X_VERBOSE=1")
elif [ "$QUIET" -eq 1 ]; then
    OPP_ARGS+=(--*.backhaulBroker.quietTrace=true)
fi

if [ ${#EXTRA_FLAGS[@]} -gt 0 ]; then
    OPP_ARGS+=("${EXTRA_FLAGS[@]}")
fi

echo "[run-sim] config=$CONFIG OTP_ALGO=$OTP_ALGO traci=127.0.0.1:$TRACI_PORT${IFACE:+ HIL_IFACE=$IFACE}"
docker run "${DOCKER_ARGS[@]}" "$IMAGE_NAME" opp_run_release "${OPP_ARGS[@]}"

