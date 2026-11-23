#!/usr/bin/env bash
set -euo pipefail

# Build the CrowNet 5G NR simulation stack (OMNeT++ 6.3.0 + INET 4 + Veins + Artery + Simu5G + CrowNet)
# inside the v2x-crownet:6.3.0 Docker image, plus the repository's libtee_v2x.so module.
#
# Usage:
#   ./artery-sim/setup_artery.sh [--rebuild-image] [--clean-objs]

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
CROWNET_DIR="$SCRIPT_DIR/deps/crownet"
IMAGE_NAME="v2x-crownet:6.3.0"

REBUILD_IMAGE=0
CLEAN_OBJS=0
for arg in "$@"; do
    case "$arg" in
        --rebuild-image) REBUILD_IMAGE=1 ;;
        --clean-objs)    CLEAN_OBJS=1 ;;
        -h|--help)
            echo "Usage: $(basename "$0") [--rebuild-image] [--clean-objs]"
            exit 0
            ;;
        *)
            echo "error: unknown option '$arg'" >&2
            exit 2
            ;;
    esac
done

command -v docker >/dev/null 2>&1 || { echo "error: docker is required" >&2; exit 1; }
command -v sumo >/dev/null 2>&1 || { echo "error: host sumo is required (SUMO 1.26.0 recommended)" >&2; exit 1; }

if [ "$REBUILD_IMAGE" -eq 1 ] || ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "[setup] building Docker image $IMAGE_NAME..."
    docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile.crownet" "$SCRIPT_DIR"
else
    echo "[setup] Docker image $IMAGE_NAME already present (pass --rebuild-image to rebuild)."
fi

mkdir -p "$SCRIPT_DIR/deps"
if [ ! -d "$CROWNET_DIR/.git" ]; then
    echo "[setup] cloning roVer-HM/crownet (master)..."
    git clone --depth 1 --branch master https://github.com/roVer-HM/crownet.git "$CROWNET_DIR"
fi

echo "[setup] syncing CrowNet C++ submodules (inet4, veins, artery, simu5g, vanetza, pybind11)..."
(
    cd "$CROWNET_DIR"
    git submodule sync --recursive
    git submodule update --init --depth 1 inet4 veins artery simu5g
    cd artery
    git submodule update --init --depth 1 extern/vanetza extern/pybind11
)

NPROC="$(nproc)"
echo "[setup] compiling CrowNet C++ frameworks in Release mode ($NPROC jobs)..."
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e CCACHE_DISABLE=1 \
    -v "$REPO_ROOT:$REPO_ROOT" \
    -w "$CROWNET_DIR" \
    "$IMAGE_NAME" \
    bash -euo pipefail -c "
        if [ ! -f inet4/src/libINET.so ]; then
            echo '==> [1/7] Building INET 4...'
            make -C inet4 makefiles
            make -C inet4 -j$NPROC MODE=release
            [ '$CLEAN_OBJS' -eq 1 ] && find inet4/out -type f \( -name '*.o' -o -name '*.d' \) -delete || true
        else
            echo '==> [1/7] INET 4 already built (inet4/src/libINET.so).'
        fi

        if [ ! -f veins/src/libveins.so ]; then
            echo '==> [2/7] Building Veins...'
            (cd veins && ./configure)
            make -C veins -j$NPROC MODE=release
            [ '$CLEAN_OBJS' -eq 1 ] && find veins/out -type f \( -name '*.o' -o -name '*.d' \) -delete || true
        else
            echo '==> [2/7] Veins already built (veins/src/libveins.so).'
        fi

        if [ ! -f veins/subprojects/veins_inet/src/libveins_inet.so ]; then
            echo '==> [3/7] Building Veins_INET...'
            (cd veins/subprojects/veins_inet && ./configure --with-inet=../../../inet4)
            make -C veins/subprojects/veins_inet -j$NPROC MODE=release
            [ '$CLEAN_OBJS' -eq 1 ] && find veins/subprojects/veins_inet/out -type f \( -name '*.o' -o -name '*.d' \) -delete || true
        else
            echo '==> [3/7] Veins_INET already built (veins_inet/src/libveins_inet.so).'
        fi

        if [ ! -f artery/build/Release/lib/libartery_storyboard.so ]; then
            echo '==> [4/7] Building Artery + Vanetza...'
            make -C artery -j$NPROC MODE=release
            [ '$CLEAN_OBJS' -eq 1 ] && find artery/build artery/extern/vanetza/build -type f \( -name '*.o' -o -name '*.d' \) -delete || true
        else
            echo '==> [4/7] Artery already built (libartery_core.so + libartery_storyboard.so).'
        fi

        if [ ! -f simu5g/src/libsimu5g.so ]; then
            echo '==> [5/7] Building Simu5G...'
            make -C simu5g makefiles
            make -C simu5g -j$NPROC MODE=release
            [ '$CLEAN_OBJS' -eq 1 ] && find simu5g/out -type f \( -name '*.o' -o -name '*.d' \) -delete || true
        else
            echo '==> [5/7] Simu5G already built (simu5g/src/libsimu5g.so).'
        fi

        if [ ! -f crownet/src/libCROWNET.so ]; then
            echo '==> [6/7] Building CrowNet shared library...'
            make -C crownet build-lib MODE=release MMOPT='-L/usr/local/lib'
            [ '$CLEAN_OBJS' -eq 1 ] && find crownet/out -type f \( -name '*.o' -o -name '*.d' \) -delete || true
        else
            echo '==> [6/7] CrowNet already built (crownet/src/libCROWNET.so).'
        fi

        echo '==> [7/7] Building libtee_v2x.so...'
        make -C '$SCRIPT_DIR' -j$NPROC
    "

if [ "$CLEAN_OBJS" -eq 1 ]; then
    echo "[setup] removing intermediate .o/.d object files inside CrowNet out/..."
    find "$CROWNET_DIR/inet4/out" "$CROWNET_DIR/veins/out" "$CROWNET_DIR/simu5g/out" "$CROWNET_DIR/crownet/out" \
        -type f \( -name '*.o' -o -name '*.d' \) -delete 2>/dev/null || true
fi

echo "[setup] CrowNet 5G NR stack and libtee_v2x.so are ready."
echo "  Run pure 5G simulation:  make sim OTP=ascon"
echo "  Run 5G Quad-RSU HIL:     make hil-quad HIL_IFACE=<nic> OTP=ascon"
