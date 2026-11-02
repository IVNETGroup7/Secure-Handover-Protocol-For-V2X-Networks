#!/bin/bash
# Sets up OMNeT++ 5.7.1, Artery (INET, Veins, Vanetza), SUMO, and the tee_v2x_handover scenario
# on the host PC (RSUs run via rsu-optee-gateway).
#
# Usage:
#   ./setup_artery.sh [--with-qtenv] [--skip-packages] [--artery-dir <dir>] [--jobs <n>]
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPS="$HERE/deps"
OMNETPP_VERSION=${OMNETPP_VERSION:-5.7.1}
ARTERY_REF=${ARTERY_REF:-master}
ARTERY_BUILD_TYPE=${ARTERY_BUILD_TYPE:-Release}
JOBS=$(nproc)
WITH_QTENV=no
SKIP_PACKAGES=no
ARTERY_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --with-qtenv) WITH_QTENV=yes ;;
        --skip-packages) SKIP_PACKAGES=yes ;;
        --artery-dir) ARTERY_DIR=$(cd "$2" && pwd); shift ;;
        --jobs) JOBS=$2; shift ;;
        -h|--help) awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
        *) echo "error: unknown option '$1' (--help)" >&2; exit 1 ;;
    esac
    shift
done

step() { echo; echo "=== $* ==="; }
have() { command -v "$1" >/dev/null 2>&1; }
# OMNeT++'s configure and its tools want this, not only bin/ in PATH (configure checks __omnetpp_root_dir)
omnetpp_environment() { set +u; source "$OMNETPP_ROOT/setenv" -q; set -u; }

. /etc/os-release
case " ${ID} ${ID_LIKE:-} " in
    *" arch "*) DISTRO=arch ;;
    *" ubuntu "*|*" debian "*) DISTRO=ubuntu ;;
    *) DISTRO=unknown ;;
esac

# System packages

install_packages() {
    step "1. system packages ($PRETTY_NAME)"
    if [ "$SKIP_PACKAGES" = yes ]; then
        echo "skipped (--skip-packages)"
        return
    fi
    case "$DISTRO" in
        ubuntu)
            sudo apt-get update
            # GeographicLib: libgeographiclib-dev on 24.04, libgeographic-dev on 22.04
            local geographic=libgeographiclib-dev
            if [ -z "$(LC_ALL=C apt-cache policy libgeographiclib-dev 2>/dev/null | awk '/Candidate/ && $2 != "(none)"')" ]; then
                geographic=libgeographic-dev
            fi
            # python3-dev: the headers of Artery's pybind11
            local packages=(build-essential clang lld gdb bison flex perl python3 python3-dev python-is-python3 git wget curl
                ca-certificates cmake pkg-config libxml2-dev zlib1g-dev libssl-dev
                libboost-dev libboost-date-time-dev libboost-system-dev "$geographic" libcrypto++-dev
                sumo sumo-tools)
            if [ "$WITH_QTENV" = yes ]; then
                packages+=(qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5opengl5-dev)
            fi
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
            ;;
        arch)
            local packages=(base-devel clang lld gdb bison flex perl python git wget curl cmake pkgconf libxml2 zlib
                openssl boost geographiclib crypto++)
            if [ "$WITH_QTENV" = yes ]; then
                packages+=(qt5-base)
            fi
            sudo pacman -S --needed --noconfirm "${packages[@]}"
            # SUMO is in the AUR, not in the official repositories
            if ! have sumo; then
                if pacman -Si sumo >/dev/null 2>&1; then
                    sudo pacman -S --needed --noconfirm sumo
                elif have yay; then
                    yay -S --needed --noconfirm sumo
                elif have paru; then
                    paru -S --needed --noconfirm sumo
                else
                    echo "WARNING: install SUMO from the AUR (e.g. 'yay -S sumo'): the scenario needs sumo in PATH" >&2
                fi
            fi
            ;;
        *)
            echo "WARNING: $PRETTY_NAME is not supported: install by hand a C++17 compiler, bison, flex, CMake," \
                "Boost (date_time, system), GeographicLib, Crypto++, OpenSSL 3 and SUMO" >&2
            ;;
    esac
}

# OMNeT++

OMNETPP_ROOT=""

install_omnetpp() {
    step "2. OMNeT++"
    if have opp_run; then
        OMNETPP_ROOT=$(cd "$(dirname "$(command -v opp_run)")/.." && pwd)
        echo "already in PATH: $OMNETPP_ROOT"
        return
    fi
    OMNETPP_ROOT="$DEPS/omnetpp-$OMNETPP_VERSION"
    if [ -x "$OMNETPP_ROOT/bin/opp_run" ] && [ -x "$OMNETPP_ROOT/bin/opp_run_dbg" ]; then
        echo "already built: $OMNETPP_ROOT"
        ln -sfn "omnetpp-$OMNETPP_VERSION" "$DEPS/omnetpp"
        return
    fi

    mkdir -p "$DEPS"
    local archive="$DEPS/omnetpp-$OMNETPP_VERSION-src-linux.tgz"
    if [ ! -d "$OMNETPP_ROOT" ]; then
        if [ ! -f "$archive" ]; then
            wget -O "$archive.part" \
                "https://github.com/omnetpp/omnetpp/releases/download/omnetpp-$OMNETPP_VERSION/omnetpp-$OMNETPP_VERSION-src-linux.tgz"
            mv "$archive.part" "$archive"
        fi
        tar -xzf "$archive" -C "$DEPS"
    fi
    ln -sfn "omnetpp-$OMNETPP_VERSION" "$DEPS/omnetpp"

    (
        cd "$OMNETPP_ROOT"
        omnetpp_environment
        ./configure WITH_QTENV="$WITH_QTENV" WITH_OSG=no WITH_OSGEARTH=no
        make -j"$JOBS" MODE=release
        make -j"$JOBS" MODE=debug
    )
}

# Artery

install_artery() {
    step "3. Artery (INET, Veins, Vanetza)"
    if [ -n "$ARTERY_DIR" ]; then
        echo "given: $ARTERY_DIR"
        return
    fi
    ARTERY_DIR="$DEPS/artery"
    if [ ! -d "$ARTERY_DIR/.git" ]; then
        git clone --recurse-submodules https://github.com/riebl/artery.git "$ARTERY_DIR"
        git -C "$ARTERY_DIR" checkout "$ARTERY_REF"
    fi
    # an empty extern/ (submodules not fetched) breaks the build
    git -C "$ARTERY_DIR" submodule update --init --recursive
}

# the scenario

register_scenario() {
    step "4. tee_v2x_handover in Artery's build"
    local list="$ARTERY_DIR/scenarios/CMakeLists.txt"
    if ! grep -q "tee_v2x_handover" "$list"; then
        printf '\n# Secure-Handover-Protocol-For-V2X-Networks (artery-sim/setup_artery.sh)\nadd_subdirectory(%s ${CMAKE_BINARY_DIR}/scenarios/tee_v2x_handover)  # tee_v2x_handover\n' \
            "$HERE" >> "$list"
        echo "registered in $list"
    else
        echo "already registered in $list"
    fi
    ln -sfn "$HERE" "$ARTERY_DIR/scenarios/tee_v2x_handover"

    # the SUMO network, from the node and edge files (kept in the repository, regenerated when missing)
    if [ ! -f "$HERE/scenario/highway.net.xml" ]; then
        (cd "$HERE/scenario" && netconvert -c highway.netccfg)
    fi
}

build_artery() {
    step "5. build (Artery, the OP-TEE gateway protocol, the tee_v2x feature)"
    if [ -n "$OMNETPP_ROOT" ] && [ -f "$OMNETPP_ROOT/setenv" ]; then
        omnetpp_environment
    fi
    local build="$ARTERY_DIR/build"
    if [ -f "$build/CMakeCache.txt" ]; then
        cmake "$build"     # picks up the new subdirectory
    else
        cmake -S "$ARTERY_DIR" -B "$build" -DCMAKE_BUILD_TYPE="$ARTERY_BUILD_TYPE"
    fi
    cmake --build "$build" -j "$JOBS"
}

install_packages
install_omnetpp
install_artery
register_scenario
build_artery

step "done"
build="$ARTERY_DIR/build"
cat <<EOF
Artery:   $ARTERY_DIR (build: $build)
Scenario: $HERE/scenario (omnetpp.ini: configurations D250m_80211p and D500m_5G; results in scenario/results/)

Run it through CMake (RUN_FLAGS picks the user interface and the configuration):
  cmake -DRUN_FLAGS="-u Cmdenv -c D250m_80211p" $build
  cmake --build $build --target run_tee_v2x_handover
EOF
if [ -x "$build/run_artery.sh" ]; then
    printf 'or directly, from the scenario folder:\n  cd %s/scenario && %s/run_artery.sh -u Cmdenv -c D500m_5G\n' "$HERE" "$build"
fi
