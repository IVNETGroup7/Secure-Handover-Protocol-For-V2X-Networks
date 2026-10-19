set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPS="$HERE/deps"
OMNETPP_VERSION=${OMNETPP_VERSION:-5.7.1}
ARTERY_REF=${ARTERY_REF:-master}
ARTERY_BUILD_TYPE=${ARTERY_BUILD_TYPE:-Release}
JOBS=$(nproc)
INSTALL_SGX=no
WITH_QTENV=no
SKIP_PACKAGES=no
ARTERY_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --install-sgx) INSTALL_SGX=yes ;;
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
# the SDK's and OMNeT++'s environment scripts read variables that may be unset
sgx_environment() { set +u; source "$SGX_SDK/environment"; set -u; }
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

# Intel SGX SDK + SGX-SSL (simulation mode)

SGX_SDK=${SGX_SDK:-/opt/intel/sgxsdk}
SGXSSL=${SGXSSL:-/opt/intel/sgxssl}

install_sgx() {
    step "4. Intel SGX SDK and SGX-SSL (simulation mode)"
    if [ -f "$SGX_SDK/environment" ] && [ -f "$SGXSSL/lib64/libsgx_usgxssl.a" ]; then
        echo "already installed: $SGX_SDK, $SGXSSL"
        return
    fi
    if [ "$INSTALL_SGX" != yes ]; then
        echo "WARNING: no Intel SGX SDK ($SGX_SDK) or SGX-SSL ($SGXSSL): Artery builds, but without the" \
            "tee_v2x_handover scenario (rerun with --install-sgx)" >&2
        return
    fi
    case "$DISTRO" in
        ubuntu) sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential python-is-python3 libssl-dev \
                    wget curl nasm git perl ;;
        arch) sudo pacman -S --needed --noconfirm base-devel python openssl wget curl nasm git perl ;;
    esac
    local work
    work=$(mktemp -d)

    # SDK
    if [ ! -f "$SGX_SDK/environment" ]; then
        local distro=ubuntu24.04-server
        if [ "$DISTRO" = ubuntu ] && [ "${VERSION_ID:-}" = 22.04 ]; then
            distro=ubuntu22.04-server
        fi
        local repo="https://download.01.org/intel-sgx/latest/linux-latest/distro/$distro"
        local installer
        installer=$(curl -fsSL "$repo/" | grep -oE 'sgx_linux_x64_sdk_[0-9.]+\.bin' | sort -uV | tail -n1)
        [ -n "$installer" ] || { echo "error: no SGX SDK installer at $repo" >&2; exit 1; }
        wget -q -O "$work/$installer" "$repo/$installer"
        chmod +x "$work/$installer"
        echo yes | sudo "$work/$installer" --prefix="$(dirname "$SGX_SDK")"
    fi

    # SGX-SSL
    if [ ! -f "$SGXSSL/lib64/libsgx_usgxssl.a" ]; then
        local tag=3.0_Rev5.4 openssl=openssl-3.0.21
        local sha=617e29af8e421f46649484a4937e48c685e47f46488167c982f88bc4ec1d522f
        git clone --depth 1 --branch "$tag" https://github.com/intel/intel-sgx-ssl.git "$work/intel-sgx-ssl"
        wget -q -O "$work/intel-sgx-ssl/openssl_source/$openssl.tar.gz" \
            "https://github.com/openssl/openssl/releases/download/$openssl/$openssl.tar.gz"
        echo "$sha  $work/intel-sgx-ssl/openssl_source/$openssl.tar.gz" | sha256sum -c -
        (
            sgx_environment
            make -C "$work/intel-sgx-ssl/Linux" all SGX_MODE=SIM SGX_SDK="$SGX_SDK"
            sudo make -C "$work/intel-sgx-ssl/Linux" install SGX_SDK="$SGX_SDK"
        )
    fi
    rm -rf "$work"
}

# the scenario

register_scenario() {
    step "5. tee_v2x_handover in Artery's build"
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
    step "5. build (Artery, the enclave, the tee_v2x feature)"
    if [ -n "$OMNETPP_ROOT" ] && [ -f "$OMNETPP_ROOT/setenv" ]; then
        omnetpp_environment
    fi
    if [ -f "$SGX_SDK/environment" ]; then
        sgx_environment
    fi
    export SGX_SDK
    local build="$ARTERY_DIR/build"
    if [ -f "$build/CMakeCache.txt" ]; then
        cmake "$build" -DSGX_SDK="$SGX_SDK" -DSGXSSL="$SGXSSL"     # picks up the new subdirectory
    else
        cmake -S "$ARTERY_DIR" -B "$build" -DCMAKE_BUILD_TYPE="$ARTERY_BUILD_TYPE" -DSGX_SDK="$SGX_SDK" \
            -DSGXSSL="$SGXSSL"
    fi
    cmake --build "$build" -j "$JOBS"
}

install_packages
install_omnetpp
install_artery
install_sgx
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
