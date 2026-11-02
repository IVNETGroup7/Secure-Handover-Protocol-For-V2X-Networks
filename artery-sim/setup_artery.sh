#!/bin/bash
# Sets up OMNeT++, Artery (INET, Veins, Vanetza), Simu5G (5G New Radio), SUMO, and the
# tee_v2x_handover scenario on the host PC (RSUs run via rsu-optee-gateway).
#
# Usage:
#   ./setup_artery.sh [--with-qtenv] [--skip-packages] [--artery-dir <dir>] [--simu5g-dir <dir>] [--jobs <n>]
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPS="$HERE/deps"
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"

if [ -z "${SUMO_HOME:-}" ]; then
    if python3 -c "import sumo" >/dev/null 2>&1; then
        export SUMO_HOME=$(python3 -c "import sumo; print(sumo.SUMO_HOME)")
        export PATH="$SUMO_HOME/bin:$PATH"
    elif [ -d /usr/share/sumo ]; then
        export SUMO_HOME=/usr/share/sumo
    fi
fi

OMNETPP_VERSION=${OMNETPP_VERSION:-5.7.1}
ARTERY_REF=${ARTERY_REF:-master}
SIMU5G_REF=${SIMU5G_REF:-master}
ARTERY_BUILD_TYPE=${ARTERY_BUILD_TYPE:-Release}
JOBS=$(nproc)
WITH_QTENV=no
SKIP_PACKAGES=no
ARTERY_DIR=""
SIMU5G_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --with-qtenv) WITH_QTENV=yes ;;
        --skip-packages) SKIP_PACKAGES=yes ;;
        --artery-dir) ARTERY_DIR=$(cd "$2" && pwd); shift ;;
        --simu5g-dir) SIMU5G_DIR=$(cd "$2" && pwd); shift ;;
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
OS_ID_STR=" ${ID:-} ${ID_LIKE:-} "
case "$OS_ID_STR" in
    *" arch "*|*" manjaro "*|*" endeavouros "*) DISTRO=arch ;;
    *" debian "*|*" ubuntu "*|*" linuxmint "*|*" pop "*|*" elementary "*|*" kali "*|*" raspbian "*) DISTRO=debian ;;
    *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*) DISTRO=redhat ;;
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
        debian)
            sudo apt-get update
            # GeographicLib: libgeographiclib-dev on 24.04+, libgeographic-dev on 22.04 and Debian
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
                openssl boost crypto++)
            if [ "$WITH_QTENV" = yes ]; then
                packages+=(qt5-base)
            fi
            sudo pacman -S --needed --noconfirm "${packages[@]}"

            # GeographicLib: in AUR (not in official pacman repos), or built from source
            if ! pkg-config --exists GeographicLib 2>/dev/null && [ ! -d /usr/include/GeographicLib ] && [ ! -d /usr/local/include/GeographicLib ]; then
                if pacman -Si geographiclib >/dev/null 2>&1; then
                    sudo pacman -S --needed --noconfirm geographiclib
                elif have yay; then
                    yay -S --needed --noconfirm geographiclib || true
                elif have paru; then
                    paru -S --needed --noconfirm geographiclib || true
                fi
                # Fallback: build from source if still missing
                if ! pkg-config --exists GeographicLib 2>/dev/null && [ ! -d /usr/include/GeographicLib ] && [ ! -d /usr/local/include/GeographicLib ]; then
                    echo "GeographicLib not found; building from source..."
                    local geo_dir="$DEPS/geographiclib-build"
                    mkdir -p "$DEPS"
                    if [ ! -d "$geo_dir/.git" ]; then
                        git clone --depth 1 https://github.com/geographiclib/geographiclib.git "$geo_dir"
                    fi
                    cmake -S "$geo_dir" -B "$geo_dir/build" -DCMAKE_BUILD_TYPE=Release
                    cmake --build "$geo_dir/build" -j"$JOBS"
                    sudo cmake --install "$geo_dir/build"
                fi
            fi

            # SUMO: in AUR, or via pip
            if ! have sumo; then
                if pacman -Si sumo >/dev/null 2>&1; then
                    sudo pacman -S --needed --noconfirm sumo
                else
                    local sumo_cachedir="$HOME/.cache/yay/sumo"
                    # If yay/paru cache exists or if already partially compiled, apply Python 3.13+ patch
                    if [ -d "$sumo_cachedir" ]; then
                        if [ -f "$sumo_cachedir/PKGBUILD" ] && ! grep -q "PyLong_AsLong" "$sumo_cachedir/PKGBUILD"; then
                            sed -i '/0001-fix-arrow-cpp20.patch.*|| true/a \    # Fix Python 3.13+ compatibility\n    sed -i -e '\''s/PyInt_Check/PyLong_Check/g'\'' -e '\''s/PyInt_AsLong/PyLong_AsLong/g'\'' -e '\''s/PyInt_FromLong/PyLong_FromLong/g'\'' "$pkgname-$pkgver"/src/libsumo/libsumo_typemap.i' "$sumo_cachedir/PKGBUILD"
                        fi
                        find "$sumo_cachedir/src" \( -name "libsumo_typemap.i" -o -name "libsumoPYTHON_wrap.cxx" \) -exec sed -i -e 's/PyInt_Check/PyLong_Check/g' -e 's/PyInt_AsLong/PyLong_AsLong/g' -e 's/PyInt_FromLong/PyLong_FromLong/g' {} + 2>/dev/null || true
                    fi

                    if [ -d "$sumo_cachedir/src/build" ] && [ -f "$sumo_cachedir/PKGBUILD" ]; then
                        echo "Resuming SUMO build from cache..."
                        (cd "$sumo_cachedir" && makepkg -si -e --noconfirm) || true
                    fi
                    if ! have sumo && have yay; then
                        yay -S --needed --noconfirm sumo || true
                    elif ! have sumo && have paru; then
                        paru -S --needed --noconfirm sumo || true
                    fi
                fi
                if ! have sumo && (have pip || have pip3); then
                    local pip_cmd="pip"
                    have pip3 && pip_cmd="pip3"
                    $pip_cmd install --upgrade --break-system-packages eclipse-sumo 2>/dev/null \
                        || sudo $pip_cmd install --upgrade --break-system-packages eclipse-sumo 2>/dev/null \
                        || $pip_cmd install --upgrade eclipse-sumo 2>/dev/null \
                        || sudo $pip_cmd install --upgrade eclipse-sumo 2>/dev/null \
                        || true
                fi
                if ! have sumo; then
                    echo "WARNING: install SUMO from the AUR (e.g. 'cd ~/.cache/yay/sumo && makepkg -si') or via 'pip install eclipse-sumo': the scenario needs sumo in PATH" >&2
                fi
            fi
            ;;
        redhat)
            local pkg_mgr="dnf"
            have dnf || pkg_mgr="yum"

            # On RHEL / CentOS / Rocky / AlmaLinux, enable EPEL for extra libraries
            if [ "${ID:-}" != "fedora" ] && [[ "${ID_LIKE:-}" != *"fedora"* ]]; then
                sudo $pkg_mgr install -y epel-release || true
            fi

            # Determine GeographicLib package name (GeographicLib-devel or geographiclib-devel)
            local geo_pkg="GeographicLib-devel"
            if ! $pkg_mgr info "$geo_pkg" >/dev/null 2>&1 && $pkg_mgr info geographiclib-devel >/dev/null 2>&1; then
                geo_pkg="geographiclib-devel"
            fi

            # Determine Crypto++ package name (cryptopp-devel or crypto++-devel)
            local crypto_pkg="cryptopp-devel"
            if ! $pkg_mgr info "$crypto_pkg" >/dev/null 2>&1 && $pkg_mgr info crypto++-devel >/dev/null 2>&1; then
                crypto_pkg="crypto++-devel"
            fi

            local packages=(
                gcc-c++ clang lld gdb bison flex perl python3 python3-devel
                git wget curl ca-certificates cmake pkgconf-pkg-config
                libxml2-devel zlib-devel openssl-devel boost-devel
            )

            if $pkg_mgr info "$geo_pkg" >/dev/null 2>&1; then
                packages+=("$geo_pkg")
            fi
            if $pkg_mgr info "$crypto_pkg" >/dev/null 2>&1; then
                packages+=("$crypto_pkg")
            fi
            if [ "$WITH_QTENV" = yes ]; then
                packages+=(qt5-qtbase-devel)
            fi

            sudo $pkg_mgr install -y "${packages[@]}"

            # Fallback for GeographicLib if not present in repos
            if ! pkg-config --exists GeographicLib 2>/dev/null && [ ! -d /usr/include/GeographicLib ] && [ ! -d /usr/local/include/GeographicLib ]; then
                echo "GeographicLib not in $pkg_mgr repos; building from source..."
                local geo_dir="$DEPS/geographiclib-build"
                mkdir -p "$DEPS"
                if [ ! -d "$geo_dir/.git" ]; then
                    git clone --depth 1 https://github.com/geographiclib/geographiclib.git "$geo_dir"
                fi
                cmake -S "$geo_dir" -B "$geo_dir/build" -DCMAKE_BUILD_TYPE=Release
                cmake --build "$geo_dir/build" -j"$JOBS"
                sudo cmake --install "$geo_dir/build"
            fi

            # SUMO on Red Hat / Fedora (OBS repo or pip)
            if ! have sumo; then
                if $pkg_mgr info sumo >/dev/null 2>&1; then
                    sudo $pkg_mgr install -y sumo
                elif have pip3 || have pip; then
                    local pip_cmd="pip3"
                    have pip3 || pip_cmd="pip"
                    $pip_cmd install --upgrade eclipse-sumo || sudo $pip_cmd install --upgrade eclipse-sumo || true
                fi
                if ! have sumo; then
                    echo "WARNING: install SUMO via DLR repository (https://download.opensuse.org/repositories/science:/dlr/) or 'pip install eclipse-sumo': the scenario needs sumo in PATH" >&2
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

# Simu5G (5G New Radio model for OMNeT++/INET)

install_simu5g() {
    step "4. Simu5G (5G New Radio model)"
    if [ -n "$SIMU5G_DIR" ]; then
        echo "given: $SIMU5G_DIR"
        return
    fi
    SIMU5G_DIR="$DEPS/simu5g"
    if [ ! -d "$SIMU5G_DIR/.git" ]; then
        git clone https://github.com/Unipisa/Simu5G.git "$SIMU5G_DIR"
        git -C "$SIMU5G_DIR" checkout "$SIMU5G_REF" || true
    fi
    ln -sfn "$SIMU5G_DIR" "$DEPS/simu5g"
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
    step "6. build (Artery, the OP-TEE gateway protocol, the tee_v2x feature)"
    if [ -n "$OMNETPP_ROOT" ] && [ -f "$OMNETPP_ROOT/setenv" ]; then
        omnetpp_environment
    fi
    local build="$ARTERY_DIR/build"
    local cmake_args=("-DCMAKE_BUILD_TYPE=$ARTERY_BUILD_TYPE")
    if [ -d "$SIMU5G_DIR/src" ]; then
        cmake_args+=("-DSIMU5G_NED_DIR=$SIMU5G_DIR/src")
    fi
    if [ -f "$build/CMakeCache.txt" ]; then
        cmake "$build"     # picks up the new subdirectory
    else
        cmake -S "$ARTERY_DIR" -B "$build" "${cmake_args[@]}"
    fi
    cmake --build "$build" -j "$JOBS"
}

install_packages
install_omnetpp
install_artery
install_simu5g
register_scenario
build_artery

step "done"
build="$ARTERY_DIR/build"
cat <<EOF
Artery:   $ARTERY_DIR (build: $build)
Simu5G:   $SIMU5G_DIR
Scenario: $HERE/scenario (omnetpp.ini: D250m_80211p [ITS-G5 802.11p] and D500m_5G [Simu5G 5G NR]; results in scenario/results/)

Run it through CMake (RUN_FLAGS picks the user interface and the configuration):
  cmake -DRUN_FLAGS="-u Cmdenv -c D250m_80211p" $build
  cmake --build $build --target run_tee_v2x_handover

  # Or run with Simu5G (5G New Radio, 3.5 GHz, 20 MHz, numerology 1, gNodeB X2 handover):
  cmake -DRUN_FLAGS="-u Cmdenv -c D500m_5G" $build
  cmake --build $build --target run_tee_v2x_handover
EOF
if [ -x "$build/run_artery.sh" ]; then
    printf 'or directly, from the scenario folder:\n  cd %s/scenario && %s/run_artery.sh -u Cmdenv -c D500m_5G\n' "$HERE" "$build"
fi
