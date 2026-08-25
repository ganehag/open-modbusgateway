#!/usr/bin/env bash
# Current Teltonika SDK releases, checked 2026-08-22.
#
# Keep this file intentionally explicit. A release build must not silently move
# to a different vendor SDK just because a web page changed.

set -euo pipefail

teltonika_target() {
    case "${1:?target is required}" in
    rut9-r)
        SDK_VERSION=00.07.06.21
        SDK_ARCHIVE=RUT9_R_GPL_00.07.06.21.tar.gz
        SDK_URL=https://firmware.teltonika-networks.com/7.6.21/RUT9/RUT9_R_GPL_00.07.06.21.tar.gz
        SDK_MD5=8eae7aa155f1a870f0d79aaae59715c2
        SDK_SHA256=9bb220a39708b541cf484faf7c8644ded088613b9fa00af8846179db8cebda2a
        SDK_DIR=rutos-ath79-rut9-gpl
        SDK_ARCH=mips_24kc
        SDK_BASE_IMAGE=ubuntu:focal
        SDK_NODE_MAJOR=18
        SDK_PYTHON_VERSION=3.8
        ;;
    rut9m-r)
        SDK_VERSION=00.07.24
        SDK_ARCHIVE=RUT9M_R_GPL_00.07.24.tar.gz
        SDK_URL=https://firmware.teltonika-networks.com/7.24/RUT9M/RUT9M_R_GPL_00.07.24.tar.gz
        SDK_MD5=8a90d233c811aa20a88ef9f49b302a50
        SDK_SHA256=288d2a0a51032a13f9b652211b079447309466c80688801283039a222e8ad424
        SDK_DIR=rutos-ramips-rut9m-sdk
        SDK_ARCH=mipsel_24kc
        SDK_BASE_IMAGE=ubuntu:jammy-20240808
        SDK_NODE_MAJOR=20
        SDK_PYTHON_VERSION=3.11
        ;;
    trb1-r)
        SDK_VERSION=00.07.24.2
        SDK_ARCHIVE=TRB1_R_GPL_00.07.24.2.tar.gz
        SDK_URL=https://firmware.teltonika-networks.com/7.24.2/TRB1/TRB1_R_GPL_00.07.24.2.tar.gz
        SDK_MD5=57e29690bb01cb501d0bc43a949d1a9b
        SDK_SHA256=d09e05c647997bc8eb8b56412641c33730209a542f6ddff4c48100c84191c4a9
        SDK_DIR=rutos-mdm9x07-trb1-sdk
        SDK_ARCH=arm_cortex-a7_neon-vfpv4
        SDK_BASE_IMAGE=ubuntu:jammy-20240808
        SDK_NODE_MAJOR=20
        SDK_PYTHON_VERSION=3.11
        ;;
    *)
        echo "unknown Teltonika target: $1" >&2
        echo "supported targets: rut9-r, rut9m-r, trb1-r" >&2
        return 2
        ;;
    esac
}
