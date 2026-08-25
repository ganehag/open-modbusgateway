# syntax=docker/dockerfile:1
# Build context is this directory. The verified SDK archive is placed at
# downloads/<SDK_ARCHIVE> by scripts/build-teltonika-sdk-image.
ARG SDK_BASE_IMAGE=ubuntu:jammy-20240808
FROM ${SDK_BASE_IMAGE} AS sdk-base

ARG SDK_ARCHIVE
ARG SDK_ROOT
ARG SDK_VERSION
ARG SDK_TARGET
ARG SDK_NODE_MAJOR
ARG SDK_PYTHON_VERSION

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    TELTONIKA_SDK_DIR=/opt/teltonika-sdk

RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils binutils-gold bison build-essential bzip2 ca-certificates cmake \
    curl default-jdk device-tree-compiler devscripts ecj fakeroot file flex \
    g++ g++-multilib gawk gcc gcc-multilib gengetopt gettext git gnupg gperf \
    groff help2man jq libc6-dev libcap2-bin libexpat-dev libffi-dev liblz4-dev \
    libncurses5-dev libpcre3-dev libsqlite3-dev libssl-dev libxml-parser-perl \
    libzstd-dev lz4 make mkisofs ocaml ocaml-findlib ocaml-nox patch pkg-config \
    psmisc python-is-python3 python3 python3-dev python3-setuptools python3-yaml \
    rsync ruby sharutils subversion swig u-boot-tools unzip uuid-dev vim-common \
    wget zip zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python${SDK_PYTHON_VERSION} python${SDK_PYTHON_VERSION}-dev python3-setuptools \
    && ln -sf /usr/bin/python${SDK_PYTHON_VERSION} /usr/local/bin/python \
    && ln -sf /usr/bin/python${SDK_PYTHON_VERSION} /usr/local/bin/python3 \
    && ln -sf /usr/bin/python${SDK_PYTHON_VERSION}-config /usr/local/bin/python3-config \
    && rm -rf /var/lib/apt/lists/*

# Teltonika's SDK prerequisite checks require Node.js and npm. Use the same
# major versions as the Dockerfiles shipped with the corresponding SDK lines.
RUN set -eux; \
    install -d -m 0755 /etc/apt/keyrings; \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${SDK_NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --shell /bin/bash builder \
    && install -d -o builder -g builder /workspace

FROM sdk-base AS bootstrap

ARG SDK_ARCHIVE
ARG SDK_ROOT

COPY teltonika/downloads/${SDK_ARCHIVE} /tmp/sdk.tar.gz
COPY openwrt /tmp/openwrt

RUN set -eux; \
    mkdir -p /opt; \
    tar -xzf /tmp/sdk.tar.gz -C /opt; \
    test -d "/opt/${SDK_ROOT}"; \
    mv "/opt/${SDK_ROOT}" "$TELTONIKA_SDK_DIR"; \
    mv /tmp/openwrt "$TELTONIKA_SDK_DIR/package/open-modbusgateway"; \
    rm /tmp/sdk.tar.gz; \
    chown -R builder:builder "$TELTONIKA_SDK_DIR"

USER builder

RUN set -eux; \
    cd "$TELTONIKA_SDK_DIR"; \
    ./scripts/feeds update -a; \
    find feeds -type d -name .git -print | sort | while IFS= read -r git_dir; do \
        repo=${git_dir%/.git}; \
        printf '%s %s\n' "$repo" "$(git -C "$repo" rev-parse HEAD)"; \
    done > feeds.lock; \
    printf '%s\n' 'CONFIG_PACKAGE_open-modbusgateway=m' >> .config; \
    make defconfig

RUN cd "$TELTONIKA_SDK_DIR" \
    && make tools/install -j"$(nproc)" V=sc

RUN cd "$TELTONIKA_SDK_DIR" \
    && make toolchain/install -j"$(nproc)" \
    && make package/libs/toolchain/compile -j"$(nproc)"

FROM bootstrap AS compiler-sdk

RUN cd "$TELTONIKA_SDK_DIR" \
    && rm -rf dl logs build_dir \
    && rm -rf staging_dir/host/opt staging_dir/toolchain-*/initial \
    && tar -C "$TELTONIKA_SDK_DIR" -cf /tmp/compiler-sdk.tar \
        .config Config.in Makefile rules.mk version ipk_packages.json \
        feeds.conf.default feeds.lock \
        include package target toolchain tools scripts feeds staging_dir tmp

FROM sdk-base AS compiler

ARG SDK_VERSION
ARG SDK_TARGET

RUN --mount=type=bind,from=compiler-sdk,source=/tmp/compiler-sdk.tar,target=/tmp/compiler-sdk.tar,readonly \
    set -eux; \
    mkdir -p "$TELTONIKA_SDK_DIR"; \
    tar -xf /tmp/compiler-sdk.tar -C "$TELTONIKA_SDK_DIR"; \
    chown -R builder:builder "$TELTONIKA_SDK_DIR"

USER builder

LABEL org.opencontainers.image.title="Open Modbus Gateway Teltonika SDK" \
      org.opencontainers.image.description="Prepared Teltonika SDK toolchain; private build infrastructure" \
      org.opencontainers.image.source="https://github.com/ganehag/open-modbusgateway" \
      org.opencontainers.image.vendor="ganehag" \
      org.opencontainers.image.version="${SDK_VERSION}" \
      org.opencontainers.image.ref.name="${SDK_TARGET}"

WORKDIR /workspace
CMD ["/bin/bash"]

FROM bootstrap AS packager

ARG SDK_VERSION
ARG SDK_TARGET

LABEL org.opencontainers.image.title="Open Modbus Gateway Teltonika SDK packager" \
      org.opencontainers.image.description="Prepared Teltonika SDK with package-build state; private build infrastructure" \
      org.opencontainers.image.source="https://github.com/ganehag/open-modbusgateway" \
      org.opencontainers.image.vendor="ganehag" \
      org.opencontainers.image.version="${SDK_VERSION}" \
      org.opencontainers.image.ref.name="${SDK_TARGET}"

WORKDIR /workspace
CMD ["/bin/bash"]
