FROM debian:bookworm-slim AS builder

RUN apt-get update -y \
  && apt-get install -y ca-certificates curl git gnupg gosu python3 wget build-essential cmake pkg-config libevent-dev libboost-dev libsqlite3-dev libzmq3-dev libminiupnpc-dev libnatpmp-dev qtbase5-dev qttools5-dev qttools5-dev-tools \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /src

# Copy source files
COPY . .

# Remove any existing build directory
RUN rm -rf build/

# Run CMake to configure the build (adjust flags if your Litecoin fork uses different options)
RUN cmake -S . -B build \
        -DWITH_ZMQ=ON \
        -DBUILD_TESTS=OFF \
        -DBUILD_UTIL:BOOL=OFF \
        -DBUILD_TX:BOOL=OFF \
        -DBUILD_WALLET_TOOL=OFF

# Build the project
RUN cmake --build build -j

# Second stage
FROM debian:bookworm-slim

ARG UID=101
ARG GID=101

ARG TARGETPLATFORM

ENV LITECOIN_DATA=/home/litecoin/.litecoin
ENV PATH=/opt/litecoin/bin:$PATH

RUN groupadd --gid ${GID} litecoin \
  && useradd --create-home --no-log-init -u ${UID} -g ${GID} litecoin \
  && apt-get update -y \
  && apt-get --no-install-recommends -y install jq curl gnupg gosu ca-certificates pkg-config libevent-dev libboost-dev libsqlite3-dev libzmq3-dev libminiupnpc-dev libnatpmp-dev qtbase5-dev qttools5-dev qttools5-dev-tools \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Litecoin Core binaries built in the first stage
COPY --from=builder /src/build/src/litecoind /opt/litecoin/bin/litecoind
COPY --from=builder /src/build/src/litecoin-cli /opt/litecoin/bin/litecoin-cli

COPY --chmod=755 entrypoint.sh /entrypoint.sh

VOLUME ["/home/litecoin/.litecoin"]

# P2P network (mainnet, testnet & regtest respectively)
EXPOSE 9333 19333 19444

# RPC interface (mainnet & testnet/regtest respectively)
EXPOSE 9332 19332

# ZMQ ports (for transactions & blocks respectively – configurable in litecoin.conf)
EXPOSE 28332 28333

HEALTHCHECK --interval=300s --start-period=60s --start-interval=10s --timeout=20s \
  CMD gosu litecoin litecoin-cli -rpcwait -getinfo || exit 1

ENTRYPOINT ["/entrypoint.sh"]

# Verify we actually built Litecoin Core
RUN litecoind -version | grep "Litecoin Core version"

CMD ["litecoind"]
