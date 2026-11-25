# The container the Linux atomics run in, with no network (docker run --network none).
# Node runs the Qalaa background service; Python runs the atomics.
FROM node:22-bookworm-slim
RUN apt-get update -q \
    && apt-get install -y -q --no-install-recommends python3 python3-yaml procps iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home atomics
USER atomics
WORKDIR /repo
