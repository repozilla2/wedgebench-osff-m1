FROM ubuntu:24.04

# No version pinning — ensures compatibility across x86 and ARM (Apple Silicon)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    python3 \
    python3-pip \
    make \
    git \
    && rm -rf /var/lib/apt/lists/*

# Accept git SHA at build time — avoids copying .git into the image
ARG GIT_SHA=untracked
ENV SENTINEL_GIT_SHA=${GIT_SHA}

WORKDIR /sentinel

COPY . .

RUN chmod +x run_m1.sh

# Volume for evidence output
VOLUME ["/sentinel/evidence"]

CMD ["./run_m1.sh"]
