FROM ubuntu:24.04

# Pinned versions for reproducibility
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc=4:13.2.0-7ubuntu1 \
    python3=3.12.3-0ubuntu2 \
    python3-pip \
    make \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sentinel

COPY . .

RUN chmod +x run_m1.sh

# Volume for evidence output
VOLUME ["/sentinel/evidence"]

CMD ["./run_m1.sh"]
