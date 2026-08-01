FROM golang:1.20.14-bookworm@sha256:9fa9101141c01e9440216d32eb2b380b3c3079bea07aeab3546020cc91b3662c AS builder

ARG NORN_COMMIT=a7be734ac2e829e2076d06d45719d2716abd3d72
WORKDIR /src
RUN git init \
    && git remote add origin https://github.com/Chain-Lab/go-norn.git \
    && git fetch --depth 1 origin "${NORN_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${NORN_COMMIT}"
RUN go mod download
COPY patches /tmp/norn-patches
RUN git apply --check /tmp/norn-patches/0001-rpc-dynamic-data-writer.patch \
    && git apply /tmp/norn-patches/0001-rpc-dynamic-data-writer.patch \
    && go test ./utils
COPY publisher/main.go /src/cmd/ri-local-publisher/main.go
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/norn ./cmd/norn \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/norn-generate ./cmd/generate \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
        -o /out/norn-local-publisher ./cmd/ri-local-publisher

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
ARG NORN_COMMIT=a7be734ac2e829e2076d06d45719d2716abd3d72
LABEL org.opencontainers.image.source="https://github.com/Chain-Lab/go-norn" \
      org.opencontainers.image.revision="${NORN_COMMIT}"
COPY --from=builder /out/norn /usr/local/bin/norn
COPY --from=builder /out/norn-generate /usr/local/bin/norn-generate
COPY --from=builder /out/norn-local-publisher /usr/local/bin/norn-local-publisher
RUN useradd --system --uid 10003 --create-home --home-dir /var/lib/norn norn
USER norn
WORKDIR /var/lib/norn
