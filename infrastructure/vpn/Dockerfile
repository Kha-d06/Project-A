# WireGuard server for Qalaa's optional VPN (docker compose --profile vpn).
# Uses the kernel's WireGuard when the host has it (Linux 5.6+), and wireguard-go
# in user space otherwise.

# Alpine no longer packages wireguard-go, so build it (pinned) as a static binary.
FROM golang:1.24.7-alpine AS wireguard-go
RUN CGO_ENABLED=0 GOBIN=/out go install -trimpath -ldflags="-s -w" \
      golang.zx2c4.com/wireguard@v0.0.0-20261024220952-b3bc704ef0ee \
 && mv /out/wireguard /out/wireguard-go

FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iptables ip6tables iproute2 curl jq
COPY --from=wireguard-go /out/wireguard-go /usr/local/bin/wireguard-go
COPY entrypoint.sh sync.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/sync.sh
VOLUME /data
EXPOSE 51820/udp
HEALTHCHECK --interval=30s --timeout=5s CMD wg show wg0 >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
