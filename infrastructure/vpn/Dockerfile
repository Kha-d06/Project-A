# WireGuard server for Qalaa's optional VPN (docker compose --profile vpn).
# Uses the kernel's WireGuard when the host has it (Linux 5.6+), and wireguard-go
# in user space otherwise.
FROM alpine:3.20
RUN apk add --no-cache wireguard-tools wireguard-go iptables ip6tables iproute2 curl jq
COPY entrypoint.sh sync.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/sync.sh
VOLUME /data
EXPOSE 51820/udp
HEALTHCHECK --interval=30s --timeout=5s CMD wg show wg0 >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
