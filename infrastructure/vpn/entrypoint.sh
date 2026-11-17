#!/bin/sh
# Brings up wg0 with this server's key, sets up NAT and isolation, then hands
# over to sync.sh, which keeps the list of allowed devices in step with SENTINEL.
set -eu

: "${SENTINEL_API_URL:?SENTINEL_API_URL is required}"
if [ "${#VPN_SYNC_TOKEN}" -lt 32 ]; then
  echo "Set SENTINEL_VPN_SYNC_TOKEN (at least 32 characters) in .env" >&2
  exit 1
fi
SUBNET="${VPN_SUBNET:-10.13.13.0/24}"
PORT="${VPN_PORT:-51820}"

umask 077
mkdir -p /data
# The server's private key is created once and kept in the volume.
[ -s /data/server.key ] || wg genkey > /data/server.key

# The server takes the first address of the subnet; SENTINEL hands out the rest.
NETWORK="${SUBNET%/*}"
PREFIX="${SUBNET#*/}"
ADDRESS="${NETWORK%.*}.$(( ${NETWORK##*.} + 1 ))"

if ! ip link add wg0 type wireguard 2>/dev/null; then
  echo "No WireGuard in this kernel; using wireguard-go." >&2
  wireguard-go wg0
fi
wg set wg0 listen-port "$PORT" private-key /data/server.key
ip address add "$ADDRESS/$PREFIX" dev wg0
ip link set mtu 1420 up dev wg0

OUT="$(ip route show default | awk '{print $5; exit}')"
iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$OUT" -j MASQUERADE
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Devices on the VPN reach the internet only: not each other, not this host,
# and not the private networks around it (the other SENTINEL containers included).
iptables -P FORWARD DROP
iptables -A FORWARD -i "$OUT" -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wg0 -o wg0 -j DROP
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8 224.0.0.0/4; do
  iptables -A FORWARD -i wg0 -d "$net" -j DROP
done
iptables -A FORWARD -i wg0 -o "$OUT" -j ACCEPT
iptables -A INPUT -i wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i wg0 -j DROP
# The tunnel carries no IPv6. Clients route ::/0 into it, so IPv6 is dropped rather than leaking.
ip6tables -A FORWARD -i wg0 -j DROP 2>/dev/null || true

echo "WireGuard listening on UDP $PORT, server address $ADDRESS, public key $(wg pubkey < /data/server.key)"
exec /usr/local/bin/sync.sh
