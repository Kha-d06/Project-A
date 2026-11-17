# Self-hosted VPN

SENTINEL can run a WireGuard VPN server next to the rest of the stack. Account
holders add their phones and computers on **Dashboard → VPN**, and connect with
the official WireGuard app.

## Turn it on

1. **Open UDP port 51820** on the server's firewall and on any cloud security group.
2. **Set these in `.env`:**
   ```bash
   SENTINEL_VPN_ENDPOINT=vpn.your-domain.example:51820   # what devices connect to
   SENTINEL_VPN_SYNC_TOKEN=<at least 32 random characters>   # ./scripts/up.sh creates one
   ```
   **Optional settings:**
   - `SENTINEL_VPN_PORT`: default 51820.
   - `SENTINEL_VPN_SUBNET`: default `10.13.13.0/24`, which allows 253 devices.
   - `SENTINEL_VPN_DNS`: default `1.1.1.1`. It must be a public resolver, because devices cannot reach private addresses through the VPN.
3. **Start it:** `docker compose --profile vpn up -d`. This restarts the API so it picks up the endpoint.
4. **Check it:**
   - `docker compose logs vpn` prints the server's public key.
   - Dashboard → VPN shows "The VPN server is running".

The host needs `/dev/net/tun`. It uses the kernel's WireGuard (Linux 5.6+) when
available, and `wireguard-go` otherwise.

## How it works

- **Keys:**
  - Each device's key pair is made in the person's browser (WebCrypto X25519).
  - The private key goes straight into the QR code or `.conf` file and is never sent to SENTINEL.
  - The server stores only public keys.
  - The server's own private key is created on first start in the `vpn-data` volume.
- **Sync:**
  - Every 10 seconds, the `vpn` container sends SENTINEL its public key and each device's last handshake and traffic, using `SENTINEL_VPN_SYNC_TOKEN`.
  - In reply it receives the list of allowed devices and applies it with `wg syncconf`, which does not drop existing sessions.
  - If SENTINEL is unreachable, the current list stays in force.
  - Removing a device on the website disconnects it within about 10 seconds.
  - A server that has not checked in for 2 minutes shows as offline.
- **Routing:**
  - Devices send all traffic through the tunnel (`AllowedIPs = 0.0.0.0/0, ::/0`).
  - The tunnel carries no IPv6. IPv6 is routed into it and dropped, so it cannot leak around the VPN.
- **Isolation:**
  - Devices can reach the internet only.
  - They cannot reach each other, the VPN container itself, or private and link-local ranges. That covers the Compose network with PostgreSQL and Redis, and the server's LAN.

## What it is, and is not

**What it does:**
- Protects people on untrusted Wi-Fi from snooping and tampering.
- Hides their home address from the sites they visit.

**What it does not do:**
- Make anyone anonymous. As the operator you can see which addresses devices connect to, just as an ISP can.
- Change any laws that apply to you about operating a VPN. Say so in your terms if you open it to the public.

**Limits:**
- Each account can add `SENTINEL_VPN_MAX_PEERS_PER_USER` devices (default 5).
- Bandwidth is whatever your server has. There is no per-user traffic limit, so watch `docker stats vpn` on a small machine.

## Removing it

Run `docker compose --profile vpn down vpn`, then clear `SENTINEL_VPN_ENDPOINT`.
Device records stay until the account holders remove them or their accounts are deleted.
