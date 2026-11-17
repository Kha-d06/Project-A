# Running SENTINEL on your laptop

A full local instance — web app, API, scan workers, database — in Docker, with
an administrator account ready to use.

## 1. Install Docker

- **Windows or macOS:** install **Docker Desktop** from <https://www.docker.com/products/docker-desktop/> and start it.
- **Linux:** install Docker Engine and the Compose plugin (`docker` and `docker compose`).

Check it works: `docker compose version` should print a version.

## 2. Get the code

```bash
git clone https://github.com/Kha-d06/Project-A.git
cd Project-A
git checkout ccr-87e2e2a2-qw0gbw
```

## 3. Start it, with an admin account — one command

```bash
./scripts/demo.sh
```

This builds everything, starts it, loads test data, and creates an
administrator. When it finishes it prints the address and the admin email and
password. The first build downloads images and can take a few minutes.

To choose your own admin email (a random strong password is generated and
printed):

```bash
./scripts/demo.sh you@example.com
```

Or set both:

```bash
ADMIN_PASSWORD='choose-a-strong-one' ./scripts/demo.sh you@example.com
```

**On Windows**, run that in **WSL** or **Git Bash**. If you prefer not to use the
script, do the two steps by hand (see “Manual steps” below).

## 4. Open it

- App: <http://localhost:8080>
- Sign in: <http://localhost:8080/sign-in> with the admin email and password printed by the script.

As an administrator you can reach everything:

| Feature | Where |
| --- | --- |
| Admin console (accounts, feeds, audit) | `/dashboard/admin` |
| **Website security assessment** (new) | `/dashboard/assessment` |
| Devices & remote scanning | `/dashboard/devices` |
| Password manager | `/dashboard/passwords` |
| VPN | `/dashboard/vpn` |
| Family & teams | `/dashboard/groups` |
| Scanners (link, message, file, QR, website, APK, screenshot) | `/dashboard/scan` |

| Download the desktop and Android apps | `/download` |
| Test inbox (every email SENTINEL sends) | <http://localhost:8025> |

The admin account already has the **site assessment** feature enabled. To turn
it on for another account, open **Admin → Accounts** and use the **Site
assessment** toggle in that account's row.

## Install the desktop app from a package

Each CI run uploads a Linux AppImage and .deb (artifact `sentinel-desktop-linux`),
and tagged releases include Windows and macOS installers too. On Linux:

```bash
sudo apt install ./SENTINEL-Desktop-0.2.0-amd64.deb     # Debian, Ubuntu, Mint
sudo dnf install ./SENTINEL-Desktop-0.2.0-x86_64.rpm    # Fedora, openSUSE, RHEL
chmod +x SENTINEL-Desktop-0.2.0-x86_64.AppImage && ./SENTINEL-Desktop-0.2.0-x86_64.AppImage
```

## Run the desktop app on your laptop (from source)

You need Node.js 22 or newer from <https://nodejs.org>. With the website running
(step 3):

```bash
cd apps/desktop
npm ci
npm start
```

In the app:
1. Open **Settings** and set **SENTINEL server** to `http://localhost:8080`, then click **Save**.
2. On the website, open **Devices → Add a device** and copy the code.
3. Back in the app, under **SENTINEL account**, enter the code and click **Link**.
4. To start scans from the website, tick **Allow scans from my SENTINEL account**.

The laptop now appears on the website's **Devices** page, where you can start a
quick, full or folder scan and quarantine anything found. To try the detection
safely, save the EICAR antivirus test file (a harmless standard test string,
from <https://www.eicar.org>) into your Downloads folder.

## What works out of the box, and what needs a key

Everything runs with no external accounts. These optional integrations stay off
until you add a key in `.env` (the file the script created) and restart:

- Live threat feeds beyond the bundled test data, Google Web Risk, VirusTotal, Have I Been Pwned.
- Email is caught by the local test inbox at <http://localhost:8025>. To send real email, set `SENTINEL_SMTP_HOST` and the other `SENTINEL_SMTP_*` settings in `.env`, then `docker compose up -d`.
- AI explanations: `SENTINEL_OPENAI_API_KEY`.
- The VPN server: `docker compose --profile vpn up -d` after setting `SENTINEL_VPN_ENDPOINT` and `SENTINEL_VPN_SYNC_TOKEN` (see `docs/vpn.md`).

The **website security assessment** makes real outbound requests to the domain
you test, so that feature needs internet access and a domain you can add a DNS
record or a file to. Everything else works offline against the bundled test data.

## Stopping and starting

```bash
docker compose down        # stop; your data is kept
docker compose up -d        # start again
docker compose logs -f api  # follow a service's logs
```

To wipe everything and start fresh: `docker compose down -v` (this deletes the
database), then `./scripts/demo.sh` again.

## Manual steps (instead of the script)

```bash
./scripts/up.sh --fixtures
docker compose exec api python -m app.cli create-admin you@example.com 'a-strong-password'
```

`create-admin` creates the account if it does not exist, or promotes an existing
one; either way it becomes an administrator with site assessment enabled.

## Troubleshooting

- **Port 8080 already in use:** set `SENTINEL_SITE_ADDRESS=:9090` in `.env`, then `docker compose up -d`, and use `http://localhost:9090`.
- **`docker compose` not found:** Docker Desktop isn't running, or on older setups the command is `docker-compose`.
- **A service isn't healthy:** `docker compose ps` then `docker compose logs <service>`. The `migrate` service must finish before `api` starts.
- **Reset the admin password:** `docker compose exec api python -m app.cli create-admin you@example.com 'new-password'`.
