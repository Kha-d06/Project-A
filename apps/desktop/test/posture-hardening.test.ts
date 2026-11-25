import { describe, expect, it } from "vitest";

import { ecryptfsHomes, parseFdesetup, parseFindmntRoot, parseLsblk, parseProcSwaps, parseZfsEncryption } from "../src/engine/encryption";
import { tpmFromSysfs } from "../src/engine/firmware";

import {
  NETWORK_HARDENING,
  networkHardeningCheck,
  parseSshdT,
  sshChecksFrom,
  sshPermissionsCheck,
  sshdGlobalSettings,
  sysctlPath,
} from "../src/engine/posture";

const UBUNTU_MAIN = `# Ubuntu's default sshd_config starts with an include
Include /etc/ssh/sshd_config.d/*.conf
#PermitRootLogin prohibit-password
PasswordAuthentication yes
KbdInteractiveAuthentication no
`;

describe("sshd effective settings", () => {
  it("follows Include drop-ins, and the first value wins (sshd semantics)", async () => {
    const files: Record<string, string[]> = {
      "/etc/ssh/sshd_config.d/*.conf": ["PasswordAuthentication no\nPermitRootLogin no\n", "PasswordAuthentication yes\n"],
    };
    const { settings } = await sshdGlobalSettings(UBUNTU_MAIN, async (p) => files[p] ?? []);
    // The drop-in comes first, so its "no" wins over the main file's later "yes".
    expect(settings.get("passwordauthentication")).toBe("no");
    expect(settings.get("permitrootlogin")).toBe("no");
    expect(sshChecksFrom(settings, "config files").map((c) => [c.id, c.status])).toEqual([
      ["ssh-root", "pass"],
      ["ssh-passwords", "pass"],
      ["ssh-empty-passwords", "pass"],
    ]);
  });

  it("ignores settings inside Match blocks: they apply to some connections only", async () => {
    const config = "PasswordAuthentication no\nMatch User backup\n  PermitRootLogin yes\n  PasswordAuthentication yes\n";
    const { settings, matched } = await sshdGlobalSettings(config);
    expect(matched).toBe(true);
    expect(settings.has("permitrootlogin")).toBe(false);
    expect(settings.get("passwordauthentication")).toBe("no");
  });

  it("resolves relative includes under /etc/ssh, stops runaway nesting, handles key=value", async () => {
    const seen: string[] = [];
    const loop = async (p: string) => {
      seen.push(p);
      return ["Include loop.conf\n"];
    };
    await sshdGlobalSettings("Include loop.conf", loop);
    expect(seen[0]).toBe("/etc/ssh/loop.conf");
    expect(seen.length).toBe(8);
    expect((await sshdGlobalSettings("PermitEmptyPasswords=yes")).settings.get("permitemptypasswords")).toBe("yes");
  });

  it("reads sshd -T output when it is available", () => {
    const settings = parseSshdT("port 22\npermitrootlogin yes\npasswordauthentication no\npermitemptypasswords yes\n");
    const checks = sshChecksFrom(settings, "sshd -T");
    expect(checks.map((c) => c.status)).toEqual(["fail", "pass", "fail"]);
    expect(checks[0]!.detail).toBe("PermitRootLogin yes (sshd -T)");
  });
});

describe("network protections (sysctl)", () => {
  const good = Object.fromEntries(NETWORK_HARDENING.map((k) => [k.key, k.want]));

  it("passes a hardened desktop and names each weak setting with its fix", () => {
    expect(networkHardeningCheck(good, false).status).toBe("pass");
    const weak = networkHardeningCheck({ ...good, "net.ipv4.conf.all.accept_redirects": 1, "net.ipv4.tcp_syncookies": 0 }, false);
    expect(weak.status).toBe("warn");
    expect(weak.detail).toContain("net.ipv4.conf.all.accept_redirects = 1");
    expect(weak.fix).toContain("net.ipv4.tcp_syncookies = 1");
    const many = Object.fromEntries(NETWORK_HARDENING.map((k) => [k.key, k.want === 0 ? 1 : 0]));
    expect(networkHardeningCheck(many, false).status).toBe("fail");
  });

  it("skips router-only settings on a machine that forwards packets (Docker, VMs)", () => {
    const routerLike = { ...good, "net.ipv4.conf.all.send_redirects": 1, "net.ipv4.conf.all.rp_filter": 0 };
    expect(networkHardeningCheck(routerLike, false).status).toBe("warn");
    expect(networkHardeningCheck(routerLike, true).status).toBe("pass");
  });

  it("is unknown when nothing can be read, and maps keys to /proc/sys", () => {
    expect(networkHardeningCheck({}, false).status).toBe("unknown");
    expect(sysctlPath("net.ipv4.conf.all.rp_filter")).toBe("/proc/sys/net/ipv4/conf/all/rp_filter");
  });
});

describe("~/.ssh permissions", () => {
  const me = 1000;
  const folder = { name: ".ssh", mode: 0o40700, uid: me, isDir: true };
  const file = (name: string, mode: number, uid = me) => ({ name, mode: 0o100000 | mode, uid, isDir: false });

  it("passes private keys, a private folder, and public files", () => {
    const check = sshPermissionsCheck(folder, [file("id_ed25519", 0o600), file("id_ed25519.pub", 0o644), file("known_hosts", 0o644), file("authorized_keys", 0o644)], me);
    expect(check.status).toBe("pass");
  });

  it("fails readable private keys, writable authorized_keys and files owned by others", () => {
    const readable = sshPermissionsCheck(folder, [file("id_rsa", 0o644)], me);
    expect(readable.status).toBe("fail");
    expect(readable.fix).toBe("chmod 600 ~/.ssh/id_rsa");
    expect(sshPermissionsCheck(folder, [file("authorized_keys", 0o666)], me).status).toBe("fail");
    expect(sshPermissionsCheck(folder, [file("id_rsa", 0o600, 0)], me).status).toBe("fail");
  });

  it("warns about an open folder, and passes when there is none", () => {
    const open = sshPermissionsCheck({ ...folder, mode: 0o40755 }, [file("id_ed25519", 0o600)], me);
    expect(open.status).toBe("warn");
    expect(open.fix).toBe("chmod 700 ~/.ssh");
    expect(sshPermissionsCheck(null, [], me).status).toBe("pass");
  });
});

describe("disk encryption edge cases (osquery-style)", () => {
  const luksRoot = (extra: object[] = []) =>
    JSON.stringify({
      blockdevices: [
        {
          name: "nvme0n1",
          type: "disk",
          children: [
            { name: "nvme0n1p1", type: "part", fstype: "vfat", mountpoints: ["/boot/efi"] },
            { name: "nvme0n1p2", type: "part", fstype: "crypto_LUKS", children: [{ name: "cryptroot", type: "crypt", fstype: "btrfs", mountpoints: ["/", "/home"] }] },
            ...extra,
          ],
        },
      ],
    });

  it("treats plain swap next to an encrypted root as partial", () => {
    expect(parseLsblk(luksRoot()).state).toBe("on");
    const leaky = parseLsblk(luksRoot([{ name: "nvme0n1p3", type: "part", fstype: "swap", mountpoints: ["[SWAP]"] }]));
    expect(leaky.state).toBe("partial");
    expect(leaky.detail).toContain("nvme0n1p3");
    // Swap inside dm-crypt, or zram in memory, is fine.
    expect(parseLsblk(luksRoot([{ name: "nvme0n1p3", type: "part", children: [{ name: "cryptswap", type: "crypt", fstype: "swap", mountpoints: ["[SWAP]"] }] }])).state).toBe("on");
    const zram = JSON.parse(luksRoot()) as { blockdevices: object[] };
    zram.blockdevices.push({ name: "zram0", type: "disk", fstype: "swap", mountpoints: ["[SWAP]"] });
    expect(parseLsblk(JSON.stringify(zram)).state).toBe("on");
    expect(parseProcSwaps("Filename Type Size Used Priority\n/swap.img file 2097148 0 -2\n/dev/zram0 partition 8000000 0 100\n")).toEqual(["/swap.img"]);
  });

  it("reads ZFS native encryption for roots lsblk can't see", () => {
    expect(parseFindmntRoot("zfs rpool/ROOT/ubuntu\n")).toEqual({ fstype: "zfs", source: "rpool/ROOT/ubuntu" });
    expect(parseZfsEncryption("aes-256-gcm\n", "rpool/ROOT/ubuntu").state).toBe("on");
    expect(parseZfsEncryption("off\n", "rpool/ROOT/ubuntu").state).toBe("off");
    expect(parseZfsEncryption("", "x").state).toBe("unknown");
  });

  it("notices eCryptfs home folders on a plain system disk", () => {
    expect(ecryptfsHomes("/dev/sda1 / ext4 rw 0 0\n/home/sam/.Private /home/sam ecryptfs rw 0 0\n")).toEqual(["/home/sam"]);
  });

  it("reads FileVault's in-between states and explains Apple silicon", () => {
    expect(parseFdesetup("FileVault is Off, but will be enabled after the next restart.").state).toBe("partial");
    expect(parseFdesetup("FileVault is On.\nDecryption in progress: Percent completed = 40").state).toBe("partial");
    expect(parseFdesetup("FileVault is On.").state).toBe("on");
    const off = parseFdesetup("FileVault is Off.", true);
    expect(off.state).toBe("off");
    expect(off.detail).toContain("hardware-encrypted");
  });

  it("never reports 'no TPM' when tpm0 exists but the kernel has no version file", () => {
    expect(tpmFromSysfs(null, true, true, "Manufacturer: 0x49465800\nTCG version: 1.2\n")).toBe("tpm1");
    expect(tpmFromSysfs(null, true, true, null)).toBe("unknown");
    expect(tpmFromSysfs(null, true, false, null)).toBe("none");
    expect(tpmFromSysfs("2\n", true, true)).toBe("tpm2");
  });
});
