/**
 * A small, bundled subset of the IEEE OUI list: enough to name common home
 * devices (routers, phones, consoles, cameras, smart-home hubs) from the first
 * three bytes of their MAC address. Not exhaustive by design — an unknown
 * prefix simply yields no vendor, never a wrong guess.
 */
const OUI: Record<string, string> = {
  "fcfbfb": "Cisco",
  "001018": "Broadcom",
  "0050f2": "Microsoft",
  "b827eb": "Raspberry Pi",
  "dca632": "Raspberry Pi",
  "e45f01": "Raspberry Pi",
  "001a11": "Google",
  "f4f5e8": "Google",
  "3c5ab4": "Google",
  "d8eb46": "Google",
  "a4cf12": "Espressif (IoT)",
  "7cdfa1": "Espressif (IoT)",
  "2462ab": "Espressif (IoT)",
  "ecfabc": "Espressif (IoT)",
  "001788": "Philips Hue",
  "0017880": "Philips Hue",
  "ac63be": "Amazon",
  "fc65de": "Amazon",
  "68375a": "Amazon",
  "44650d": "Amazon",
  "f0272d": "Amazon",
  "000c43": "Ralink/MediaTek",
  "0018e7": "Cameo (cameras)",
  "00408c": "Axis (cameras)",
  "accc8e": "Axis (cameras)",
  "bcad28": "Hangzhou Hikvision",
  "4c11bf": "Hangzhou Hikvision",
  "c056e3": "Hangzhou Hikvision",
  "e0508b": "Zhejiang Dahua",
  "3c1f9": "Zhejiang Dahua",
  "001c14": "VMware",
  "005056": "VMware",
  "080027": "VirtualBox",
  "52540": "QEMU/KVM",
  "d85ed3": "TP-Link",
  "50c7bf": "TP-Link",
  "0c80631": "TP-Link",
  "a42bb0": "TP-Link",
  "001374": "Netgear",
  "9cd36d": "Netgear",
  "204e7f": "Netgear",
  "c0ffd4": "ASUS",
  "2c56dc": "ASUS",
  "88d7f6": "ASUS",
  "001a2b": "AVM (FRITZ!Box)",
  "3810d5": "AVM (FRITZ!Box)",
  "c80e14": "D-Link",
  "001346": "D-Link",
  "ccb255": "D-Link",
  "000e58": "Sonos",
  "b8e937": "Sonos",
  "5ccf7f": "Apple",
  "a85c2c": "Apple",
  "f0b479": "Apple",
  "dc2b2a": "Apple",
  " acde48": "Apple",
  "001451": "Apple",
  "e0acf1": "Samsung",
  "f008f1": "Samsung",
  "5401fd": "Samsung",
  "0017c9": "Samsung",
  "bc8385": "Microsoft Xbox",
  "7845c4": "Sony PlayStation",
  "00041f": "Sony PlayStation",
  "e84e06": "Edimax",
  "744401": "Ubiquiti",
  "fcecda": "Ubiquiti",
  "245a4c": "Ubiquiti",
};

/** Resolve a MAC address to a vendor, or null when the prefix isn't bundled. */
export function vendorOf(mac: string | null): string | null {
  if (!mac) return null;
  const hex = mac.toLowerCase().replace(/[^0-9a-f]/g, "");
  if (hex.length < 6) return null;
  // Try the longer (more specific) prefixes first, then the 3-byte OUI.
  for (const len of [7, 6]) {
    const hit = OUI[hex.slice(0, len)];
    if (hit) return hit;
  }
  return null;
}

/**
 * Documented factory default logins, used ONLY by the opt-in, per-device
 * credential check. Kept short and vendor-generic. The point is to tell the
 * person "this device still has its factory password", never to break in.
 */
export const DEFAULT_LOGINS: { user: string; pass: string }[] = [
  { user: "admin", pass: "admin" },
  { user: "admin", pass: "password" },
  { user: "admin", pass: "" },
  { user: "admin", pass: "1234" },
  { user: "root", pass: "root" },
  { user: "root", pass: "admin" },
  { user: "user", pass: "user" },
  { user: "", pass: "admin" },
];
