/**
 * Blocking the webcam and microphone.
 *
 * Linux: the camera and sound devices live under /dev. Blocking removes access
 * to those device nodes (an elevated chmod, so apps can't open them); allowing
 * restores the usual group-readable mode. No driver — just file permissions,
 * which udev would otherwise manage.
 *
 * Windows: the OS has a per-capability privacy switch in the registry
 * (ConsentStore, under HKCU so no administrator rights are needed); we flip it
 * to Deny or Allow with reg.exe.
 *
 * macOS has no supported user-space way to force this off, so it reports
 * unsupported and the interface explains that (graceful degradation).
 */
import { readdir, stat } from "node:fs/promises";

export type Device = "camera" | "microphone";
export type BlockState = "blocked" | "allowed" | "unknown" | "unsupported";

export function privacyBlockSupported(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "linux" || platform === "win32";
}

// --- Linux ------------------------------------------------------------------------------

/** Camera device nodes (/dev/video*). */
export async function cameraNodes(devDir = "/dev"): Promise<string[]> {
  try {
    return (await readdir(devDir)).filter((n) => /^video\d+$/.test(n)).map((n) => `${devDir}/${n}`);
  } catch {
    return [];
  }
}

/** Sound device nodes (/dev/snd/pcm*c capture devices, plus controls). */
export async function micNodes(sndDir = "/dev/snd"): Promise<string[]> {
  try {
    return (await readdir(sndDir)).filter((n) => /^pcmC\d+D\d+c$/.test(n)).map((n) => `${sndDir}/${n}`);
  } catch {
    return [];
  }
}

/** Build the elevated chmod script that blocks or restores a set of device nodes. */
export function linuxBlockScript(nodes: string[], block: boolean): string {
  if (!nodes.every((n) => /^\/dev\/[\w/]+$/.test(n))) throw new Error("unexpected device path");
  const mode = block ? "0" : "0660";
  const lines = nodes.map((n) => `chmod ${mode} '${n}' 2>/dev/null || true`);
  return ["#!/bin/sh", ...lines, ""].join("\n");
}

/** A device is blocked (on Linux) when its nodes exist but none are group/other readable. */
export async function linuxState(nodes: string[]): Promise<BlockState> {
  if (!nodes.length) return "unknown";
  try {
    let anyReadable = false;
    for (const node of nodes) {
      const mode = (await stat(node)).mode & 0o077;
      if (mode !== 0) anyReadable = true;
    }
    return anyReadable ? "allowed" : "blocked";
  } catch {
    return "unknown";
  }
}

// --- Windows ----------------------------------------------------------------------------

const CONSENT_KEY = (device: Device) =>
  `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\${device === "camera" ? "webcam" : "microphone"}`;

/** reg.exe arguments to set the per-capability privacy switch. */
export function windowsRegSetArgs(device: Device, allow: boolean): string[] {
  return ["add", CONSENT_KEY(device), "/v", "Value", "/t", "REG_SZ", "/d", allow ? "Allow" : "Deny", "/f"];
}

export function windowsRegQueryArgs(device: Device): string[] {
  return ["query", CONSENT_KEY(device), "/v", "Value"];
}

/** Parse `reg query ... /v Value` output into a block state. */
export function parseWindowsConsent(output: string): BlockState {
  const m = /Value\s+REG_SZ\s+(\w+)/i.exec(output);
  if (!m) return "unknown";
  return m[1]!.toLowerCase() === "deny" ? "blocked" : "allowed";
}
