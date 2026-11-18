/**
 * Windows Controlled Folder Access (ransomware protection built into Windows
 * Defender). This is a user-space integration: we read and change it through
 * Defender's own PowerShell cmdlets — no driver, no kernel code. Turning it on
 * or changing its folders needs administrator rights, so those run through an
 * elevated PowerShell (the UAC prompt); reading its state does not.
 *
 * Linux and macOS have no equivalent, so the capability reports unsupported and
 * the interface shows why (graceful degradation).
 */

export type CfaState = "on" | "off" | "audit" | "unknown";

export interface CfaStatus {
  supported: boolean;
  state: CfaState;
  /** Folders Windows is guarding beyond its always-on defaults. */
  folders: string[];
  /** Apps the person has allowed to write to guarded folders. */
  allowedApps: string[];
}

/** Map the numeric EnableControlledFolderAccess value Defender reports. */
export function cfaStateFromValue(value: unknown): CfaState {
  // 0 = Disabled, 1 = Enabled (block), 2 = Audit mode.
  if (value === 1 || value === "1" || value === "Enabled") return "on";
  if (value === 2 || value === "2" || value === "AuditMode") return "audit";
  if (value === 0 || value === "0" || value === "Disabled") return "off";
  return "unknown";
}

/** Parse `Get-MpPreference | ConvertTo-Json` output into a status. */
export function parseMpPreference(json: string): CfaStatus {
  try {
    const data = JSON.parse(json) as Record<string, unknown>;
    const asList = (value: unknown): string[] =>
      Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : typeof value === "string" && value ? [value] : [];
    return {
      supported: true,
      state: cfaStateFromValue(data.EnableControlledFolderAccess),
      folders: asList(data.ControlledFolderAccessProtectedFolders),
      allowedApps: asList(data.ControlledFolderAccessAllowedApplications),
    };
  } catch {
    return { supported: true, state: "unknown", folders: [], allowedApps: [] };
  }
}

export function onlySupportedOnWindows(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "win32";
}

const READ_SCRIPT =
  "Get-MpPreference | Select-Object EnableControlledFolderAccess,ControlledFolderAccessProtectedFolders,ControlledFolderAccessAllowedApplications | ConvertTo-Json -Compress";

export async function cfaStatus(platform: NodeJS.Platform = process.platform, run = runPowershell): Promise<CfaStatus> {
  if (!onlySupportedOnWindows(platform)) return { supported: false, state: "unknown", folders: [], allowedApps: [] };
  try {
    return parseMpPreference(await run(READ_SCRIPT));
  } catch {
    return { supported: true, state: "unknown", folders: [], allowedApps: [] };
  }
}

/** A single quoted path argument for a PowerShell command (defends the quoting). */
function psQuote(path: string): string {
  return `'${path.replace(/'/g, "''")}'`;
}

/**
 * The elevated PowerShell script to apply a change. It is run once through a
 * UAC prompt (Start-Process -Verb RunAs) so the person sees exactly what elevates.
 */
export function cfaApplyScript(action: "enable" | "disable" | "audit" | "add-folder" | "allow-app", path?: string): string {
  switch (action) {
    case "enable":
      return "Set-MpPreference -EnableControlledFolderAccess Enabled";
    case "disable":
      return "Set-MpPreference -EnableControlledFolderAccess Disabled";
    case "audit":
      return "Set-MpPreference -EnableControlledFolderAccess AuditMode";
    case "add-folder":
      if (!path) throw new Error("a folder is required");
      return `Add-MpPreference -ControlledFolderAccessProtectedFolders ${psQuote(path)}`;
    case "allow-app":
      if (!path) throw new Error("an application is required");
      return `Add-MpPreference -ControlledFolderAccessAllowedApplications ${psQuote(path)}`;
  }
}

function runPowershell(script: string): Promise<string> {
  return new Promise((resolve, reject) => {
    import("node:child_process").then(({ execFile }) => {
      execFile(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", script],
        { timeout: 20_000, windowsHide: true, maxBuffer: 2 * 1024 * 1024 },
        (error, stdout) => (error && !stdout ? reject(error) : resolve(String(stdout))),
      );
    });
  });
}

/** Run an elevated change via a UAC prompt. */
export async function cfaApply(action: Parameters<typeof cfaApplyScript>[0], path?: string, run = runElevated): Promise<void> {
  await run(cfaApplyScript(action, path));
}

function runElevated(innerScript: string): Promise<void> {
  // Start-Process -Verb RunAs raises the UAC prompt, then runs the inner command elevated.
  const wrapped = `Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-Command',${JSON.stringify(innerScript)} -Wait`;
  return new Promise((resolve, reject) => {
    import("node:child_process").then(({ execFile }) => {
      execFile("powershell.exe", ["-NoProfile", "-Command", wrapped], { timeout: 120_000, windowsHide: true }, (error) =>
        error ? reject(error) : resolve(),
      );
    });
  });
}
