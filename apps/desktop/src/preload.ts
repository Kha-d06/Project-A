/** The only functions the interface can call. No Node.js reaches the page. */
import { contextBridge, ipcRenderer, webUtils } from "electron";

const api = {
  status: () => ipcRenderer.invoke("status"),
  history: () => ipcRenderer.invoke("history"),
  choose: (kind: "files" | "folder") => ipcRenderer.invoke("choose", kind),
  scan: (paths: string[]) => ipcRenderer.invoke("scan", paths),
  quickScan: () => ipcRenderer.invoke("quick-scan"),
  quarantineList: () => ipcRenderer.invoke("quarantine-list"),
  quarantineAdd: (path: string) => ipcRenderer.invoke("quarantine-add", path),
  quarantineRestore: (id: string) => ipcRenderer.invoke("quarantine-restore", id),
  quarantineDelete: (id: string) => ipcRenderer.invoke("quarantine-delete", id),
  updateSignatures: () => ipcRenderer.invoke("update-signatures"),
  fullScan: (path: string) => ipcRenderer.invoke("full-scan", path),
  settings: (changes: Record<string, unknown>) => ipcRenderer.invoke("settings", changes),
  addWatchFolder: () => ipcRenderer.invoke("add-watch-folder"),
  addProtectedFolder: () => ipcRenderer.invoke("add-protected-folder"),
  wifi: () => ipcRenderer.invoke("wifi"),
  updates: () => ipcRenderer.invoke("updates"),
  updateCheck: () => ipcRenderer.invoke("update-check"),
  updateInstall: () => ipcRenderer.invoke("update-install"),
  securityCheck: () => ipcRenderer.invoke("security-check"),
  processCheck: () => ipcRenderer.invoke("process-check"),
  historyCheck: (days: number) => ipcRenderer.invoke("history-check", days),
  historyLast: () => ipcRenderer.invoke("history-last"),
  monitorStart: () => ipcRenderer.invoke("monitor-start"),
  monitorStop: () => ipcRenderer.invoke("monitor-stop"),
  monitorConnections: () => ipcRenderer.invoke("monitor-connections"),
  monitorServices: () => ipcRenderer.invoke("monitor-services"),
  monitorEvents: (minutes: number) => ipcRenderer.invoke("monitor-events", minutes),
  monitorServiceControl: (name: string, action: "start" | "stop" | "restart") => ipcRenderer.invoke("monitor-service-control", name, action),
  vpnStatus: () => ipcRenderer.invoke("vpn-status"),
  vpnSetup: () => ipcRenderer.invoke("vpn-setup"),
  vpnConnect: () => ipcRenderer.invoke("vpn-connect"),
  vpnDisconnect: () => ipcRenderer.invoke("vpn-disconnect"),
  vpnShowFile: () => ipcRenderer.invoke("vpn-show-file"),
  startupAcknowledge: () => ipcRenderer.invoke("startup-acknowledge"),
  scanProgram: (id: string) => ipcRenderer.invoke("scan-program", id),
  backupAddFolder: () => ipcRenderer.invoke("backup-add-folder"),
  backupRemoveFolder: (path: string) => ipcRenderer.invoke("backup-remove-folder", path),
  backupDestination: () => ipcRenderer.invoke("backup-destination"),
  backupPassword: (password: string | null) => ipcRenderer.invoke("backup-password", password),
  backupRun: () => ipcRenderer.invoke("backup-run"),
  backupOpen: (mode: "verify" | "restore", password: string) => ipcRenderer.invoke("backup-open", mode, password),
  accountLink: (code: string) => ipcRenderer.invoke("account-link", code),
  accountUnlink: () => ipcRenderer.invoke("account-unlink"),
  pathOf: (file: File) => webUtils.getPathForFile(file),
  on: (channel: "scan-result" | "scan-progress" | "ransomware-alert" | "remote-activity" | "device-use" | "backup-progress" | "schedule-ran" | "update-state" | "monitor-sample" | "monitor-event", listener: (payload: unknown) => void) => {
    const wrapped = (_event: unknown, payload: unknown) => listener(payload);
    ipcRenderer.on(channel, wrapped);
    return () => ipcRenderer.removeListener(channel, wrapped);
  },
};

contextBridge.exposeInMainWorld("sentinel", api);
export type SentinelApi = typeof api;
