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
  pathOf: (file: File) => webUtils.getPathForFile(file),
  on: (channel: "scan-result" | "scan-progress" | "ransomware-alert", listener: (payload: unknown) => void) => {
    const wrapped = (_event: unknown, payload: unknown) => listener(payload);
    ipcRenderer.on(channel, wrapped);
    return () => ipcRenderer.removeListener(channel, wrapped);
  },
};

contextBridge.exposeInMainWorld("sentinel", api);
export type SentinelApi = typeof api;
