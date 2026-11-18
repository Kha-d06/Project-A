/**
 * Local history in SQLite (Node's built-in node:sqlite, so nothing to install):
 * one resource sample a minute, kept for 7 days, and a log of security events
 * (file changes, posture checks, processes ended, services changed). It stays on
 * this computer.
 */
import type { DatabaseSync } from "node:sqlite";

export const RETENTION_DAYS = 7;

export interface HistoryPoint {
  at: string;
  cpu: number;
  memory: number;
  rx: number;
  tx: number;
  read: number;
  write: number;
}

export interface SecurityEvent {
  at: string;
  kind: string;
  level: "info" | "warning" | "alert";
  message: string;
}

export class Telemetry {
  private constructor(private readonly db: DatabaseSync) {}

  static async open(file: string): Promise<Telemetry> {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(file);
    db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS samples (at INTEGER PRIMARY KEY, cpu REAL, memory REAL, rx INTEGER, tx INTEGER, read INTEGER, write INTEGER);
      CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER, kind TEXT, level TEXT, message TEXT);
      CREATE INDEX IF NOT EXISTS events_at ON events(at);
    `);
    return new Telemetry(db);
  }

  record(point: Omit<HistoryPoint, "at">, at = Date.now()): void {
    this.db
      .prepare("INSERT OR REPLACE INTO samples (at, cpu, memory, rx, tx, read, write) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(Math.floor(at / 60_000) * 60_000, point.cpu, point.memory, point.rx, point.tx, point.read, point.write);
  }

  log(kind: string, level: SecurityEvent["level"], message: string, at = Date.now()): void {
    this.db.prepare("INSERT INTO events (at, kind, level, message) VALUES (?, ?, ?, ?)").run(at, kind, level, message.slice(0, 1000));
  }

  /** Averages over buckets so a day fits in ~144 points. */
  history(hours: number, buckets = 144, now = Date.now()): HistoryPoint[] {
    const since = now - hours * 3600_000;
    const size = Math.max(60_000, Math.floor((hours * 3600_000) / buckets / 60_000) * 60_000);
    const rows = this.db
      .prepare(
        `SELECT (at / ?) * ? AS bucket, AVG(cpu) AS cpu, AVG(memory) AS memory, AVG(rx) AS rx, AVG(tx) AS tx, AVG(read) AS read, AVG(write) AS write
         FROM samples WHERE at >= ? GROUP BY bucket ORDER BY bucket`,
      )
      .all(size, size, since) as { bucket: number; cpu: number; memory: number; rx: number; tx: number; read: number; write: number }[];
    return rows.map((r) => ({ at: new Date(Number(r.bucket)).toISOString(), cpu: Math.round(r.cpu * 10) / 10, memory: Math.round(r.memory * 10) / 10, rx: Math.round(r.rx), tx: Math.round(r.tx), read: Math.round(r.read), write: Math.round(r.write) }));
  }

  events(limit = 200): SecurityEvent[] {
    return (this.db.prepare("SELECT at, kind, level, message FROM events ORDER BY at DESC LIMIT ?").all(limit) as { at: number; kind: string; level: SecurityEvent["level"]; message: string }[]).map(
      (r) => ({ at: new Date(Number(r.at)).toISOString(), kind: r.kind, level: r.level, message: r.message }),
    );
  }

  prune(now = Date.now()): void {
    const cutoff = now - RETENTION_DAYS * 86_400_000;
    this.db.prepare("DELETE FROM samples WHERE at < ?").run(cutoff);
    // Security events are kept longer (90 days): they are small and useful for audits.
    this.db.prepare("DELETE FROM events WHERE at < ?").run(now - 90 * 86_400_000);
  }

  close(): void {
    this.db.close();
  }
}
