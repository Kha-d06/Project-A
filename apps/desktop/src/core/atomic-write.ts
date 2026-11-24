/**
 * Writes a file atomically (temp file, then rename), one write at a time per
 * file, so overlapping saves (a check and a click at the same moment) can't
 * race on the temp file or land out of order.
 */
import { rename, writeFile } from "node:fs/promises";

const queues = new Map<string, Promise<void>>();
let counter = 0;

export function atomicWrite(file: string, data: string): Promise<void> {
  const previous = queues.get(file) ?? Promise.resolve();
  const next = previous
    .catch(() => undefined)
    .then(async () => {
      const tmp = `${file}.${process.pid}.${++counter}.tmp`;
      await writeFile(tmp, data, { mode: 0o600 });
      await rename(tmp, file);
    });
  queues.set(file, next);
  void next.finally(() => {
    if (queues.get(file) === next) queues.delete(file);
  });
  return next;
}
