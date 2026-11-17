/** When a scheduled scan or backup is due. Pure, so it is easy to test. */

export interface Schedule {
  frequency: "off" | "daily" | "weekly";
  /** 0 = Sunday … 6 = Saturday; used for weekly schedules. */
  day: number;
  /** Local hour, 0–23. */
  hour: number;
}

export const DEFAULT_SCHEDULE: Schedule = { frequency: "off", day: 0, hour: 12 };

export function sanitizeSchedule(input: unknown): Schedule | null {
  if (!input || typeof input !== "object") return null;
  const value = input as Record<string, unknown>;
  const frequency = value.frequency;
  if (frequency !== "off" && frequency !== "daily" && frequency !== "weekly") return null;
  const day = Number(value.day);
  const hour = Number(value.hour);
  if (!Number.isInteger(day) || day < 0 || day > 6 || !Number.isInteger(hour) || hour < 0 || hour > 23) return null;
  return { frequency, day, hour };
}

/** The most recent moment the schedule asked for a run, at or before `now`. */
export function lastSlot(schedule: Schedule, now: Date): Date | null {
  if (schedule.frequency === "off") return null;
  const slot = new Date(now);
  slot.setHours(schedule.hour, 0, 0, 0);
  if (schedule.frequency === "daily") {
    if (slot > now) slot.setDate(slot.getDate() - 1);
    return slot;
  }
  slot.setDate(slot.getDate() - ((slot.getDay() - schedule.day + 7) % 7));
  if (slot > now) slot.setDate(slot.getDate() - 7);
  return slot;
}

/**
 * Due when the latest slot has passed and nothing ran since. A computer that was
 * off at the scheduled time catches up when it next starts, once, not once per
 * missed slot.
 */
export function isDue(schedule: Schedule, lastRun: string | null, now: Date = new Date()): boolean {
  const slot = lastSlot(schedule, now);
  if (!slot) return false;
  if (!lastRun) return true;
  return new Date(lastRun) < slot;
}

export function nextSlot(schedule: Schedule, now: Date = new Date()): Date | null {
  const last = lastSlot(schedule, now);
  if (!last) return null;
  const next = new Date(last);
  next.setDate(next.getDate() + (schedule.frequency === "daily" ? 1 : 7));
  return next;
}
