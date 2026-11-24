//! The pet's behaviour: a pure state machine with no I/O and no clock of its
//! own. Every input carries the time, and `next_deadline` says when it next
//! needs waking, so the window sleeps (no timer runs) while nothing happens.

/// Milliseconds on any monotonic clock.
pub type Millis = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mood {
    Idle,
    Patrol,
    Sleep,
    Scan,
    Defend,
    Alert,
    Happy,
}

impl Mood {
    pub fn as_str(self) -> &'static str {
        match self {
            Mood::Idle => "idle",
            Mood::Patrol => "patrol",
            Mood::Sleep => "sleep",
            Mood::Scan => "scan",
            Mood::Defend => "defend",
            Mood::Alert => "alert",
            Mood::Happy => "happy",
        }
    }

    /// Higher wins when two things happen at once.
    fn rank(self) -> u8 {
        match self {
            Mood::Alert => 6,
            Mood::Defend => 5,
            Mood::Scan => 4,
            Mood::Happy => 3,
            Mood::Patrol => 2,
            Mood::Idle => 1,
            Mood::Sleep => 0,
        }
    }
}

/// What can happen, as reported by the background service or the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Time passed (sent when a deadline is reached).
    Tick,
    ScanStarted,
    ScanFinished {
        threats: u32,
    },
    /// A file was blocked or quarantined.
    ThreatBlocked,
    /// Something needs the person's decision (ransomware halt, new network device…).
    Alert,
    /// The person moved the mouse over the pet or used the computer.
    Activity,
    /// The person clicked the pet: acknowledges an alert.
    Clicked,
    Snooze {
        minutes: u32,
    },
    Unsnooze,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub defend_ms: Millis,
    pub happy_ms: Millis,
    pub patrol_every_ms: Millis,
    pub patrol_ms: Millis,
    pub sleep_after_ms: Millis,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            defend_ms: 6_000,
            happy_ms: 3_000,
            patrol_every_ms: 120_000,
            patrol_ms: 6_000,
            sleep_after_ms: 300_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pet {
    mood: Mood,
    since: Millis,
    last_activity: Millis,
    scanning: bool,
    alert_pending: bool,
    snoozed_until: Option<Millis>,
    timing: Timing,
}

impl Pet {
    pub fn new(now: Millis, timing: Timing) -> Self {
        Self {
            mood: Mood::Idle,
            since: now,
            last_activity: now,
            scanning: false,
            alert_pending: false,
            snoozed_until: None,
            timing,
        }
    }

    pub fn mood(&self) -> Mood {
        self.mood
    }

    /// Hidden while snoozed; alerts still wake it.
    pub fn visible(&self, now: Millis) -> bool {
        self.snoozed_until.is_none_or(|until| now >= until) || self.alert_pending
    }

    fn set(&mut self, mood: Mood, now: Millis) {
        if self.mood != mood {
            self.mood = mood;
            self.since = now;
        }
    }

    /// Takes the higher-ranked of the current mood and `mood`.
    fn raise(&mut self, mood: Mood, now: Millis) {
        if mood.rank() >= self.mood.rank() || matches!(self.mood, Mood::Patrol | Mood::Idle | Mood::Sleep | Mood::Happy) {
            self.set(mood, now);
        }
    }

    /// The resting mood once nothing more urgent is going on.
    fn settle(&mut self, now: Millis) {
        let mood = if self.alert_pending {
            Mood::Alert
        } else if self.scanning {
            Mood::Scan
        } else if now.saturating_sub(self.last_activity) >= self.timing.sleep_after_ms {
            Mood::Sleep
        } else {
            Mood::Idle
        };
        self.set(mood, now);
    }

    pub fn handle(&mut self, input: Input, now: Millis) -> Mood {
        match input {
            Input::ScanStarted => {
                self.scanning = true;
                self.raise(Mood::Scan, now);
            }
            Input::ScanFinished { threats } => {
                self.scanning = false;
                if threats > 0 {
                    self.alert_pending = true;
                    self.set(Mood::Alert, now);
                } else if !self.alert_pending && self.mood != Mood::Defend {
                    self.set(Mood::Happy, now);
                }
            }
            Input::ThreatBlocked => {
                if self.mood != Mood::Alert {
                    self.set(Mood::Defend, now);
                }
            }
            Input::Alert => {
                self.alert_pending = true;
                self.set(Mood::Alert, now);
            }
            Input::Activity => {
                self.last_activity = now;
                if self.mood == Mood::Sleep {
                    self.settle(now);
                }
            }
            Input::Clicked => {
                self.last_activity = now;
                if self.alert_pending {
                    self.alert_pending = false;
                    self.settle(now);
                } else if self.mood == Mood::Sleep {
                    self.settle(now);
                }
            }
            Input::Snooze { minutes } => {
                self.snoozed_until = Some(now + u64::from(minutes) * 60_000);
            }
            Input::Unsnooze => self.snoozed_until = None,
            Input::Tick => self.tick(now),
        }
        self.mood
    }

    fn tick(&mut self, now: Millis) {
        if self.snoozed_until.is_some_and(|until| now >= until) {
            self.snoozed_until = None;
        }
        let elapsed = now.saturating_sub(self.since);
        let t = self.timing;
        match self.mood {
            Mood::Defend if elapsed >= t.defend_ms => {
                if self.alert_pending {
                    self.set(Mood::Alert, now);
                } else {
                    self.set(Mood::Happy, now);
                }
            }
            Mood::Happy if elapsed >= t.happy_ms => self.settle(now),
            Mood::Patrol if elapsed >= t.patrol_ms => self.settle(now),
            Mood::Idle => {
                if now.saturating_sub(self.last_activity) >= t.sleep_after_ms {
                    self.set(Mood::Sleep, now);
                } else if elapsed >= t.patrol_every_ms {
                    self.set(Mood::Patrol, now);
                }
            }
            _ => {}
        }
    }

    /// When the pet next needs a `Tick`, or `None` to sleep until an event.
    pub fn next_deadline(&self) -> Option<Millis> {
        let t = self.timing;
        let snooze = self.snoozed_until;
        let own = match self.mood {
            Mood::Defend => Some(self.since + t.defend_ms),
            Mood::Happy => Some(self.since + t.happy_ms),
            Mood::Patrol => Some(self.since + t.patrol_ms),
            Mood::Idle => Some((self.since + t.patrol_every_ms).min(self.last_activity + t.sleep_after_ms)),
            Mood::Sleep | Mood::Scan | Mood::Alert => None,
        };
        match (own, snooze) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}
