"use client";

import { usePrefersReducedMotion } from "@/lib/reduced-motion";

/**
 * The hero illustration: traffic arriving at the citadel.
 *
 * Packets (links, messages, files, QR codes) travel along network lanes towards
 * the gate. Clean ones pass the brass rampart and enter; malicious ones are
 * stopped at the rampart with a pulse. A radar sweeps behind, and a lock, a key
 * and a fingerprint orbit the walls.
 *
 * Decorative only: no labels or numbers that could be read as real data.
 * Animated with SVG's declarative animation (no JavaScript per frame); people
 * who prefer reduced motion get a still composition.
 */

const CX = 280;
const CY = 330;
const RAMPART = 140;
const GATE = { x: 280, y: 352 };

type Glyph = "link" | "mail" | "file" | "qr";

// Each lane: the outer stretch ends exactly on the rampart ring.
const LANES = [
  { outer: "M-20 70 C 60 86, 112 200, 158.8 260", end: [158.8, 260] },
  { outer: "M-20 300 C 40 308, 92 328, 140 330", end: [140, 330] },
  { outer: "M580 46 C 500 76, 442 190, 394.7 249.7", end: [394.7, 249.7] },
  { outer: "M580 336 C 520 334, 470 331, 420 330", end: [420, 330] },
  { outer: "M286 -20 C 290 60, 272 130, 280 190", end: [280, 190] },
] as const;

const PACKETS: { lane: number; glyph: Glyph; bad: boolean; begin: number }[] = [
  { lane: 0, glyph: "link", bad: true, begin: 0 },
  { lane: 3, glyph: "file", bad: false, begin: -1.2 },
  { lane: 1, glyph: "mail", bad: false, begin: -2.4 },
  { lane: 4, glyph: "qr", bad: false, begin: -3.3 },
  { lane: 2, glyph: "mail", bad: true, begin: -4.4 },
  { lane: 1, glyph: "file", bad: true, begin: -5.6 },
  { lane: 3, glyph: "link", bad: false, begin: -6.7 },
  { lane: 0, glyph: "qr", bad: false, begin: -7.9 },
  { lane: 4, glyph: "link", bad: true, begin: -9.0 },
  { lane: 2, glyph: "file", bad: false, begin: -10.2 },
];
const DUR = 7.2;
const CYCLE = 11.4; // packets re-enter after this many seconds

const ORBIT = `M ${CX - 215} ${CY - 10} a 215 92 0 1 0 430 0 a 215 92 0 1 0 -430 0`;
const SPECKS = [
  [62, 132, 1.2], [118, 46, 0.9], [210, 96, 1.1], [358, 70, 0.8], [470, 120, 1.3], [520, 214, 0.9],
  [44, 410, 1], [508, 418, 1.1], [420, 452, 0.8], [130, 446, 0.9], [330, 30, 1], [486, 30, 0.7],
] as const;

function Glyphs() {
  // Simplified line icons on a 24px grid, drawn with currentColor.
  return (
    <defs>
      <symbol id="g-link" viewBox="0 0 24 24">
        <path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7" />
      </symbol>
      <symbol id="g-mail" viewBox="0 0 24 24">
        <rect x="3" y="5" width="18" height="14" rx="2" />
        <path d="m21 7-9 6-9-6" />
      </symbol>
      <symbol id="g-file" viewBox="0 0 24 24">
        <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" />
        <path d="M14 3v5h5M9 13h6M9 17h4" />
      </symbol>
      <symbol id="g-qr" viewBox="0 0 24 24">
        <rect x="4" y="4" width="6" height="6" rx="1" />
        <rect x="14" y="4" width="6" height="6" rx="1" />
        <rect x="4" y="14" width="6" height="6" rx="1" />
        <path d="M14 14h2v2M20 14v6h-6M17 17h.01" />
      </symbol>
      <symbol id="g-lock" viewBox="0 0 24 24">
        <rect x="4" y="11" width="16" height="10" rx="2" />
        <path d="M8 11V7a4 4 0 0 1 8 0v4M12 15v2" />
      </symbol>
      <symbol id="g-key" viewBox="0 0 24 24">
        <circle cx="7.5" cy="15.5" r="4.5" />
        <path d="m10.7 12.3 9.3-9.3M16 7l3 3M18.5 4.5 21 7" />
      </symbol>
      <symbol id="g-print" viewBox="0 0 24 24">
        <path d="M12 10a2 2 0 0 0-2 2c0 1-.1 2.5-.3 4M14 13c0 2.4 0 6.4-1 9M17.3 21c.1-.6.4-2.3.5-3M2 12a10 10 0 0 1 18-6M21.8 16c.2-2 .1-5.4 0-6M5 19.5c.5-1.5 1-4.5 1-7.5a6 6 0 0 1 .3-2M9 6.8a6 6 0 0 1 9 5.2v2" />
      </symbol>
      <radialGradient id="cs-gate-glow">
        <stop offset="0" stopColor="var(--accent)" stopOpacity="0.85" />
        <stop offset="1" stopColor="var(--accent)" stopOpacity="0" />
      </radialGradient>
      <radialGradient id="cs-halo">
        <stop offset="0" stopColor="var(--accent)" stopOpacity="0.16" />
        <stop offset="0.6" stopColor="var(--accent)" stopOpacity="0.04" />
        <stop offset="1" stopColor="var(--accent)" stopOpacity="0" />
      </radialGradient>
      <linearGradient id="cs-sweep" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0" stopColor="var(--oasis)" stopOpacity="0" />
        <stop offset="1" stopColor="var(--oasis)" stopOpacity="0.1" />
      </linearGradient>
      <linearGradient id="cs-wall" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stopColor="var(--surface-raised)" />
        <stop offset="1" stopColor="var(--surface)" />
      </linearGradient>
    </defs>
  );
}

function Chip({ glyph, tone }: { glyph: Glyph | "lock" | "key" | "print"; tone: "clean" | "bad" | "neutral" }) {
  const color = tone === "bad" ? "var(--risk-danger)" : tone === "clean" ? "var(--oasis)" : "var(--accent)";
  return (
    <g>
      <rect x="-14" y="-14" width="28" height="28" rx="8" fill="var(--surface-raised)" stroke={color} strokeOpacity="0.55" />
      <use href={`#g-${glyph}`} x="-8" y="-8" width="16" height="16" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </g>
  );
}

function Citadel() {
  // Front elevation: two crenellated towers, a curtain wall and an open gate.
  return (
    <g>
      <ellipse cx={CX} cy="384" rx="150" ry="16" fill="var(--ink)" opacity="0.08" />
      {/* plinth: the rock the citadel stands on */}
      <path d="M170 382h220l-14 14H184Z" fill="var(--surface-raised)" stroke="var(--line-strong)" />
      <path
        d="M190 382V226H200V236H210V226H220V236H230V226H240V278H250V268H260V278H275V268H285V278H300V268H310V278H320V226H330V236H340V226H350V236H360V226H370V382Z"
        fill="url(#cs-wall)"
        stroke="var(--accent)"
        strokeOpacity="0.45"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      {/* stone courses */}
      <path d="M190 300h50M320 300h50M190 336h180M240 312h80" stroke="var(--line)" strokeWidth="1" />
      {/* arrow slits */}
      {[214, 346].map((x) => (
        <rect key={x} x={x - 2.5} y="252" width="5" height="22" rx="2.5" fill="var(--surface-sunken)" stroke="var(--line-strong)" />
      ))}
      {/* the gate */}
      <path d="M260 382v-36a20 20 0 0 1 40 0v36Z" fill="var(--surface-sunken)" stroke="var(--line-strong)" strokeWidth="1.5" />
      <path d="M266 382v-34M274 382v-38M282 382v-38M290 382v-36" stroke="var(--line-strong)" strokeOpacity="0.6" />
      <path d="m280 312 7 7-7 7-7-7 7-7Z" fill="var(--accent)" />
      {/* banner */}
      <path d="M215 226v-26" stroke="var(--line-strong)" strokeWidth="1.5" />
      <path d="M215 201h18l-5 5 5 5h-18Z" fill="var(--accent)" opacity="0.9" />
    </g>
  );
}

export function CitadelScene() {
  const reduce = usePrefersReducedMotion();
  const still = reduce;

  return (
    <div aria-hidden className="relative mx-auto w-full max-w-[34rem] select-none">
      <svg viewBox="0 0 560 480" className="block h-auto w-full overflow-visible" fill="none">
        <Glyphs />

        <circle cx={CX} cy={CY} r="250" fill="url(#cs-halo)" />

        {/* survey rings */}
        {[220, 180].map((r) => (
          <circle key={r} cx={CX} cy={CY} r={r} stroke="var(--line)" strokeDasharray={r === 220 ? "1 7" : undefined} />
        ))}

        {/* radar sweep */}
        <g className={still ? undefined : "cs-radar"}>
          <path d={`M${CX} ${CY} L${CX + 220} ${CY} A220 220 0 0 0 ${CX + 190.5} ${CY - 110} Z`} fill="url(#cs-sweep)" />
          <path d={`M${CX} ${CY} L${CX + 220} ${CY}`} stroke="var(--oasis)" strokeOpacity="0.3" />
        </g>

        {/* drifting specks */}
        {SPECKS.map(([x, y, r], i) => (
          <circle key={i} cx={x} cy={y} r={r} fill="var(--ink-faint)" opacity="0.45">
            {!still && <animate attributeName="opacity" values="0.15;0.6;0.15" dur={`${4 + (i % 5)}s`} begin={`${-i * 0.7}s`} repeatCount="indefinite" />}
          </circle>
        ))}

        {/* network lanes */}
        {LANES.map((lane, i) => (
          <g key={i}>
            <path d={lane.outer} stroke="var(--line-strong)" strokeWidth="1.2" strokeDasharray="2 6" strokeLinecap="round">
              {!still && <animate attributeName="stroke-dashoffset" from="0" to="-32" dur="1.6s" repeatCount="indefinite" />}
            </path>
            <path d={`M${lane.end[0]} ${lane.end[1]} L${GATE.x} ${GATE.y}`} stroke="var(--line)" strokeWidth="1" strokeDasharray="2 6" />
          </g>
        ))}

        {/* packets: behind the walls, so clean ones disappear into the citadel */}
        {PACKETS.map((packet, i) => {
          const lane = LANES[packet.lane]!;
          const full = `${lane.outer} L${GATE.x} ${GATE.y}`;
          const begin = `${packet.begin}s`;
          const dur = `${CYCLE}s`;
          const travel = DUR / CYCLE;
          if (still) {
            if (i > 4) return null;
            return (
              <g key={i} transform={`translate(${(lane.end[0] * 2 + (packet.lane % 2 ? 40 : -10)) / 2.2} ${lane.end[1] - 30})`}>
                <Chip glyph={packet.glyph} tone={packet.bad ? "bad" : "clean"} />
              </g>
            );
          }
          if (packet.bad) {
            const [ex, ey] = lane.end;
            const stop = travel * 0.78;
            return (
              <g key={i}>
                <g>
                  <animateMotion path={lane.outer} dur={dur} begin={begin} repeatCount="indefinite" keyPoints="0;1;1" keyTimes={`0;${stop};1`} calcMode="spline" keySplines="0.3 0 0.4 1;0 0 1 1" />
                  <animate attributeName="opacity" values="0;1;1;0;0" keyTimes={`0;0.05;${stop + 0.04};${stop + 0.12};1`} dur={dur} begin={begin} repeatCount="indefinite" />
                  <Chip glyph={packet.glyph} tone="bad" />
                </g>
                {/* blocked at the rampart */}
                <circle cx={ex} cy={ey} r="10" stroke="var(--risk-danger)" strokeWidth="2" fill="none" opacity="0">
                  <animate attributeName="r" values="10;10;34;34" keyTimes={`0;${stop};${stop + 0.14};1`} dur={dur} begin={begin} repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0;0;0.9;0;0" keyTimes={`0;${stop};${stop + 0.01};${stop + 0.14};1`} dur={dur} begin={begin} repeatCount="indefinite" />
                </circle>
                <path d={`M${ex - 5} ${ey - 5}l10 10m0-10-10 10`} stroke="var(--risk-danger)" strokeWidth="2.4" strokeLinecap="round" opacity="0">
                  <animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes={`0;${stop + 0.02};${stop + 0.04};${stop + 0.12};${stop + 0.18};1`} dur={dur} begin={begin} repeatCount="indefinite" />
                </path>
              </g>
            );
          }
          return (
            <g key={i}>
              <animateMotion path={full} dur={dur} begin={begin} repeatCount="indefinite" keyPoints="0;1;1" keyTimes={`0;${travel};1`} calcMode="spline" keySplines="0.35 0 0.5 1;0 0 1 1" />
              <animate attributeName="opacity" values="0;1;1;0;0" keyTimes={`0;0.05;${travel * 0.85};${travel};1`} dur={dur} begin={begin} repeatCount="indefinite" />
              <Chip glyph={packet.glyph} tone="clean" />
            </g>
          );
        })}

        {/* the rampart: where every packet is checked */}
        <circle cx={CX} cy={CY} r={RAMPART} stroke="var(--accent)" strokeOpacity="0.55" strokeWidth="1.6" strokeDasharray="10 7" className={still ? undefined : "cs-rampart"} />
        <circle cx={CX} cy={CY} r={RAMPART + 8} stroke="var(--accent)" strokeOpacity="0.15" />

        <Citadel />

        {/* gate glow when traffic is let in */}
        <circle cx={GATE.x} cy={GATE.y + 6} r="34" fill="url(#cs-gate-glow)" opacity="0.35">
          {!still && <animate attributeName="opacity" values="0.2;0.55;0.2" dur="2.4s" repeatCount="indefinite" />}
        </circle>

        {/* orbiting guardians */}
        {(["lock", "key", "print"] as const).map((glyph, i) =>
          still ? (
            <g key={glyph} transform={`translate(${[82, 470, 400][i]} ${[372, 392, 214][i]})`}>
              <Chip glyph={glyph} tone="neutral" />
            </g>
          ) : (
            <g key={glyph}>
              <animateMotion path={ORBIT} dur="36s" begin={`${-i * 12}s`} repeatCount="indefinite" />
              <Chip glyph={glyph} tone="neutral" />
            </g>
          ),
        )}
      </svg>
      <style>{`
        .cs-radar { transform-box: view-box; transform-origin: ${CX}px ${CY}px; animation: cs-spin 9s linear infinite; }
        .cs-rampart { animation: cs-dash 6s linear infinite; }
        @keyframes cs-spin { to { transform: rotate(-360deg); } }
        @keyframes cs-dash { to { stroke-dashoffset: -170; } }
      `}</style>
    </div>
  );
}
