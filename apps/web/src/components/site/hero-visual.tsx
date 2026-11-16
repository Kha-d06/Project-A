/**
 * Decorative only. It illustrates the idea of inspection and is not connected to
 * any data, so it carries no labels, numbers or alerts that could read as real.
 */
export function HeroVisual() {
  return (
    <div aria-hidden className="relative mx-auto aspect-square w-full max-w-[26rem] select-none">
      <svg viewBox="0 0 400 400" className="absolute inset-0 size-full" fill="none">
        <defs>
          <linearGradient id="hero-sweep" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stopColor="var(--accent)" stopOpacity="0" />
            <stop offset="0.85" stopColor="var(--accent)" stopOpacity="0.18" />
            <stop offset="1" stopColor="var(--accent)" stopOpacity="0.9" />
          </linearGradient>
          <clipPath id="hero-shield">
            <path d="M200 52 92 92v86c0 70 46 122 108 142 62-20 108-72 108-142V92L200 52Z" />
          </clipPath>
        </defs>

        {[170, 130, 90].map((radius) => (
          <circle
            key={radius}
            cx="200"
            cy="200"
            r={radius}
            stroke="var(--line)"
            strokeDasharray={radius === 170 ? "2 6" : undefined}
          />
        ))}
        <path d="M30 200h340M200 30v340" stroke="var(--line)" strokeDasharray="2 6" />

        <path
          d="M200 52 92 92v86c0 70 46 122 108 142 62-20 108-72 108-142V92L200 52Z"
          fill="var(--surface)"
          stroke="var(--line-strong)"
          strokeWidth="1.5"
        />
        <g clipPath="url(#hero-shield)">
          {Array.from({ length: 9 }, (_, row) => (
            <path
              key={row}
              d={`M92 ${108 + row * 24}h216`}
              stroke="var(--line)"
              strokeDasharray={row % 2 ? "28 10 6 10" : "12 8 40 8"}
            />
          ))}
          <rect x="92" y="-60" width="216" height="60" fill="url(#hero-sweep)" className="hero-sweep" />
        </g>
        <path
          d="M200 84 120 113v66c0 52 33 91 80 107 47-16 80-55 80-107v-66L200 84Z"
          stroke="var(--accent)"
          strokeOpacity="0.5"
          strokeWidth="1"
        />
        <circle cx="200" cy="190" r="6" fill="var(--accent)" />
        <circle cx="200" cy="190" r="16" stroke="var(--accent)" strokeOpacity="0.35" />
      </svg>
      <style>{`
        .hero-sweep { animation: hero-sweep 3.2s cubic-bezier(.45,0,.25,1) 400ms 3 both; }
        @keyframes hero-sweep { from { transform: translateY(0); } to { transform: translateY(380px); } }
        @media (prefers-reduced-motion: reduce) { .hero-sweep { animation: none; opacity: 0; } }
      `}</style>
    </div>
  );
}
