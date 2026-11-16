# Design system

Tokens live in `apps/web/src/app/globals.css`; components in
`apps/web/src/components/ui`.

## Principles

- **Calm by default.** Colour signals meaning. The teal accent marks interactive
  and brand elements; red and amber appear only for real findings.
- **Evidence first.** Every verdict sits next to the reasons and checks behind it.
- **Honest states.** Loading, scanning, failed, inconclusive and empty states are
  designed as carefully as the success state, and none of them imply a check
  that did not happen.

## Colour roles

Components use roles (`bg-surface`, `text-ink-muted`, `text-danger`), never raw
colours. The light and dark themes each define every role explicitly; the light
theme is not an inversion of the dark one.

| Role | Use |
| --- | --- |
| `canvas`, `surface`, `surface-raised`, `surface-sunken` | Page, panels, overlays, wells and evidence blocks |
| `line`, `line-strong` | Dividers and control borders |
| `ink`, `ink-muted`, `ink-faint` | Text hierarchy |
| `accent` | Buttons, focus rings, links, brand mark |
| `danger`, `warning`, `clear`, `unknown` | Known threat, suspicious, no known threat, inconclusive |

Verdicts are always conveyed by text and icon as well as colour (`RiskBadge`,
`Verdict`). The theme follows the system setting unless the user picks one, and a
script in `<head>` applies it before first paint.

## Typography

- **Manrope** for display text, **Inter** for interface text, **JetBrains Mono** for URLs, hashes and evidence.
- All three are self-hosted through Fontsource, so no requests go to Google.
- Scale: `display` 3.25rem, `title` 1.75rem, body 1rem, small 0.875rem, caption 0.75rem. Display sizes use tighter tracking.

## Spacing and layout

- Tailwind's 4px spacing scale.
- Content width is 72rem (`max-w-6xl`) for pages and 48rem (`max-w-3xl`) for forms and prose.
- Panels use a 12px radius and controls 8px.
- Breakpoints: Tailwind defaults (`sm` 640, `md` 768, `lg` 1024). The dashboard sidebar collapses into a menu below `lg`, and tables become stacked rows below `md`.

## Motion

- **Approved motion.** Short, decelerating transitions (`fade-up`, 320ms). The sweep under an active scan is the only indefinite animation, and it stops when the scan does.
- **Known threats.** A known-threat verdict pulses twice to draw attention, then stays still.
- **Hero illustration.** It sweeps three times on load and is decorative only, with no numbers or labels that could read as live detection.
- **Never.** No fake progress percentages and no ambient "live activity".
- **Reduced motion.** `prefers-reduced-motion` disables all animation, and the scan sweep is hidden, since its text label already says the scan is running.

## Accessibility rules

- Semantic landmarks and a "Skip to content" link.
- Every control has a label. Errors are linked with `aria-describedby`, and invalid fields set `aria-invalid`.
- Visible focus rings (2px accent) on everything interactive.
- The scanner tabs follow the WAI-ARIA tabs pattern with arrow-key navigation. Dialogs use the native `<dialog>` element for focus trapping and Escape.
- Scan progress and toasts are announced through live regions.
- Links inside text are underlined, not distinguished by colour alone.
- Every public page, the dashboard pages and a scan report pass axe-core (WCAG 2.1 A and AA plus best-practice rules) in both themes. Faint text keeps a contrast of at least 4.5:1 on every surface.
