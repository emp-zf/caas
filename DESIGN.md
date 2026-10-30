# DESIGN.md — ZFTunnel by Velocity · Command center

## What this is
The dashboard and login surface for the Xray gateway (`server.js`). Redesigned under the
[seenry](.opencode/skills/seenry/SKILL.md) workflow with a **Lens** identity: deep layered
gradient field, three drifting color orbs, frosted glass surfaces, one mint accent reserved
for live state.

## Brand guidelines

### Truth
A one-operator instrument for a machine the owner built and trusts. Glass says: the tool is
transparent, the data is the object. Not a spectator dashboard — a lens into a running system.

### Visual idea — Lens
Chrome (topbar, hero, cards, modals) is frosted glass; data-dense surfaces (logs, URIs,
network numbers) sit on near-opaque panels so every glyph stays crisp (selective transparency).

### Type
- Inter / system-ui. Weights 500 and 600 only. No uppercase letter-spaced eyebrows.
- Display sizes tighten tracking (−0.03em). Sentence case everywhere.
- Mono (ui-monospace) only for URIs, logs and aligned numerals — never as texture.

### Color world (dark = default)
| Token | Dark | Light |
| --- | --- | --- |
| `--field` | #05090d | #eef4f1 |
| `--field-2` | #0a1418 | #f7faf8 |
| orbs a/b/c | mint #12d9a0 · teal #0ea5e9 · violet #8b5cf6 | pastel versions |
| `--glass` | rgba(255,255,255,.06) | rgba(255,255,255,.55) |
| `--surface` | rgba(10,20,24,.78) | rgba(255,255,255,.80) |
| `--stroke` | rgba(255,255,255,.14) | rgba(255,255,255,.72) |
| `--ink` | #e8f3f1 | #0f2724 |
| `--muted` | #8ba8a3 | #55706a |
| `--accent` | #5ef2c3 (mint) | #0d9488 (deep teal) |

Rules:
- Accent = live state only (status dot, online, traffic, focus ring). Nothing decorative glows.
- Glass surfaces: `backdrop-filter: blur(20px) saturate(1.4)`, hairline border `--stroke`,
  inner top highlight `inset 0 1px 0 rgba(255,255,255,.24)`, radius 20px cards / 12px controls.
- Data panels: `--surface`, radius 12px, no lift on hover. Only chrome lifts.

### Motion
| What | Trigger | Spec |
| --- | --- | --- |
| Card entrance | load | rise 14px + fade, 420ms, `cubic-bezier(.22,1,.36,1)`, stagger 60ms |
| Card hover | :hover | translateY(−2px), border brighten, 180ms |
| Live dot | .online/.live | box-shadow pulse ring, 2s loop |
| Modal | open | backdrop fade + panel scale(.96)→1, 240ms |
| Theme switch | toggle | 240ms cross-fade via CSS variables |
| Orbs | always | drift translate/scale, alternate 30–38s |
| Reduced motion | media query | all animations off; opacity-only where needed |

### Structure
- Static shell (head, CSS, body) and client script live inside `server.js` template literals.
- Serve-time token swap: template keeps `EDGETUNNEL` / `edgetunnel-theme` / `EdgeTunnel`,
  the server rewrites them to `ZFTUNNEL` / `zftunnel-theme` / `ZFTunnel by Velocity`.
- Client hooks (ids/classes) are stable — see the inventory in `.seenry/`.

## References kept (research)
- Superdesign, "Glassmorphism dashboard" — selective transparency: glass on chrome,
  near-opaque on data-dense surfaces.
- Seenry house style — quiet premium, tuned weights, one accent, real data only.

## Work log
- `.seenry/idea.md` — five directions, picked Lens (restraint borrowed from Obsidian pane).
- `.seenry/identity.md` — tokens above.
- `.seenry/motion.md` — motion table above.
- Restore point: git commit `13512c9` (pre-redesign state).
- QA rounds: automated visual review (multimodal-looker) across login/desktop/mobile.
  Round 1 → round 3 fixes: URI wrapping (inline ellipsis removed), mobile grids
  (2-col/1-col media queries, tabular numerals), all 6 network tiles shown, topbar
  wrap, full-page orb gradients (glass survives below the fold), frosted inputs,
  muted lifted #b6d2cc, copy tone "Direct routing", port from API not hardcoded.
- Seenry gate `check.mjs` runs against the login page; dashboard is auth-gated so
  the visual-review loop (screenshots → looker agent) is the gate for it.
