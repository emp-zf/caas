# BRIEF — ZFTunnel Command Center glassmorphism redesign

## Audience
A single operator (the owner) managing their self-hosted Xray proxy gateway. Technical, works alone, uses this dashboard a few times a day to copy connection URIs, scan QR codes, check traffic and verify network status. Also used on a phone in a pinch.

## The one job of the surface
Make the gateway's state legible at a glance and make copying a connection URI or scanning a QR code effortless. The design should feel like a precision instrument for one person — calm, premium, alive but never busy.

## Real content
- Brand: ZFTunnel by Velocity (mark + "XRAY CONTROL CENTER" tagline)
- Header: theme toggle (dark/light), logout
- Hero: "Command center" + live status ("Dashboard connected")
- Gateway configuration form: UUID + 5 paths (VLESS / VMess / Trojan / Shadowsocks / XHTTP) + Save
- Runtime logs card: auto-refresh badge + logs view
- Connection profiles: 5 URI cards (VLESS, VMess, Trojan, Shadowsocks, XHTTP) each with QR + Copy URI
- Current network information: 4 network cards (Edge IP w/ country flag, Location, Cloudflare IP, Latency) + speed tests + traffic counter (up/down/active)
- Modals: configuration (already the form card), QR (with generated QR image), runtime logs

## What is fixed (do not change)
- All DOM ids and classes referenced by existing client JS: `#theme, #logs-button, #config-button, #uuid, #uris, #logs-modal, #logs-close, #qr-modal, #qr-close, #qr-title, #qr-image, #config-modal, #config, #xhttp, #network-card, #network-details, #network-status, #status, #logs, #network-tests, #traffic-counter, #traffic-up, #traffic-down, #traffic-active, .protocol, .uri, .copy, .save, .layout, .card, .actions, .fields, .log-head, .live`
- All client functions: `show, buildUris, compactUriCards, openQr, closeQr, openConfig, initializeConfigModal, bindConfigForm, openLogs, renderLogs, logout, toggleTheme, syncModalTheme, refreshNetwork, renderNetworkTests, renderEdgeNetworkCards, addNetworkCard, addNetworkFlags, ensureNetworkTests, ensureTrafficCounter, refreshTraffic, syncNetworkSummaryTheme, syncNetworkTheme, arrangeActions, api, countryFlag, load`
- Login page (separate template) gets the same glass language but keeps its form action and ids.
- Dark mode stays the default; light mode must remain fully readable.
- Must remain a single embedded template string in `server.js` — no external assets, no build step for the page.

## Direction (the brief outranks house style)
Glassmorphism: frosted translucent cards (`backdrop-filter: blur`), soft inner/outer glow, hairline light borders, vibrant gradient orbs drifting behind the glass, deep layered background. Smooth, purposeful UI animation: staggered card entrance, hover lift, modal fade+scale, live-pulse indicators, number transitions. Respect `prefers-reduced-motion`.

## Tone
Quiet premium. One refined accent (mint/emerald on dark, deep teal on light), sentence case, two weights max (500/600), tight tracking, real data everywhere. No AI tells: no gradient blobs-as-decoration (the orbs are the glass substrate, not clip-art), no uppercase letter-spaced eyebrows, no invented icons — inline SVG only where a control needs one.
