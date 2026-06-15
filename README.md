# Mezo

**Scan history forensics for VAAST — surfaces patterns, anomalies, and behavioral trends across proxy captures.**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![VAAST Xtension](https://img.shields.io/badge/VAAST-Xtension-7C3AED)](https://xtension.xtrinel.com)
[![Tier: Free](https://img.shields.io/badge/tier-free-gray)](https://xtension.xtrinel.com)

## What's new in v0.2.0

- Full tab UI with live-updating analysis results
- No longer requires an active scan session
- Real-time updates as proxy captures arrive (debounced 1.5s)
- Collapsible finding sections
- Manual refresh button
- "Updated Xs ago" live timestamp

## What it does

Just as the Mesozoic era left a fossil record that reveals patterns across deep time, Mezo reads your session's capture history to surface what keeps recurring, what's clustered around errors, and what's unexpectedly large. It runs three forensic passes across your proxy captures and writes findings directly to the VAAST results pane.

## The Three Analyses

| Pass | What it detects | Why it matters |
|------|----------------|----------------|
| **Repeated Host Probing** | Hosts receiving 5+ requests in a session | AI agents making repetitive enumeration calls often indicate tool-call loops or hallucinated retry behavior |
| **Error Response Clustering** | Endpoints returning multiple 4xx/5xx errors | Broken tool calls, hallucinated API paths, and policy-blocked prompt injection attempts leave error clusters |
| **Anomalous Response Size** | Responses >2 standard deviations from session mean | Data exfiltration via model output and successful prompt injection often manifest as unusually large responses |

## Installation

**Via Xtension Store (recommended):**
1. Go to [xtension.xtrinel.com](https://xtension.xtrinel.com)
2. Find Mezo and click "Install in VAAST"

**Manual:**
1. Download the latest release zip from [GitHub Releases](https://github.com/AnishKajan/mezo-xtension/releases)
2. Copy `dist/index.js` and `manifest.json` to `~/.vaast/extensions/mezo/`
3. Restart VAAST or reload Xtensions from Settings

## Usage

1. Open VAAST and start a session with a target
2. Run a scan or use the HTTPS proxy to capture traffic
3. Click the **Mezo** tab in the sidebar to see findings
4. Click **Analyze Session History** to run the three forensic passes
5. Findings also appear in the main results pane automatically

## Permissions

| Permission | Used for |
|-----------|----------|
| `proxy.read` | Reads captured proxy traffic for analysis |
| `scanner.write` | Writes findings to the VAAST results pane |
| `ui.tab` | Registers the Mezo tab in the sidebar |
| `session.read` | Reads current workspace and target metadata |

## Building from source

```bash
npm install
npm run build
```

Output: `dist/index.js`

## Contributing

Open issues and PRs welcome. This is a community Xtension — not affiliated with or maintained by Xtrinel.

## Compatibility

- VAAST 1.0.0+
- Free tier (no Pro required)

## Links

- [Xtension Store](https://xtension.xtrinel.com)
- [VAAST Docs — Building Xtensions](https://docs.xtrinel.com/docs/xtension/building-xtensions)
- [xtension-registry](https://github.com/Xtrinel-Group/xtension-registry)

## License

MIT
