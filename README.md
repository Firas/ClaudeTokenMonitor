# ClaudeTokenMonitor

> Written by [Claude](https://claude.com/claude-code) (Anthropic's AI, in
> conversation with the repo owner) — not hand-coded by a human.

Claude usage (5-hour session + weekly window) in the macOS menu bar. Native
Swift, zero third-party dependencies — only Cocoa / Foundation / Security /
SQLite3 / CommonCrypto, all part of the OS.

```
🟢W:89%  🟢H:79%  ⏱2ч 8м
```

Colored circles flag how much budget is left (🟢 >50% · 🟡 20–50% · 🔴 <20%).
Click the status item for a detail menu: exact %, reset countdown, last
update time, and raw API debug line.

## How it gets the numbers

Pulls from the same usage endpoint the claude.ai **web app** itself calls
(`https://claude.ai/api/organizations/{orgId}/usage`) — this is a different
data source than Anthropic's official OAuth `/api/oauth/usage` endpoint
that the Claude Code CLI's `/usage` command uses (see the companion
[claude-tray-mac](https://github.com/Firas/claude-tray-mac) project for
that route).

Auth for this endpoint needs the `sessionKey` cookie, which is read
directly from the **Claude Desktop** app's local Chromium cookie store
(`~/Library/Application Support/Claude/Cookies`, a SQLite DB). Modern
Chromium encrypts cookie values ("v10" format) with AES-128-CBC using a key
derived via PBKDF2-SHA1 from a password stored in the macOS Keychain under
`Chromium Safe Storage` / `Claude Safe Storage` — this is the standard
Chromium-on-macOS cookie encryption scheme (the same one tools like
[`browser_cookie3`](https://github.com/borisbabic/browser_cookie3) implement
for other Chromium apps); this project reimplements just that one decrypt
step natively in Swift via raw `CCCrypt`/`CCKeyDerivationPBKDF` calls, no
external crypto library.

## Requirements

- Claude Desktop app installed and logged in (need a live `sessionKey`
  cookie).
- macOS with Xcode Command Line Tools (`swiftc`) to build.

## Build & run

```bash
swiftc -O token_monitor.swift -o token_monitor
./token_monitor
```

## Autostart

Runs permanently via a LaunchAgent (`com.claude.token-monitor.plist`,
included) — starts on login, `KeepAlive` restarts it if it crashes.

```bash
cp com.claude.token-monitor.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.claude.token-monitor.plist
```
