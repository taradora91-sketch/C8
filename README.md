# 🤖 Cantor8 Multi-Account Bot

Auto CC ↔ USDCX round-trip swap farming bot for [Cantor8 Wallet](https://wallet.cantor8.tech). Supports multiple accounts running in parallel with per-account proxy and a clean real-time dashboard.

## Features

- **Multi-Account Parallel** — Run unlimited accounts simultaneously via `Promise.allSettled`
- **Per-Account Proxy** — Each account can use its own HTTP/HTTPS proxy
- **Auto Swap Farming** — CC → USDCX rounds with auto bulk-back USDCX → CC
- **Smart Error Handling** — Clean error messages, auto-retry on server errors, token refresh on 401
- **Real-Time Dashboard** — Per-account blocks showing balances, uptime, swap counters, rewards, and status indicators
- **Monthly Rewards Tracking** — Displays CC earned, volume, transactions, and rank from leaderboard API
- **Auto Offer Acceptance** — Automatically accepts pending wallet offers
- **Stuck Order Recovery** — Detects and resolves stuck/stale orders automatically

## Prerequisites

- [Node.js](https://nodejs.org/) v18 or higher
- A Cantor8 wallet with a 24-word mnemonic phrase

## Installation

```bash
git clone <repo-url>
cd Cantor8Bot-Sipal
npm install
```

## Configuration

Copy `config_tmp.json` to `config.json` and fill in your details:

```bash
cp config_tmp.json config.json
```

### Account Setup

```jsonc
{
    "accounts": [
        {
            "name": "Account 1",           // Display name
            "mnemonic": "your 24 words",   // Wallet mnemonic phrase
            "proxy": ""                     // Optional: "http://user:pass@host:port"
        },
        {
            "name": "Account 2",
            "mnemonic": "your 24 words",
            "proxy": "http://user:pass@host:port"
        }
    ]
}
```

### Swap Settings

| Field | Description | Default |
|-------|-------------|---------|
| `enabled` | Enable/disable swap farming | `true` |
| `rounds` | Number of CC → USDCX swap rounds | `1000` |
| `delay_seconds` | Delay between rounds | `5` |
| `reserve_cc` | Minimum CC to keep in wallet | `2` |
| `min_amount` | CC amount per swap | `11` |

### Proxy Support

Each account supports an optional HTTP/HTTPS proxy:

```json
{
    "name": "Account 1",
    "mnemonic": "...",
    "proxy": "http://username:password@proxy-host:port"
}
```

Leave `proxy` as `""` to use direct connection.

## Usage

```bash
node index.js
```

### Dashboard

The bot displays a real-time per-account dashboard:

```
🏦 Account 1
  CC: 10.09  USDCx: 0.0232  Up: 37m53s
  Swaps: 5(→)  CC→U:3/50 U→CC:2/5
  🏆 Reward [2025-03-08]: 307.97 CC Vol $1539 302 Txns  Rank #195
  N✅ S✅ P✅
  21.40.28 ✅ Authenticated
  21.40.54 💱 11 CC (Amulet) → 2.18 USDCX
  21.41.31 ✅ +2.18 USDCX

🏦 Account 2
  CC: 15.04  USDCx: 0.03  Up: 37m53s
  ...
```

**Status Indicators:**
- `N` — Nonce/Auth (✅ authenticated, ❌ not yet)
- `S` — Swap API (✅ active, ❌ inactive)
- `P` — Proxy (✅ configured, `--` no proxy)

## How It Works

1. **Key Derivation** — Derives 20 Ed25519 key pairs from your mnemonic using HD path `m/501'/800245900'/0'/{i}'/0'`
2. **Account Recovery** — Recovers your Cantor8 party ID using derived public keys
3. **Authentication** — Signs challenge with Ed25519 for wallet + swap API tokens
4. **Swap Loop** — Executes CC → USDCX swaps for the configured number of rounds
5. **Bulk-Back** — When CC runs low, automatically swaps all USDCX back to CC
6. **Final Bulk** — After all rounds, converts remaining USDCX back to CC

## Error Messages

| Error | Meaning |
|-------|---------|
| `[5xx] Server-Side Error` | Server is down, bot will auto-retry |
| `[401] Auth expired` | Token expired, auto-refreshed |
| `[409] Conflict` | Active order exists, bot handles it |
| `[429] Rate limited` | Too many requests, auto-retry with backoff |
| `[ECONNREFUSED/ETIMEDOUT]` | Network issue, auto-retry |

## License

MIT
