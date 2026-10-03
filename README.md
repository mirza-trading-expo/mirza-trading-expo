# Mirza Trading Expo — full-stack starter

Signals, live market tools and membership only. This is not an exchange and does not execute trades.

## Run locally
1. Install Node.js 20+.
2. Copy `.env.example` to `.env`; set a long random `JWT_SECRET`, unique `ADMIN_EMAIL`, strong `ADMIN_PASSWORD`, USDT network and wallet address.
3. `npm install`
4. `npm start`
5. Open http://localhost:3000

The first configured admin account is created on startup if no admin exists. Do not deploy with example credentials.

## Included
- Email/password registration and login (bcrypt password hashes, JWT session token)
- Public signal feed and VIP-only signal endpoint
- Admin signal publishing, user list, and manual payment approval/rejection
- USDT payment submission by transaction hash; approval activates 30/365-day access
- CoinGecko market snapshot and TradingView chart embed

## Before production
- Deploy behind HTTPS; set secure environment secrets and backups.
- Add email verification, password reset, CSRF strategy if using cookies, audit logs, stricter per-route rate limits, schema validation, and monitoring.
- Configure a real USDT address and explicitly state the supported chain. Manually verify transaction hash, asset, chain, amount, recipient and confirmations in a trusted block explorer before approval. Never auto-approve from a user-supplied hash.
- Define prices, refund/renewal rules, privacy policy, terms, and local legal/tax obligations.
- Store payment receipts only if needed; this starter uses transaction hash and note, not uploaded documents.
- Do not request wallet seed phrases/private keys. Do not promise returns or label sample signals as live recommendations.
- SQLite is suitable for local prototype; use managed PostgreSQL and migrations for production.
