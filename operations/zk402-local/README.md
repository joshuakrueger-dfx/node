# ZK402 — Full Local Test Environment

A complete, runnable ZK402 publisher stack: Postgres + the zkCoins node
(facilitator) + an Esplora stub + the dashboard frontend. Exercises the
real HTTP surface — exact payments, the non-custodial settlement view,
and the Flow-D Claude-token metering path — with no real Bitcoin needed.

## Quick start

```sh
cp .env.example .env

# Offline (default): a tiny Esplora stub, fully netless.
docker compose --profile offline up -d --build

# OR against real Mutinynet (public testnet tip/scanner):
# docker compose --profile mutinynet up -d --build

./seed.sh     # onboard merchant_demo (+ API key → .seed/), metering channel,
              # AND seed the Bazaar: 3 demo sellers + service catalog + reputation
./e2e.sh      # full smoke: verify → settle → idempotent → dashboard → meter

open http://localhost:3402     # dashboard — log in with the key in .seed/api-key
```

## The Bazaar (agent economy)

`seed.sh` calls `seed-bazaar.mjs`, which onboards **three demo sellers** and
registers a curated catalog so the marketplace ranks meaningfully:

| Seller | Services |
|---|---|
| `merchant_demo` | Claude Sonnet / Opus / Haiku inference (per request) |
| `merchant_dataco` | Weather API, Crypto Price Feed, Web Search |
| `merchant_gpufarm` | GPU Job (A100/min, `final` access), OCR |

Reputation is **earned, not set**: the seeder settles exact payments from
many *distinct* payers per service (distinct payers drive the confidence
score), so `GET /v2/x402/discovery/search?query=inference` returns the
catalog reputation-ranked (Sonnet > Opus > Haiku). Seller API keys land in
`.seed/api-key{,-dataco,-gpufarm}`. Re-running is safe: keys are reused and
existing services are looked up rather than re-created.

## What runs

| Service | Port | Role |
|---|---|---|
| postgres:17 | 5432 | state (migrations auto-apply on node boot) |
| esplora-stub | 3002 | fixed empty tip so the node boots + scanner idles (offline profile) |
| zkcoins-node | 4242 | the ZK402 facilitator (verify/settle/authorizations/dashboard/stream/receipt-keys) |
| dashboard | 3402 | merchant dashboard + buyer playground |

`ZK402_RECEIPT_KEY` and `PUBLISHER_KEY` are generated into `.env` by
`seed.sh` on first run. The ZK402 path is pure Postgres + crypto;
settlement + publisher acceptance are mocked behind traits, so the whole
flow works without a live chain.

## e2e.sh proves

1. **Exact payment** — `POST /v2/x402/verify` → `isValid`, `POST
   /v2/x402/settle` → `success` + signed receipt, a second settle returns
   the SAME receipt (idempotent).
2. **Dashboard** — `GET /api/zk402/dashboard/{summary,payments}` with the
   bearer API key; `401` without it.
3. **Receipt keys** — `GET /api/zk402/receipt-keys` advertises the active
   Ed25519 signing key for offline receipt verification.
4. **Streaming meter** — a signed `ZK402-STREAM-V1` voucher for 1,000,000
   Claude output tokens @ 15 µsat/token charges exactly **15 sats**, and
   the channel meter reflects it.

Exit code is non-zero on any failed assertion.

## Running the node without Docker (fast dev loop)

```sh
docker run -d --name pg -e POSTGRES_USER=zk402 -e POSTGRES_PASSWORD=zk402 \
  -e POSTGRES_DB=zk402 -p 5433:5432 postgres:17
node esplora-stub/server.js &                      # :3002
IS_MAINNET=false DATABASE_URL=postgres://zk402:zk402@127.0.0.1:5433/zk402 \
  ESPLORA_URL=http://127.0.0.1:3002 ESPLORA_WS_URL=ws://127.0.0.1:3002/api/v1/ws \
  USERNAME_DOMAIN=zk402.local PUBLISHER_KEY=$(openssl rand -hex 32) \
  ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1 cargo run -p node
ZK402_API=http://127.0.0.1:4242 ./seed.sh && ZK402_API=http://127.0.0.1:4242 ./e2e.sh
```

> The scanner logs a benign "block txids InvalidResponse" against the
> stub — the ZK402 facilitator does not use the scanner, so this is noise.
