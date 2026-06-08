#!/usr/bin/env bash
# Seed the ZK402 test environment: generate keys, onboard a merchant,
# create a metering channel for a demo buyer. Idempotent-ish.
set -euo pipefail
cd "$(dirname "$0")"
API="${ZK402_API:-http://localhost:4242}"
mkdir -p .seed
[ -f .env ] || cp .env.example .env

# 1. Generate node keys into .env if absent.
gen_env() { grep -q "^$1=.\+" .env || sed -i.bak "s|^$1=.*|$1=$2|" .env && rm -f .env.bak; }
if ! grep -q "^PUBLISHER_KEY=.\+" .env; then
  gen_env PUBLISHER_KEY "$(openssl rand -hex 32)"; echo "generated PUBLISHER_KEY"
fi
if ! grep -q "^ZK402_RECEIPT_KEY=.\+" .env; then
  # Ed25519 PKCS8 (v1) DER → base64url no-pad
  KEY=$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=\n')
  gen_env ZK402_RECEIPT_KEY "$KEY"; echo "generated ZK402_RECEIPT_KEY"
fi

# 2. Demo buyer key.
[ -f .seed/buyer.hex ] || openssl rand -hex 32 > .seed/buyer.hex
BUYER=$(cat .seed/buyer.hex)
PAYER=$(node e2e-agent.mjs payer "{\"sk\":\"$BUYER\"}")
echo "demo payer: $PAYER"

# 3. Wait for the node.
echo -n "waiting for node at $API "
for i in $(seq 1 60); do curl -sf "$API/health" >/dev/null 2>&1 && break; echo -n .; sleep 1; done
echo " up"

# 4. Onboard merchant (capture API key once).
RESP=$(curl -sf -X POST "$API/api/zk402/merchants" -H 'content-type: application/json' \
  -d '{"merchantId":"merchant_demo","displayName":"Demo Merchant","settlementAddress":"zk1qdemoaddress"}' || true)
KEY=$(echo "$RESP" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).apiKey||"")}catch{console.log("")}})')
if [ -n "$KEY" ]; then echo "$KEY" > .seed/api-key; echo "onboarded merchant_demo, api key saved → .seed/api-key";
else echo "merchant already onboarded (api key only shown once; reuse .seed/api-key)"; fi
echo "merchant_demo" > .seed/merchant

# 5. Metering channel for the demo buyer (cap 100000 sats).
NOW=$(date +%s)
curl -sf -X POST "$API/api/zk402/authorizations" -H 'content-type: application/json' -d "$(cat <<JSON
{"payer":"$PAYER","network":"zkcoins:regtest","expiresAt":"$(date -u -r $((NOW+86400)) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d @$((NOW+86400)) +%Y-%m-%dT%H:%M:%SZ)","allowedMerchants":["merchant_demo"],"spendLimitTotal":"100000","facilitator":"http://localhost:4242","signature":"demo-auth-sig"}
JSON
)" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);require("fs").writeFileSync(".seed/channel",j.authorizationId);console.log("channel:",j.authorizationId)}catch(e){console.log("channel create:",s)}})'

# 6. Seed the Bazaar: 3 demo sellers + curated service catalog + reputation.
echo "seeding bazaar (3 sellers, services, reputation)…"
ZK402_API="$API" node seed-bazaar.mjs

echo "seed complete."
