// Seed the ZK402 Bazaar: onboard 3 demo merchants, register a curated
// catalog of agent-economy services (compute / data / gpu), and generate
// reputation by settling exact payments from DISTINCT payers (distinct_payers
// drives the reputation confidence/score). Self-contained (@noble only); the
// canonical voucher encoder mirrors @zk402/sdk + the Rust facilitator EXACTLY
// — if it drifts the node's /v2/x402/settle rejects the signature and seeding
// visibly fails. Idempotent-ish: merchant keys are persisted + reused, and an
// already-registered service is looked up rather than re-created.
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";

const API = process.env.ZK402_API || "http://localhost:4242";
const NETWORK = "zkcoins:regtest";
const FACILITATOR = API;

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => Uint8Array.from(s.match(/.{2}/g).map((b) => parseInt(b, 16)));
const rnd = (n) => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
const rndId = (p) => p + hex(rnd(8));
const enc = new TextEncoder();

function voucherMsg(f) {
  return enc.encode(
    `ZK402-V1\nscheme=zkcoins-publisher\nnetwork=${f.network}\nmode=${f.mode}\n` +
    `intent_id=${f.intentId}\nauthorization_id=${f.authorizationId ?? ""}\nvoucher_id=${f.voucherId}\n` +
    `payer=${f.payer}\nmerchant=${f.merchant}\namount=${f.amount}\nfee_amount=${f.feeAmount}\n` +
    `asset=btc-sats\nresource_hash=${f.resourceHash}\nrequest_hash=${f.requestHash}\n` +
    `valid_after=${f.validAfter}\nvalid_before=${f.validBefore}\nnonce=${f.nonce}\n` +
    `facilitator=${f.facilitator}\naccess_threshold=${f.accessThreshold}`);
}
const signSchnorr = (sk, digest) => hex(schnorr.sign(digest, fromHex(sk), new Uint8Array(32))).toUpperCase();

const MERCHANTS = {
  demo:    { id: "merchant_demo",    name: "Demo Merchant (Claude)", addr: "zk1qdemoaddress", keyFile: ".seed/api-key" },
  dataco:  { id: "merchant_dataco",  name: "DataCo APIs",            addr: "zk1qdatacoaddr",  keyFile: ".seed/api-key-dataco" },
  gpufarm: { id: "merchant_gpufarm", name: "GPU Farm",               addr: "zk1qgpufarmaddr", keyFile: ".seed/api-key-gpufarm" },
};

// rep = number of distinct-payer exact payments → drives reputation score.
const CATALOG = [
  { m: "demo",    serviceId: "svc_claude_sonnet", capability: "inference",   displayName: "Claude Sonnet Inference", description: "Claude Sonnet 4.6 LLM inference, billed per request", endpoint: "https://api.demo.test/v1/claude-sonnet", price: 18, rep: 14, model: "claude-sonnet-4-6" },
  { m: "demo",    serviceId: "svc_claude_opus",   capability: "inference",   displayName: "Claude Opus Inference",   description: "Claude Opus 4.8 LLM inference, highest quality, per request", endpoint: "https://api.demo.test/v1/claude-opus", price: 30, rep: 6, model: "claude-opus-4-8" },
  { m: "demo",    serviceId: "svc_claude_haiku",  capability: "inference",   displayName: "Claude Haiku Inference",  description: "Claude Haiku 4.5 fast LLM inference, per request", endpoint: "https://api.demo.test/v1/claude-haiku", price: 6, rep: 4, model: "claude-haiku-4-5" },
  { m: "dataco",  serviceId: "svc_weather",       capability: "weather",     displayName: "Weather API",             description: "Current weather and forecast by lat/lon", endpoint: "https://api.dataco.test/v1/weather", price: 2, rep: 9, privacy: "public" },
  { m: "dataco",  serviceId: "svc_pricefeed",     capability: "price-feed",  displayName: "Crypto Price Feed",       description: "Real-time crypto and FX price feed", endpoint: "https://api.dataco.test/v1/prices", price: 3, rep: 5 },
  { m: "dataco",  serviceId: "svc_websearch",     capability: "web-search",  displayName: "Web Search API",          description: "Web search with ranked results for agents", endpoint: "https://api.dataco.test/v1/search", price: 5, rep: 7 },
  { m: "gpufarm", serviceId: "svc_gpu_a100",      capability: "gpu-compute", displayName: "GPU Job (A100, per minute)", description: "On-demand A100 GPU compute, billed per GPU-minute", endpoint: "https://api.gpufarm.test/v1/gpu/submit", price: 500, rep: 3, accessThreshold: "final" },
  { m: "gpufarm", serviceId: "svc_ocr",           capability: "ocr",         displayName: "OCR Service",             description: "Document OCR and text extraction", endpoint: "https://api.gpufarm.test/v1/ocr", price: 3, rep: 3 },
];

async function ensureMerchantKey(m) {
  if (existsSync(m.keyFile)) {
    // Probe the saved key: if the DB was wiped (fresh chain), the stale key
    // returns 401 and we must re-onboard rather than reuse it.
    const key = readFileSync(m.keyFile, "utf8").trim();
    const probe = await fetch(`${API}/api/zk402/dashboard/services`, { headers: { "x-api-key": key } });
    if (probe.status === 200) return key;
  }
  const r = await fetch(`${API}/api/zk402/merchants`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ merchantId: m.id, displayName: m.name, settlementAddress: m.addr }),
  });
  const j = await r.json().catch(() => ({}));
  if (j.apiKey) { writeFileSync(m.keyFile, j.apiKey); console.log(`onboarded ${m.id} → ${m.keyFile}`); return j.apiKey; }
  throw new Error(`onboard ${m.id} failed and no saved key (${r.status}): ${JSON.stringify(j)}`);
}

async function ensureService(svc, key, merchantId) {
  const body = {
    serviceId: svc.serviceId, capability: svc.capability, displayName: svc.displayName,
    description: svc.description, endpoint: svc.endpoint, network: NETWORK, facilitator: FACILITATOR,
    pricePolicy: { kind: "per_request", amountSats: svc.price, ...(svc.model ? { model: svc.model } : {}) },
    headlineAmountSats: svc.price, accessThreshold: svc.accessThreshold || "publisher_accepted",
    privacyLevel: svc.privacy || "private",
  };
  const r = await fetch(`${API}/api/zk402/services`, {
    method: "POST", headers: { "content-type": "application/json", "x-api-key": key }, body: JSON.stringify(body),
  });
  if (r.status === 201) return (await r.json()).resourceHash;
  // Already seeded (dup id) → recover its resourceHash from the merchant catalog.
  const list = await fetch(`${API}/api/zk402/dashboard/services`, { headers: { "x-api-key": key } }).then((x) => x.json()).catch(() => ({ services: [] }));
  const found = (list.services || []).find((it) => it.metadata?.serviceId === svc.serviceId);
  if (found) return found.accepts[0].extra.resourceHash;
  throw new Error(`register ${svc.serviceId} failed: ${r.status} ${await r.text().catch(() => "")}`);
}

async function payOnce({ resourceHash, merchant, amount }) {
  const sk = hex(rnd(32));
  const payer = "zkpayer_" + hex(schnorr.getPublicKey(fromHex(sk)));
  const now = Math.floor(Date.now() / 1000);
  const f = {
    network: NETWORK, mode: "exact-payment-intent", intentId: rndId("zki_"), authorizationId: "",
    voucherId: rndId("zkv_"), payer, merchant, amount, feeAmount: 0, resourceHash,
    requestHash: "sha256:" + hex(rnd(32)), validAfter: now, validBefore: now + 120, nonce: rndId("n_"),
    facilitator: FACILITATOR, accessThreshold: "publisher_accepted",
  };
  const sig = signSchnorr(sk, sha256(voucherMsg(f)));
  const accepted = {
    scheme: "zkcoins-publisher", network: NETWORK, amount: String(amount), asset: "btc-sats", payTo: merchant,
    maxTimeoutSeconds: 30, extra: { mode: f.mode, facilitator: FACILITATOR, resourceId: "seed", resourceHash, accessThreshold: f.accessThreshold },
  };
  const payload = {
    intentId: f.intentId, authorizationId: null, voucherId: f.voucherId, payer, merchant, amount: String(amount),
    feeAmount: "0", asset: "btc-sats", resourceHash, requestHash: f.requestHash, validAfter: String(now),
    validBefore: String(now + 120), nonce: f.nonce, signatureScheme: "bip340-schnorr", signature: sig,
  };
  const env = { x402Version: 2, paymentPayload: { x402Version: 2, resource: { url: "https://seed.local/x" }, accepted, payload, extensions: {} }, paymentRequirements: accepted };
  const r = await fetch(`${API}/v2/x402/settle`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(env) });
  const j = await r.json().catch(() => ({}));
  return j.success === true;
}

async function main() {
  mkdirSync(".seed", { recursive: true });
  const keys = {};
  for (const k of Object.keys(MERCHANTS)) keys[k] = await ensureMerchantKey(MERCHANTS[k]);
  console.log("registering services + generating reputation…");
  for (const svc of CATALOG) {
    const rh = await ensureService(svc, keys[svc.m], MERCHANTS[svc.m].id);
    let ok = 0;
    for (let i = 0; i < svc.rep; i++) if (await payOnce({ resourceHash: rh, merchant: MERCHANTS[svc.m].id, amount: svc.price })) ok++;
    console.log(`  ${svc.serviceId.padEnd(18)} ${String(svc.price).padStart(4)} sats  rep ${ok}/${svc.rep} payers`);
  }
  console.log("bazaar seed complete.");
}
main().catch((e) => { console.error("bazaar seed FAILED:", e.message); process.exit(1); });
