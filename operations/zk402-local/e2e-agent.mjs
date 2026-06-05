// Buyer-side signing tool for the ZK402 local e2e. Self-contained
// (@noble only). The canonical encoders mirror @zk402/sdk and the Rust
// facilitator EXACTLY — correctness is enforced e2e: if an encoding is
// wrong, the node's verify/meter rejects the signature and e2e fails.
import { schnorr } from "@noble/curves/secp256k1";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

const enc = new TextEncoder();
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => Uint8Array.from(s.match(/.{2}/g).map((b) => parseInt(b, 16)));
const b64urlDecode = (s) => {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(Buffer.from(b64, "base64"));
};

const payerOf = (sk) => "zkpayer_" + hex(schnorr.getPublicKey(fromHex(sk)));

function voucherMsg(f) {
  return enc.encode(
    `ZK402-V1\nscheme=zkcoins-publisher\nnetwork=${f.network}\nmode=${f.mode}\n` +
    `intent_id=${f.intentId}\nauthorization_id=${f.authorizationId ?? ""}\nvoucher_id=${f.voucherId}\n` +
    `payer=${f.payer}\nmerchant=${f.merchant}\namount=${f.amount}\nfee_amount=${f.feeAmount}\n` +
    `asset=btc-sats\nresource_hash=${f.resourceHash}\nrequest_hash=${f.requestHash}\n` +
    `valid_after=${f.validAfter}\nvalid_before=${f.validBefore}\nnonce=${f.nonce}\n` +
    `facilitator=${f.facilitator}\naccess_threshold=${f.accessThreshold}`);
}
function streamMsg(f) {
  return enc.encode(
    `ZK402-STREAM-V1\nscheme=zkcoins-publisher\nnetwork=${f.network}\nchannel_id=${f.channelId}\n` +
    `voucher_seq=${f.voucherSeq}\npayer=${f.payer}\nmerchant=${f.merchant}\nasset=btc-sats\n` +
    `max_amount=${f.maxAmount}\ncumulative_authorized=${f.cumulativeAuthorized}\n` +
    `resource_hash=${f.resourceHash}\nrequest_hash=${f.requestHash}\nvalid_after=${f.validAfter}\n` +
    `valid_before=${f.validBefore}\nfacilitator=${f.facilitator}\naccess_threshold=${f.accessThreshold}`);
}
const signSchnorr = (sk, digest) => hex(schnorr.sign(digest, fromHex(sk), new Uint8Array(32))).toUpperCase();

function receiptCanonical(r) {
  const e = Object.entries(r).filter(([k, v]) => k !== "signature" && v != null).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + e.map(([k, v]) => `${JSON.stringify(k)}:${JSON.stringify(v)}`).join(",") + "}";
}

const [cmd, ...rest] = process.argv.slice(2);
const arg = JSON.parse(rest[0] || "{}");

if (cmd === "payer") {
  process.stdout.write(payerOf(arg.sk));
} else if (cmd === "voucher") {
  const f = { ...arg, payer: payerOf(arg.sk) };
  const sig = signSchnorr(arg.sk, sha256(voucherMsg(f)));
  const accepted = {
    scheme: "zkcoins-publisher", network: f.network, amount: String(f.amount), asset: "btc-sats",
    payTo: f.merchant, maxTimeoutSeconds: 30,
    extra: { mode: f.mode, facilitator: f.facilitator, resourceId: "demo", resourceHash: f.resourceHash, accessThreshold: f.accessThreshold },
  };
  const payload = {
    intentId: f.intentId, authorizationId: f.authorizationId ?? null, voucherId: f.voucherId, payer: f.payer,
    merchant: f.merchant, amount: String(f.amount), feeAmount: String(f.feeAmount), asset: "btc-sats",
    resourceHash: f.resourceHash, requestHash: f.requestHash, validAfter: String(f.validAfter),
    validBefore: String(f.validBefore), nonce: f.nonce, signatureScheme: "bip340-schnorr", signature: sig,
  };
  const paymentPayload = { x402Version: 2, resource: { url: "https://demo.local/x" }, accepted, payload, extensions: {} };
  process.stdout.write(JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements: accepted }));
} else if (cmd === "stream") {
  const f = { ...arg, payer: payerOf(arg.sk) };
  const sig = signSchnorr(arg.sk, sha256(streamMsg(f)));
  process.stdout.write(JSON.stringify({
    streamVoucher: {
      network: f.network, channelId: f.channelId, voucherSeq: f.voucherSeq, payer: f.payer, merchant: f.merchant,
      maxAmount: f.maxAmount, cumulativeAuthorized: f.cumulativeAuthorized, resourceHash: f.resourceHash,
      requestHash: f.requestHash, validAfter: f.validAfter, validBefore: f.validBefore,
      facilitator: f.facilitator, accessThreshold: f.accessThreshold,
    },
    signature: sig,
    usage: arg.usage,
  }));
} else if (cmd === "verify-receipt") {
  // arg: { receipt, keys:[{kid,publicKeyBase64url}] }
  const r = arg.receipt, kid = r.kid, sig = r.signature;
  const key = arg.keys.find((k) => k.kid === kid);
  if (!key) { process.stdout.write("NO_KEY"); process.exit(0); }
  let pub = b64urlDecode(key.publicKeyBase64url);
  if (pub.length === 44) pub = pub.slice(12);
  const ok = ed25519.verify(b64urlDecode(sig), enc.encode(receiptCanonical(r)), pub);
  process.stdout.write(ok ? "OK" : "BAD");
} else {
  process.stderr.write(`unknown cmd: ${cmd}\n`); process.exit(2);
}
