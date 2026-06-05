// Minimal Esplora stub for the ZK402 offline test environment.
//
// The zkCoins node needs Esplora only to (a) fetch a chain tip once at
// boot (main.rs get_tip_hash) and (b) feed its block scanner. The ZK402
// facilitator path (verify/settle/dashboard/streaming) never touches
// Bitcoin, so a fixed empty tip is enough: the scanner processes one
// empty block and then idles. The WS endpoint accepts connections and
// stays quiet (one tip frame, then silence).
import http from "node:http";
import { WebSocketServer } from "ws";

const PORT = process.env.PORT ? Number(process.env.PORT) : 3002;
const TIP_HASH = "0000000000000000000000000000000000000000000000000000000000004242";
const TIP_HEIGHT = 0;

const send = (res, code, body, type = "application/json") => {
  res.writeHead(code, { "content-type": type });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
};

const server = http.createServer((req, res) => {
  const path = (req.url || "/").split("?")[0];
  if (path === "/blocks/tip/hash") return send(res, 200, TIP_HASH, "text/plain");
  if (path === "/blocks/tip/height") return send(res, 200, String(TIP_HEIGHT), "text/plain");
  if (path === `/block-height/${TIP_HEIGHT}`) return send(res, 200, TIP_HASH, "text/plain");
  if (path === `/block/${TIP_HASH}/txids`) return send(res, 200, []);
  if (path === `/block/${TIP_HASH}/status`)
    return send(res, 200, { in_best_chain: true, height: TIP_HEIGHT, next_best: null });
  if (path === "/health") return send(res, 200, { ok: true });
  // tx lookups + everything else: not found (no inscriptions in this env).
  return send(res, 404, "not found", "text/plain");
});

// WS at /api/v1/ws: accept, emit one tip frame, then stay silent.
const wss = new WebSocketServer({ server, path: "/api/v1/ws" });
wss.on("connection", (ws) => {
  try {
    ws.send(JSON.stringify({ block: { id: TIP_HASH, height: TIP_HEIGHT } }));
  } catch {}
  ws.on("message", () => {}); // ignore subscribe frames
});

server.listen(PORT, () => console.log(`esplora-stub on :${PORT} (tip ${TIP_HASH})`));
