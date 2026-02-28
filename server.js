import express from "express";
import crypto from "crypto";

const app = express();

// Logger (optional, gut zum Debuggen)
app.use((req, res, next) => {
  console.log("INCOMING:", req.method, req.path);
  next();
});

// Health
app.get("/health", (req, res) => {
  res.status(200).json({ ok: true, service: "innocigs-connector" });
});

// Root
app.get("/", (req, res) => {
  res.status(200).send("InnoCigs Connector is running 🚀");
});
// Shopify Webhook Endpoint (MUSS VOR express.json() stehen!)
app.post("/webhooks/orders-create", express.raw({ type: "application/json" }), (req, res) => {
  const secret = process.env.SHOPIFY_WEBHOOK_SECRET;
  if (!secret) return res.status(500).send("Missing SHOPIFY_WEBHOOK_SECRET");

  const hmacHeader = req.get("X-Shopify-Hmac-Sha256") || "";
  const digest = crypto
    .createHmac("sha256", secret)
    .update(req.body)              // <- Buffer, NICHT JSON.stringify
    .digest("base64");

  if (digest !== hmacHeader) return res.status(401).send("Invalid HMAC");

  const payload = JSON.parse(req.body.toString("utf8"));
  console.log("✅ Verified Shopify Order:", payload?.id);

  return res.status(200).send("ok");
});
// Test-Route (Health Check)
app.get("/health", (req, res) => {
  res.status(200).json({ ok: true, service: "innocigs-connector" });
});// ===== Shopify OAuth (Install/Login) =====
const tokens = new Map(); // shop -> access_token
const states = new Map(); // shop -> state

function buildHmacMessage(query) {
  const { hmac, signature, ...rest } = query;
  return Object.keys(rest)
    .sort()
    .map((k) => `${k}=${Array.isArray(rest[k]) ? rest[k].join(",") : rest[k]}`)
    .join("&");
}

function verifyShopifyHmac(query) {
  const secret = process.env.SHOPIFY_API_SECRET;
  const provided = query.hmac;
  if (!secret || !provided) return false;

  const msg = buildHmacMessage(query);
  const calculated = crypto.createHmac("sha256", secret).update(msg).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(calculated, "utf8"), Buffer.from(provided, "utf8"));
}

// Start OAuth
app.get("/auth", (req, res) => {
  const shop = req.query.shop || process.env.SHOPIFY_SHOP;
  if (!shop) return res.status(400).send("Missing shop");

  const apiKey = process.env.SHOPIFY_API_KEY;
  const scopes = process.env.SHOPIFY_SCOPES || "read_products,write_products,read_orders";
  const appUrl = process.env.SHOPIFY_APP_URL;

  if (!apiKey || !appUrl) return res.status(500).send("Missing SHOPIFY_API_KEY or SHOPIFY_APP_URL");

  const state = crypto.randomBytes(16).toString("hex");
  states.set(shop, state);

  const redirectUri = `${appUrl}/auth/callback`;
  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(apiKey)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(installUrl);
});

// OAuth callback
app.get("/auth/callback", async (req, res) => {
  const { shop, code, state } = req.query;

  if (!shop || !code || !state) return res.status(400).send("Missing params");
  if (states.get(shop) !== state) return res.status(401).send("Invalid state");
  if (!verifyShopifyHmac(req.query)) return res.status(401).send("Invalid HMAC");

  const apiKey = process.env.SHOPIFY_API_KEY;
  const apiSecret = process.env.SHOPIFY_API_SECRET;

  const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: apiKey,
      client_secret: apiSecret,
      code,
    }),
  });

  const data = await tokenRes.json();
  if (!data.access_token) return res.status(500).send(`No access_token: ${JSON.stringify(data)}`);

  tokens.set(shop, data.access_token);

  return res.status(200).send("✅ App connected. Access token saved.");
});
// ===== /Shopify OAuth =====// Shopify Auth Route

app.get("/", (req, res) => {
  res.status(200).send("InnoCigs Connector is running 🚀");
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
