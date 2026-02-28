import express from "express";
import crypto from "crypto";

const app = express();
const INNOCIGS_CID = process.env.INNOCIGS_CID;
const INNOCIGS_AUTH = process.env.INNOCIGS_AUTH;
const INNOCIGS_MODE = (process.env.INNOCIGS_MODE || "order").toLowerCase();

const INNOCIGS_ORDER_URL = "https://www.innocigs.com/restapi/order";
const INNOCIGS_DROPSHIP_URL = "https://www.innocigs.com/restapi/dropship";// Logger (optional, gut zum Debuggen)
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
app.post("/webhooks/orders-create", express.raw({ type: "application/json" }), async (req, res) => {
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
if (!INNOCIGS_CID || !INNOCIGS_AUTH) {
  console.log("❌ Missing INNOCIGS_CID or INNOCIGS_AUTH in Render Environment");
  return res.status(500).send("Missing INNOCIGS credentials");
}

const targetUrl = INNOCIGS_MODE === "dropship" ? INNOCIGS_DROPSHIP_URL : INNOCIGS_ORDER_URL;

// 1) Shopify → InnoCigs Order JSON bauen (minimal)
const orderData = {
  // WICHTIG: Das hier ist ein MINIMALER Start. Danach erweitern wir es passend zur InnoCigs Doku.
  ordernumber: String(payload?.id || ""),
  firstname: payload?.shipping_address?.first_name || "",
  lastname: payload?.shipping_address?.last_name || "",
  street: payload?.shipping_address?.address1 || "",
  zip: payload?.shipping_address?.zip || "",
  city: payload?.shipping_address?.city || "",
  country: payload?.shipping_address?.country_code || "DE",
  email: payload?.email || "",
  phone: payload?.shipping_address?.phone || payload?.phone || "",
  items: (payload?.line_items || []).map(i => ({
    // Das wichtigste: wir brauchen die InnoCigs Artikelnummer/SKU!
    // Shopify SKU muss mit InnoCigs Artikelnummer übereinstimmen.
    artnum: i?.sku || "",
    amount: Number(i?.quantity || 0),
  })),
};

// 2) POST an InnoCigs
const innocigsRes = await fetch(targetUrl, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    // InnoCigs Auth: "cid:passwort"
    "Auth": `${INNOCIGS_CID}:${INNOCIGS_AUTH}`,
  },
  body: JSON.stringify(orderData),
});

const innocigsText = await innocigsRes.text();
console.log("📦 InnoCigs response status:", innocigsRes.status);
console.log("📦 InnoCigs response body:", innocigsText);
  // ✅ Bestellung an InnoCigs senden
await sendOrderToInnocigs(payload);

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
async function sendOrderToInnocigs(order) {
  try {
    const res = await fetch(process.env.INNOCIGS_ORDER_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.INNOCIGS_API_KEY}`,
      },
      body: JSON.stringify({
        order_id: order.id,
        customer: {
          name: order.shipping_address?.name,
          street: order.shipping_address?.address1,
          zip: order.shipping_address?.zip,
          city: order.shipping_address?.city,
          country: order.shipping_address?.country,
        },
        items: (order.line_items || []).map((item) => ({
          sku: item.sku,
          quantity: item.quantity,
        })),
      }),
    });

    const text = await res.text();
    console.log("📦 InnoCigs Response:", res.status, text);
  } catch (e) {
    console.error("❌ InnoCigs Error:", e);
  }
}const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
