import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ type: "*/*" }));

// Test-Route (Health Check)
app.get("/health", (req, res) => {
  res.status(200).json({ ok: true, service: "innocigs-connector" });
});
// Shopify Auth Route
app.get("/auth", (req, res) => {
  res.status(200).send("auth route ok");
});
app.get("/", (req, res) => {
  res.status(200).send("InnoCigs Connector is running 🚀");
});
app.get("/auth/callback", (req, res) => {
  res.status(200).send("callback route ok");
});// Shopify Webhook Endpoint
app.post("/webhooks/orders-create", (req, res) => {
  const secret = process.env.SHOPIFY_WEBHOOK_SECRET;
  if (!secret) return res.status(500).send("Missing SHOPIFY_WEBHOOK_SECRET");

  const hmacHeader = req.get("X-Shopify-Hmac-Sha256") || "";
  const rawBody = JSON.stringify(req.body);

  const digest = crypto3
    .createHmac("sha256", secret)
    .update(rawBody, "utf8")
    .digest("base64");

  if (digest !== hmacHeader) return res.status(401).send("Invalid HMAC");

  console.log("✅ Verified Shopify Order:", req.body);
  res.status(200).send("ok");
});
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
