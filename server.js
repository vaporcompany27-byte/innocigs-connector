import express from "express";

const app = express();
app.use(express.json({ type: "*/*" }));

// Test-Route (Health Check)
app.get("/health", (req, res) => {
  res.status(200).json({ ok: true, service: "innocigs-connector" });
});

// Shopify Webhook Endpoint
app.post("/webhooks/orders-create", (req, res) => {
  console.log("New Shopify Order:", req.body);
  res.status(200).send("Webhook received");
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
