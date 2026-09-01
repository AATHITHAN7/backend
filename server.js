require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");

const analyzeRoutes = require("./src/routes/analyze");

const app = express();
const PORT = process.env.PORT || 5000;

const corsOrigin = process.env.CORS_ORIGIN && process.env.CORS_ORIGIN !== "*"
  ? process.env.CORS_ORIGIN.split(",").map((s) => s.trim())
  : "*";

app.use(helmet());
app.use(cors({ origin: corsOrigin }));
app.use(express.json({ limit: "2mb" }));
app.use(morgan("tiny"));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});
app.use("/api", limiter);

app.use("/api", analyzeRoutes);

app.get("/", (req, res) => {
  res.json({
    name: "TRACE Phishing Attack Investigation Platform API",
    status: "running",
    endpoints: [
      "POST /api/analyze",
      "GET  /api/report/:id",
      "GET  /api/report/:id/export",
      "GET  /api/health"
    ]
  });
});

app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`TRACE backend listening on port ${PORT}`);
});
