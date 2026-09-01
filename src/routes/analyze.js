const express = require("express");
const { generateReport } = require("../reportGenerator");
const reportStore = require("../store/reportStore");
const { renderHtmlReport } = require("../utils/htmlExport");
const { validateAnalyzeInput } = require("../utils/validate");

const router = express.Router();

// POST /api/analyze -> run full analysis, persist the report in memory, return it
router.post("/analyze", (req, res) => {
  const errors = validateAnalyzeInput(req.body);
  if (errors.length) {
    return res.status(400).json({ error: "Invalid input", details: errors });
  }
  try {
    const report = generateReport(req.body);
    reportStore.save(report);
    return res.status(201).json(report);
  } catch (err) {
    console.error("Analysis failed:", err);
    return res.status(500).json({ error: "Analysis failed", details: err.message });
  }
});

// GET /api/report/:id -> fetch a previously generated report (shareable link target)
router.get("/report/:id", (req, res) => {
  const report = reportStore.get(req.params.id);
  if (!report) {
    return res.status(404).json({ error: "Report not found or has expired." });
  }
  return res.json(report);
});

// GET /api/report/:id/export -> self-contained HTML version of the report
router.get("/report/:id/export", (req, res) => {
  const report = reportStore.get(req.params.id);
  if (!report) {
    return res.status(404).send("<h1>Report not found or has expired.</h1>");
  }
  res.setHeader("Content-Type", "text/html");
  res.setHeader("Content-Disposition", `inline; filename="incident-report-${report.id}.html"`);
  return res.send(renderHtmlReport(report));
});

// GET /api/health -> simple liveness probe
router.get("/health", (req, res) => {
  res.json({ status: "ok", reportsInMemory: reportStore.size() });
});

module.exports = router;
