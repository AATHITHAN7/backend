const { v4: uuidv4 } = require("uuid");
const { analyzeSender, extractDomain } = require("./analyzers/senderAnalyzer");
const { analyzeDomain } = require("./analyzers/domainAnalyzer");
const { analyzeUrls } = require("./analyzers/urlAnalyzer");
const { analyzeUrgency } = require("./analyzers/urgencyAnalyzer");
const { analyzeAttachments } = require("./analyzers/attachmentAnalyzer");
const { computeScore, verdictForScore, rankSeverity, severityCounts } = require("./scoring");
const { buildRecommendedActions } = require("./recommendedActions");
const { buildNarrative } = require("./narrative");

function generateReport(input) {
  const {
    senderEmail = "",
    senderName = "",
    replyTo = "",
    subject = "",
    body = "",
    urls = [],
    attachments = []
  } = input;

  const senderResult = analyzeSender(senderEmail, senderName, replyTo);
  const domain = senderResult.domain || extractDomain(senderEmail);
  const domainResult = analyzeDomain(domain);
  const urlResult = analyzeUrls(urls);
  const urgencyResult = analyzeUrgency(subject, body);
  const attachmentResult = analyzeAttachments(attachments);

  const allIndicators = [
    ...senderResult.indicators,
    ...domainResult.indicators.map((i) => ({ ...i })),
    ...urlResult.indicators,
    ...urgencyResult.indicators,
    ...attachmentResult.indicators
  ];

  const ranked = rankSeverity(allIndicators);
  const score = computeScore(ranked);
  const { verdict, riskLevel, summary } = verdictForScore(score);
  const counts = severityCounts(ranked);

  const iocs = {
    emails: [senderEmail].filter(Boolean),
    domains: Array.from(new Set([domain, ...urlResult.iocDomains].filter(Boolean))),
    urls: urlResult.iocUrls,
    attachments: attachmentResult.iocFiles
  };

  const recommendedActions = buildRecommendedActions({
    riskLevel,
    indicators: ranked,
    iocDomains: iocs.domains,
    iocUrls: iocs.urls,
    iocFiles: iocs.attachments
  });

  const narrative = buildNarrative({
    input: { senderEmail, subject },
    verdict,
    score,
    indicators: ranked,
    severityCounts: counts
  });

  const report = {
    id: uuidv4(),
    generatedAt: new Date().toISOString(),
    input: { senderEmail, senderName, replyTo, subject, body, urls, attachments },
    score,
    verdict,
    riskLevel,
    verdictSummary: summary,
    narrative,
    severityCounts: counts,
    indicators: ranked,
    iocs,
    recommendedActions
  };

  return report;
}

module.exports = { generateReport };
