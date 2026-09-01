const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Combine indicator weights into a single 0-100 risk score.
 * Weights are summed, then compressed with diminishing returns so that
 * five or six firing indicators doesn't automatically imply an absurd
 * multiple-hundred score - it saturates realistically toward 100.
 */
function computeScore(indicators) {
  if (!indicators.length) return 0;
  const rawSum = indicators.reduce((sum, i) => sum + i.weight, 0);
  // Diminishing-returns saturation curve: 1 - e^(-x/60), scaled to 100
  const saturated = 100 * (1 - Math.exp(-rawSum / 65));
  return Math.round(Math.min(100, saturated));
}

function verdictForScore(score) {
  if (score >= 70) {
    return {
      verdict: "Confirmed Phishing",
      riskLevel: "critical",
      summary: "Multiple high-confidence indicators of compromise were found across sender, domain, link, and content analysis. This message should be treated as an active phishing attempt."
    };
  }
  if (score >= 45) {
    return {
      verdict: "Likely Phishing",
      riskLevel: "high",
      summary: "Several strong indicators point to a fraudulent message. Do not interact with links, attachments, or provide any information."
    };
  }
  if (score >= 20) {
    return {
      verdict: "Suspicious",
      riskLevel: "medium",
      summary: "Some indicators of manipulation or spoofing were found. The message should be verified through an independent, trusted channel before taking any action."
    };
  }
  return {
    verdict: "Likely Safe",
    riskLevel: "low",
    summary: "No significant phishing indicators were detected. Standard email hygiene practices still apply."
  };
}

function rankSeverity(indicators) {
  return [...indicators].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.weight - a.weight);
}

function severityCounts(indicators) {
  return indicators.reduce(
    (acc, i) => {
      acc[i.severity] = (acc[i.severity] || 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 }
  );
}

module.exports = { computeScore, verdictForScore, rankSeverity, severityCounts, SEVERITY_RANK };
