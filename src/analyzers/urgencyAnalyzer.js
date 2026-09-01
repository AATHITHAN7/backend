const LEXICON = [
  // Time pressure / urgency
  { phrase: "immediately", weight: 8, category: "Urgency" },
  { phrase: "act now", weight: 10, category: "Urgency" },
  { phrase: "urgent", weight: 8, category: "Urgency" },
  { phrase: "within 24 hours", weight: 10, category: "Urgency" },
  { phrase: "within 48 hours", weight: 9, category: "Urgency" },
  { phrase: "expire", weight: 8, category: "Urgency" },
  { phrase: "final notice", weight: 10, category: "Urgency" },
  { phrase: "last warning", weight: 10, category: "Urgency" },
  { phrase: "right away", weight: 6, category: "Urgency" },
  { phrase: "time-sensitive", weight: 7, category: "Urgency" },

  // Threat / consequence framing
  { phrase: "suspended", weight: 9, category: "Threat" },
  { phrase: "suspension", weight: 9, category: "Threat" },
  { phrase: "will be closed", weight: 10, category: "Threat" },
  { phrase: "account will be locked", weight: 10, category: "Threat" },
  { phrase: "unauthorized access", weight: 8, category: "Threat" },
  { phrase: "unusual activity", weight: 7, category: "Threat" },
  { phrase: "legal action", weight: 9, category: "Threat" },
  { phrase: "permanently deleted", weight: 9, category: "Threat" },
  { phrase: "restricted", weight: 6, category: "Threat" },

  // Credential / information harvesting
  { phrase: "verify your account", weight: 12, category: "Credential Request" },
  { phrase: "verify your identity", weight: 12, category: "Credential Request" },
  { phrase: "confirm your password", weight: 14, category: "Credential Request" },
  { phrase: "confirm your identity", weight: 12, category: "Credential Request" },
  { phrase: "update your billing", weight: 11, category: "Credential Request" },
  { phrase: "update your payment", weight: 11, category: "Credential Request" },
  { phrase: "click here to verify", weight: 13, category: "Credential Request" },
  { phrase: "login to confirm", weight: 11, category: "Credential Request" },
  { phrase: "re-enter your", weight: 10, category: "Credential Request" },
  { phrase: "social security number", weight: 15, category: "Credential Request" },
  { phrase: "one-time password", weight: 10, category: "Credential Request" },
  { phrase: "otp", weight: 8, category: "Credential Request" },

  // Reward / curiosity bait
  { phrase: "you have won", weight: 10, category: "Reward Bait" },
  { phrase: "claim your prize", weight: 11, category: "Reward Bait" },
  { phrase: "free gift", weight: 8, category: "Reward Bait" },
  { phrase: "congratulations", weight: 6, category: "Reward Bait" },

  // Generic / impersonal address (weak but real signal)
  { phrase: "dear customer", weight: 5, category: "Generic Greeting" },
  { phrase: "dear user", weight: 5, category: "Generic Greeting" },
  { phrase: "valued customer", weight: 4, category: "Generic Greeting" }
];

function analyzeUrgency(subject = "", body = "") {
  const indicators = [];
  const fullText = `${subject}\n${body}`;
  const lowerText = fullText.toLowerCase();

  const matches = [];
  for (const entry of LEXICON) {
    if (lowerText.includes(entry.phrase)) {
      matches.push(entry);
    }
  }

  if (matches.length > 0) {
    // Group by category for readable evidence
    const byCategory = {};
    for (const m of matches) {
      byCategory[m.category] = byCategory[m.category] || [];
      byCategory[m.category].push(m.phrase);
    }
    for (const [category, phrases] of Object.entries(byCategory)) {
      const weight = Math.min(
        30,
        phrases.reduce((sum, p) => sum + LEXICON.find((l) => l.phrase === p).weight, 0)
      );
      const severity = weight >= 20 ? "critical" : weight >= 12 ? "high" : weight >= 7 ? "medium" : "low";
      indicators.push({
        id: `urgency-${category.toLowerCase().replace(/\s+/g, "-")}`,
        category: "Language & Urgency",
        severity,
        weight,
        title: `${category} language detected`,
        detail: `The message body/subject contains ${category.toLowerCase()} phrasing designed to short-circuit careful reading: ${phrases.map((p) => `"${p}"`).join(", ")}.`,
        evidence: phrases.join(", ")
      });
    }
  }

  // Excessive punctuation / shouting, a weak stylistic tell
  const exclamations = (fullText.match(/!/g) || []).length;
  if (exclamations >= 2) {
    indicators.push({
      id: "urgency-exclamation",
      category: "Language & Urgency",
      severity: "low",
      weight: 5,
      title: "Excessive exclamation marks",
      detail: `The message uses ${exclamations} exclamation marks, a stylistic pressure tactic uncommon in genuine account/security notices.`,
      evidence: `${exclamations} "!" characters`
    });
  }

  const capsWords = fullText.match(/\b[A-Z]{4,}\b/g) || [];
  if (capsWords.length >= 2) {
    indicators.push({
      id: "urgency-caps",
      category: "Language & Urgency",
      severity: "low",
      weight: 5,
      title: "Multiple all-caps words",
      detail: `Words in all caps (${[...new Set(capsWords)].slice(0, 5).join(", ")}) are used to simulate urgency/importance.`,
      evidence: [...new Set(capsWords)].join(", ")
    });
  }

  return { indicators, matchedPhrases: matches.map((m) => m.phrase) };
}

module.exports = { analyzeUrgency, LEXICON };
