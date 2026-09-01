/**
 * Produces a prioritised action list for the security team based on the
 * verdict and which indicator categories fired. This is what turns a
 * score into something an analyst can execute on immediately.
 */
function buildRecommendedActions({ riskLevel, indicators, iocDomains = [], iocUrls = [], iocFiles = [] }) {
  const actions = [];
  const categories = new Set(indicators.map((i) => i.category));

  if (riskLevel === "critical" || riskLevel === "high") {
    actions.push({
      priority: "Immediate",
      action: "Quarantine the message",
      detail: "Remove the message from the recipient's mailbox and any other mailboxes it was delivered to (search-and-purge across the mail environment)."
    });
    actions.push({
      priority: "Immediate",
      action: "Block sender domain and IOC URLs at the email gateway / web proxy",
      detail: `Add ${[...iocDomains].join(", ") || "the sender domain"} and any linked URLs to the blocklist to stop further delivery and prevent click-through.`
    });
  }

  if (categories.has("URL") || iocUrls.length > 0) {
    actions.push({
      priority: riskLevel === "low" ? "Optional" : "High",
      action: "Detonate URLs in a sandboxed environment",
      detail: "Submit the linked URLs to an isolated browsing/sandbox tool to confirm the landing page behaviour without exposing an endpoint."
    });
  }

  if (categories.has("Attachment")) {
    actions.push({
      priority: "High",
      action: "Submit attachment for malware analysis",
      detail: "Send the attachment to your sandbox/AV engine (e.g. detonation chamber) before it is opened on any endpoint."
    });
  }

  if (riskLevel === "critical" || riskLevel === "high") {
    actions.push({
      priority: "High",
      action: "Check whether the recipient interacted with the message",
      detail: "Confirm whether links were clicked or credentials were entered. If so, force a password reset and review account/session activity for the affected user immediately."
    });
    actions.push({
      priority: "Medium",
      action: "Search for the same indicators across the organisation",
      detail: "Hunt for the sender domain, subject line, and URLs across all mailboxes to identify other recipients of the same campaign."
    });
  }

  if (riskLevel === "medium") {
    actions.push({
      priority: "Medium",
      action: "Verify through an independent channel",
      detail: "Contact the purported sender/organisation using a known-good phone number or website (not any contact details in the message) before taking any requested action."
    });
    actions.push({
      priority: "Low",
      action: "Monitor for follow-up messages",
      detail: "Flag the sender/domain for continued monitoring in case this is reconnaissance for a follow-up spear-phishing attempt."
    });
  }

  if (riskLevel === "low") {
    actions.push({
      priority: "Low",
      action: "No immediate action required",
      detail: "No significant indicators were found. Retain standard user awareness practices (verify unexpected requests, hover before clicking)."
    });
  }

  actions.push({
    priority: "Standard",
    action: "Log the incident and preserve evidence",
    detail: "Retain original headers, the raw message source, and this report for audit trail and future correlation."
  });

  return actions;
}

module.exports = { buildRecommendedActions };
