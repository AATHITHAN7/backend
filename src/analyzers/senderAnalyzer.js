const { findBrandImpersonation } = require("./brandSimilarity");

const FREE_PROVIDERS = [
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
  "icloud.com", "mail.com", "protonmail.com", "zoho.com", "yandex.com"
];

function extractDomain(email) {
  const at = email.lastIndexOf("@");
  if (at === -1) return null;
  return email.slice(at + 1).trim().toLowerCase();
}

function extractLocalPart(email) {
  const at = email.lastIndexOf("@");
  if (at === -1) return email;
  return email.slice(0, at).trim().toLowerCase();
}

/**
 * @param {string} senderEmail e.g. "security@paypa1-login.com"
 * @param {string} [senderName] display name shown in the mail client, e.g. "PayPal Security"
 * @param {string} [replyTo] optional Reply-To address, if provided/known
 */
function analyzeSender(senderEmail, senderName = "", replyTo = "") {
  const indicators = [];
  const cleanEmail = (senderEmail || "").trim();
  const domain = extractDomain(cleanEmail);
  const local = extractLocalPart(cleanEmail);

  if (!domain) {
    indicators.push({
      id: "sender-malformed",
      category: "Sender Address",
      severity: "high",
      weight: 20,
      title: "Malformed sender address",
      detail: `"${cleanEmail}" does not look like a valid email address.`,
      evidence: cleanEmail
    });
    return { domain: null, local, indicators };
  }

  // 1. Display name says one brand, domain says another
  if (senderName) {
    const nameLower = senderName.toLowerCase();
    const brandHitsInName = require("./brandSimilarity").KNOWN_BRANDS.filter((b) =>
      nameLower.includes(b)
    );
    const domainSld = domain.split(".").slice(-2)[0];
    for (const brand of brandHitsInName) {
      if (!domainSld.includes(brand)) {
        indicators.push({
          id: "sender-display-name-mismatch",
          category: "Sender Address",
          severity: "critical",
          weight: 25,
          title: "Display name impersonates a brand not present in the domain",
          detail: `The display name "${senderName}" references "${brand}", but the actual sending domain is "${domain}". Mail clients show the display name prominently, which attackers exploit to hide the real address.`,
          evidence: `${senderName} <${cleanEmail}>`
        });
      }
    }
  }

  // 2. Free webmail provider claiming to be a company/brand in local part or name
  if (FREE_PROVIDERS.includes(domain)) {
    const suspiciousLocal = /security|support|billing|admin|helpdesk|noreply|account/i.test(local);
    if (suspiciousLocal || senderName) {
      indicators.push({
        id: "sender-free-provider",
        category: "Sender Address",
        severity: "medium",
        weight: 12,
        title: "Official-sounding sender on a free consumer email provider",
        detail: `"${local}@${domain}" uses a free public email provider (${domain}). Legitimate organisational security/billing notices are never sent from consumer webmail.`,
        evidence: cleanEmail
      });
    }
  }

  // 3. Reply-To mismatch
  if (replyTo && replyTo.trim().toLowerCase() !== cleanEmail.toLowerCase()) {
    const replyDomain = extractDomain(replyTo);
    if (replyDomain && replyDomain !== domain) {
      indicators.push({
        id: "sender-reply-to-mismatch",
        category: "Sender Address",
        severity: "high",
        weight: 18,
        title: "Reply-To domain differs from the From domain",
        detail: `Replies would be routed to "${replyTo}" (${replyDomain}) instead of the sending domain "${domain}". This is a common technique to intercept victim replies.`,
        evidence: `From: ${cleanEmail} | Reply-To: ${replyTo}`
      });
    }
  }

  // 4. Brand impersonation directly in the sender's own domain SLD
  const sld = domain.split(".").slice(-2)[0];
  const brandHits = findBrandImpersonation(sld);
  if (brandHits.length > 0) {
    const top = brandHits[0];
    indicators.push({
      id: "sender-domain-lookalike",
      category: "Sender Address",
      severity: "critical",
      weight: 28,
      title: `Sender domain impersonates "${top.brand}"`,
      detail: `The domain "${domain}" resembles the trusted brand "${top.brand}" (${top.technique}). Legitimate mail from ${top.brand} would come from ${top.brand}.com or a verified subdomain of it.`,
      evidence: domain
    });
  }

  // 5. Suspicious local-part role account pretending to be personal/security team
  if (/^(security|support|no-?reply|admin|billing|helpdesk|verify|account)$/i.test(local) && brandHits.length > 0) {
    indicators.push({
      id: "sender-role-account-lookalike",
      category: "Sender Address",
      severity: "medium",
      weight: 8,
      title: "Generic security/support role account on a lookalike domain",
      detail: `"${local}@${domain}" pairs a trust-signalling local part (e.g. "security") with a domain that is not the genuine brand domain.`,
      evidence: cleanEmail
    });
  }

  return { domain, local, indicators };
}

module.exports = { analyzeSender, extractDomain, extractLocalPart, FREE_PROVIDERS };
