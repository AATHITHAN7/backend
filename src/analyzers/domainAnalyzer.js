const { findBrandImpersonation } = require("./brandSimilarity");

const SUSPICIOUS_TLDS = [
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "zip",
  "mov", "work", "support", "loan", "win", "review", "kim", "country",
  "gdn", "men", "party", "science", "date", "faith", "icu", "buzz"
];

function analyzeDomain(domain) {
  const indicators = [];
  if (!domain) return { indicators };

  const parts = domain.split(".");
  const tld = parts[parts.length - 1];
  const sld = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  const subdomainCount = Math.max(0, parts.length - 2);

  // 1. Suspicious / cheap TLD frequently abused for throwaway phishing infrastructure
  if (SUSPICIOUS_TLDS.includes(tld)) {
    indicators.push({
      id: "domain-suspicious-tld",
      category: "Domain",
      severity: "medium",
      weight: 12,
      title: `High-abuse top-level domain ".${tld}"`,
      detail: `".${tld}" domains are inexpensive, largely unregulated, and disproportionately used for short-lived phishing campaigns.`,
      evidence: domain
    });
  }

  // 2. Punycode / IDN homograph domain
  if (domain.startsWith("xn--") || parts.some((p) => p.startsWith("xn--"))) {
    indicators.push({
      id: "domain-punycode",
      category: "Domain",
      severity: "critical",
      weight: 25,
      title: "Punycode-encoded (internationalised) domain",
      detail: `"${domain}" is encoded as punycode, a technique used to render look-alike characters from other alphabets that visually mimic a trusted Latin-script brand name.`,
      evidence: domain
    });
  }

  // 3. Hyphens / digits stuffed into the SLD (paypa1-login, secure-appleid-support)
  const hyphenCount = (sld.match(/-/g) || []).length;
  if (hyphenCount >= 1) {
    indicators.push({
      id: "domain-hyphenated",
      category: "Domain",
      severity: hyphenCount >= 2 ? "high" : "medium",
      weight: hyphenCount >= 2 ? 16 : 10,
      title: "Hyphenated domain combining a brand-style word with a trust word",
      detail: `"${sld}" concatenates words with hyphens (e.g. brand + "login"/"secure"/"verify"). Genuine brands overwhelmingly register clean, single-word domains.`,
      evidence: domain
    });
  }

  const hasDigitSubForLetter = /[0-9]/.test(sld) && /[a-z]/.test(sld);
  if (hasDigitSubForLetter) {
    indicators.push({
      id: "domain-digit-substitution",
      category: "Domain",
      severity: "high",
      weight: 15,
      title: "Digits mixed into an otherwise alphabetic brand-like name",
      detail: `"${sld}" mixes numerals with letters (e.g. "1" for "l", "0" for "o"), a classic homoglyph substitution used to visually imitate a trusted domain.`,
      evidence: domain
    });
  }

  // 4. Excessive subdomain depth (paypal.com.verify-account.security-check.xyz)
  if (subdomainCount >= 2) {
    indicators.push({
      id: "domain-excess-subdomains",
      category: "Domain",
      severity: "high",
      weight: 14,
      title: "Excessive subdomain nesting",
      detail: `"${domain}" has ${subdomainCount} subdomain levels. Attackers often bury a real brand name as a subdomain of an unrelated registered domain to deceive quick visual inspection.`,
      evidence: domain
    });
  }

  // 5. Brand impersonation via edit-distance / embedding
  const brandHits = findBrandImpersonation(sld);
  if (brandHits.length > 0) {
    const top = brandHits[0];
    indicators.push({
      id: "domain-brand-similarity",
      category: "Domain",
      severity: "critical",
      weight: 27,
      title: `Domain closely resembles trusted brand "${top.brand}"`,
      detail: `Edit-distance/normalisation analysis found "${domain}" is a close lookalike of "${top.brand}.com" (${top.technique}, similarity distance ${top.distance}).`,
      evidence: domain
    });
  }

  // 6. Overly long SLD (often auto-generated phishing kit domains)
  if (sld.replace(/-/g, "").length >= 20) {
    indicators.push({
      id: "domain-long-sld",
      category: "Domain",
      severity: "low",
      weight: 6,
      title: "Unusually long domain name",
      detail: `"${sld}" is unusually long for a brand domain, consistent with auto-generated phishing infrastructure.`,
      evidence: domain
    });
  }

  return { tld, sld, subdomainCount, indicators };
}

module.exports = { analyzeDomain, SUSPICIOUS_TLDS };
