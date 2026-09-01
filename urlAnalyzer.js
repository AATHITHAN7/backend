const { findBrandImpersonation } = require("./brandSimilarity");
const { analyzeDomain } = require("./domainAnalyzer");

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly", "lnkd.in"
];

const SUSPICIOUS_PATH_KEYWORDS = [
  "verify", "login", "signin", "secure", "account", "update", "confirm",
  "billing", "suspend", "unlock", "reset", "password", "authenticate", "validate"
];

function safeParseUrl(raw) {
  try {
    // Add a scheme if missing so URL() can parse bare "domain.com/path" input
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
    return new URL(hasScheme ? raw : `http://${raw}`);
  } catch {
    return null;
  }
}

/**
 * @param {Array<string|{href:string, text?:string}>} urls
 */
function analyzeUrls(urls = []) {
  const indicators = [];
  const iocUrls = [];
  const iocDomains = new Set();

  for (const entry of urls) {
    const raw = typeof entry === "string" ? entry : entry.href;
    const displayText = typeof entry === "string" ? null : entry.text || null;
    if (!raw || !raw.trim()) continue;

    const parsed = safeParseUrl(raw.trim());
    if (!parsed) {
      indicators.push({
        id: `url-malformed-${raw}`,
        category: "URL",
        severity: "low",
        weight: 5,
        title: "Malformed link could not be parsed",
        detail: `"${raw}" is not a well-formed URL.`,
        evidence: raw
      });
      continue;
    }

    iocUrls.push(parsed.href);
    iocDomains.add(parsed.hostname.toLowerCase());

    // 1. Plain HTTP instead of HTTPS
    if (parsed.protocol === "http:") {
      indicators.push({
        id: `url-no-tls-${parsed.href}`,
        category: "URL",
        severity: "medium",
        weight: 10,
        title: "Link uses unencrypted HTTP",
        detail: `"${parsed.href}" does not use HTTPS. Any credentials submitted on this page would travel in clear text, and modern brands do not link to plain HTTP login pages.`,
        evidence: parsed.href
      });
    }

    // 2. Raw IP address as host
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) {
      indicators.push({
        id: `url-ip-host-${parsed.href}`,
        category: "URL",
        severity: "critical",
        weight: 25,
        title: "Link points to a raw IP address, not a domain name",
        detail: `"${parsed.href}" resolves directly to an IP address (${parsed.hostname}) rather than a named, registered domain — a strong phishing/malware-hosting signal.`,
        evidence: parsed.href
      });
    }

    // 3. "@" trick — everything before @ is cosmetic, browser navigates to what follows
    if (raw.includes("@") && !raw.trim().startsWith("mailto:")) {
      indicators.push({
        id: `url-at-symbol-${parsed.href}`,
        category: "URL",
        severity: "critical",
        weight: 22,
        title: '"@" obfuscation in URL',
        detail: `The link contains an "@" symbol. Browsers ignore everything before "@" and navigate to what follows it, so attackers prefix a fake trusted-looking domain before "@" to disguise the real destination.`,
        evidence: raw
      });
    }

    // 4. URL shortener hiding the real destination
    if (SHORTENERS.includes(parsed.hostname.toLowerCase())) {
      indicators.push({
        id: `url-shortener-${parsed.href}`,
        category: "URL",
        severity: "medium",
        weight: 12,
        title: "Link uses a URL shortener",
        detail: `"${parsed.hostname}" masks the true destination domain until the link is clicked, a common technique to bypass quick visual checks and email filters.`,
        evidence: parsed.href
      });
    }

    // 5. Anchor/display text mismatch (link says paypal.com but points elsewhere)
    if (displayText) {
      const textDomainMatch = displayText.match(/([a-z0-9-]+\.)+[a-z]{2,}/i);
      if (textDomainMatch) {
        const textDomain = textDomainMatch[0].toLowerCase();
        if (!parsed.hostname.toLowerCase().endsWith(textDomain) && !textDomain.endsWith(parsed.hostname.toLowerCase())) {
          indicators.push({
            id: `url-anchor-mismatch-${parsed.href}`,
            category: "URL",
            severity: "critical",
            weight: 24,
            title: "Displayed link text does not match the real destination",
            detail: `The message shows the link as "${displayText}" (implying ${textDomain}), but it actually points to "${parsed.hostname}". This is a classic disguised-hyperlink technique.`,
            evidence: `Displayed: ${displayText} -> Actual: ${parsed.href}`
          });
        }
      }
    }

    // 6. Suspicious keywords in the path/query pushing toward credential entry
    const pathAndQuery = (parsed.pathname + parsed.search).toLowerCase();
    const matchedKeywords = SUSPICIOUS_PATH_KEYWORDS.filter((k) => pathAndQuery.includes(k));
    if (matchedKeywords.length > 0) {
      indicators.push({
        id: `url-credential-path-${parsed.href}`,
        category: "URL",
        severity: "medium",
        weight: 10 + Math.min(matchedKeywords.length - 1, 2) * 4,
        title: "Link path targets account/credential action",
        detail: `The URL path contains credential-harvesting language: ${matchedKeywords.join(", ")}. Combined with sender/domain red flags, this strongly suggests a fake login page.`,
        evidence: parsed.href
      });
    }

    // 7. Domain-level checks reused for the link's host (TLD, hyphens, brand similarity, punycode)
    const domainResult = analyzeDomain(parsed.hostname.toLowerCase());
    for (const ind of domainResult.indicators) {
      indicators.push({
        ...ind,
        id: `url-${ind.id}-${parsed.href}`,
        category: "URL",
        title: `Link domain: ${ind.title}`,
        evidence: parsed.href
      });
    }
  }

  return { indicators, iocUrls, iocDomains: Array.from(iocDomains) };
}

module.exports = { analyzeUrls, SHORTENERS, SUSPICIOUS_PATH_KEYWORDS };
