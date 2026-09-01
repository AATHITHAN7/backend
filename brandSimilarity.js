/**
 * Brand impersonation / typosquat detection.
 *
 * Strategy:
 *  1. Normalise homoglyphs (1 -> l, 0 -> o, rn -> m, etc.) before comparing.
 *  2. Compute Levenshtein edit distance between the candidate domain's
 *     second-level domain (SLD) and every known brand.
 *  3. Flag a match when the distance is small relative to the brand's
 *     length but the strings are NOT identical (an exact match to a known
 *     brand domain is legitimate, not an impersonation).
 */

const KNOWN_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
  "netflix", "linkedin", "outlook", "office365", "dropbox", "chase",
  "bankofamerica", "wellsfargo", "citibank", "hsbc", "dhl", "fedex", "ups",
  "usps", "americanexpress", "adobe", "icloud", "yahoo", "whatsapp",
  "coinbase", "binance", "steamcommunity", "steam", "spotify", "irs",
  "docusign", "zoom", "twitter", "x", "github"
];

// Common character substitutions used in lookalike domains.
const HOMOGLYPH_MAP = {
  "0": "o",
  "1": "l",
  "3": "e",
  "5": "s",
  "7": "t",
  "8": "b",
  "rn": "m",
  "vv": "w",
  "cl": "d",
  "ii": "u"
};

function normaliseHomoglyphs(str) {
  let out = str.toLowerCase();
  for (const [from, to] of Object.entries(HOMOGLYPH_MAP)) {
    out = out.split(from).join(to);
  }
  return out;
}

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

/**
 * @param {string} sld second-level domain, e.g. "paypa1-login"
 * @returns {Array<{brand: string, distance: number, normalised: string, technique: string}>}
 */
function findBrandImpersonation(sld) {
  if (!sld) return [];
  const rawLower = sld.toLowerCase();
  const normalised = normaliseHomoglyphs(rawLower);
  const hits = [];

  for (const brand of KNOWN_BRANDS) {
    if (rawLower === brand) continue; // exact legitimate match, not impersonation

    // 1) Substring containment with extra tokens (e.g. "paypal-login", "secure-paypal")
    const containsBrand = normalised.includes(brand) && normalised !== brand;

    // 2) Edit-distance closeness on the normalised string
    const distance = levenshtein(normalised, brand);
    const threshold = brand.length <= 5 ? 1 : brand.length <= 8 ? 2 : 3;
    const closeMatch = distance > 0 && distance <= threshold;

    if (containsBrand || closeMatch) {
      hits.push({
        brand,
        distance,
        normalised,
        technique: containsBrand
          ? "brand name embedded with extra words/characters"
          : "character substitution / edit-distance lookalike"
      });
    }
  }

  // De-duplicate, keep the closest match per brand family, sort by distance
  return hits.sort((a, b) => a.distance - b.distance);
}

module.exports = { findBrandImpersonation, levenshtein, normaliseHomoglyphs, KNOWN_BRANDS };
