/**
 * Builds a plain-language narrative paragraph from the structured findings,
 * so the "write-up" the security team receives is generated automatically
 * rather than composed by hand.
 */
function buildNarrative({ input, verdict, score, indicators, severityCounts }) {
  const { senderEmail, subject } = input;
  const topReasons = [...indicators]
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((i) => i.title.toLowerCase());

  const reasonClause =
    topReasons.length > 0
      ? `The strongest contributing factors were: ${topReasons.join("; ")}.`
      : "No material risk factors were identified in the supplied content.";

  const countClause = `In total, ${indicators.length} indicator${indicators.length === 1 ? "" : "s"} fired (${severityCounts.critical} critical, ${severityCounts.high} high, ${severityCounts.medium} medium, ${severityCounts.low} low).`;

  return (
    `An automated analysis of the message purportedly from "${senderEmail || "unknown sender"}" ` +
    `with subject "${subject || "(no subject)"}" produced a risk score of ${score}/100, ` +
    `resulting in a verdict of "${verdict}". ${reasonClause} ${countClause} ` +
    `This report was generated automatically from sender, domain, URL, attachment, and language analysis; ` +
    `it is intended to support — not replace — analyst judgement.`
  );
}

module.exports = { buildNarrative };
