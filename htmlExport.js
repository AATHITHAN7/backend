function esc(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

const RISK_COLORS = {
  critical: "#e5484d",
  high: "#f5a524",
  medium: "#f5d90a",
  low: "#3dd68c"
};

function renderHtmlReport(report) {
  const color = RISK_COLORS[report.riskLevel] || "#8891a8";
  const indicatorsHtml = report.indicators
    .map(
      (i) => `
      <tr>
        <td style="padding:10px 12px;border-bottom:1px solid #253150;font-family:'IBM Plex Mono',monospace;font-size:11px;color:${RISK_COLORS[i.severity]};text-transform:uppercase;">${esc(i.severity)}</td>
        <td style="padding:10px 12px;border-bottom:1px solid #253150;font-size:13px;color:#8891a8;">${esc(i.category)}</td>
        <td style="padding:10px 12px;border-bottom:1px solid #253150;font-size:14px;color:#e4e8f1;"><strong>${esc(i.title)}</strong><br/><span style="color:#8891a8;font-size:12.5px;">${esc(i.detail)}</span></td>
        <td style="padding:10px 12px;border-bottom:1px solid #253150;font-family:'IBM Plex Mono',monospace;font-size:11px;color:#5b8def;">${esc(i.weight)}</td>
      </tr>`
    )
    .join("");

  const actionsHtml = report.recommendedActions
    .map(
      (a) => `<li style="margin-bottom:10px;"><strong style="color:#5b8def;">[${esc(a.priority)}]</strong> ${esc(a.action)} — <span style="color:#8891a8;">${esc(a.detail)}</span></li>`
    )
    .join("");

  const iocBlock = (label, list) =>
    list && list.length
      ? `<div style="margin-bottom:10px;"><span style="color:#8891a8;font-size:11px;text-transform:uppercase;letter-spacing:.05em;">${esc(label)}</span><br/><span style="font-family:'IBM Plex Mono',monospace;font-size:13px;color:#e4e8f1;">${list.map(esc).join("<br/>")}</span></div>`
      : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Incident Report ${esc(report.id)}</title>
<style>
  body { background:#0e1420; color:#e4e8f1; font-family: -apple-system, Inter, Segoe UI, sans-serif; margin:0; padding:40px; }
  .sheet { max-width: 860px; margin: 0 auto; background:#141b2c; border:1px solid #253150; border-radius:4px; padding:40px; }
  h1 { font-family: 'Space Grotesk', sans-serif; font-size: 24px; margin:0 0 4px; }
  .meta { color:#8891a8; font-size:12.5px; margin-bottom: 28px; font-family:'IBM Plex Mono',monospace; }
  .stamp { display:inline-block; border:3px solid ${color}; color:${color}; font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:20px; letter-spacing:.08em; padding:8px 18px; transform: rotate(-3deg); border-radius:4px; margin-bottom:20px; }
  table { width:100%; border-collapse:collapse; margin-top:10px; }
  .section-title { font-family:'Space Grotesk',sans-serif; font-size:15px; text-transform:uppercase; letter-spacing:.06em; color:#8891a8; margin:32px 0 12px; border-bottom:1px solid #253150; padding-bottom:8px;}
</style>
</head>
<body>
  <div class="sheet">
    <h1>TRACE — Incident Report</h1>
    <div class="meta">ID: ${esc(report.id)} &middot; Generated: ${esc(report.generatedAt)}</div>
    <div class="stamp">${esc(report.verdict.toUpperCase())}</div>
    <p style="font-size:14px;color:#c3c9d9;line-height:1.6;">${esc(report.verdictSummary)}</p>
    <p style="font-size:13px;color:#8891a8;line-height:1.7;">${esc(report.narrative)}</p>

    <div class="section-title">Risk Score</div>
    <div style="font-family:'Space Grotesk',sans-serif;font-size:36px;color:${color};">${esc(report.score)}<span style="font-size:16px;color:#8891a8;">/100</span></div>

    <div class="section-title">Indicators of Manipulation (${report.indicators.length})</div>
    <table>
      <thead><tr>
        <th style="text-align:left;padding:8px 12px;font-size:11px;color:#8891a8;text-transform:uppercase;">Severity</th>
        <th style="text-align:left;padding:8px 12px;font-size:11px;color:#8891a8;text-transform:uppercase;">Category</th>
        <th style="text-align:left;padding:8px 12px;font-size:11px;color:#8891a8;text-transform:uppercase;">Finding</th>
        <th style="text-align:left;padding:8px 12px;font-size:11px;color:#8891a8;text-transform:uppercase;">Weight</th>
      </tr></thead>
      <tbody>${indicatorsHtml || `<tr><td colspan="4" style="padding:14px;color:#8891a8;">No indicators fired.</td></tr>`}</tbody>
    </table>

    <div class="section-title">Indicators of Compromise (IOCs)</div>
    ${iocBlock("Sender email", report.iocs.emails)}
    ${iocBlock("Domains", report.iocs.domains)}
    ${iocBlock("URLs", report.iocs.urls)}
    ${iocBlock("Attachments", report.iocs.attachments)}

    <div class="section-title">Recommended Actions</div>
    <ul style="padding-left:18px;font-size:13.5px;line-height:1.6;color:#e4e8f1;">${actionsHtml || "<li>No actions required.</li>"}</ul>

    <div class="meta" style="margin-top:36px;">Generated automatically by TRACE — Phishing Attack Investigation Platform. This report is evidence-based and does not require manual write-up.</div>
  </div>
</body>
</html>`;
}

module.exports = { renderHtmlReport };
