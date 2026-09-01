/**
 * Purely in-memory store. Reports vanish on server restart by design —
 * this project intentionally avoids a database. A share link is only as
 * durable as the running process, which is acceptable for an
 * investigation/triage tool where reports are exported (JSON/HTML) for
 * permanent retention by the security team.
 */
const TTL_MS = (Number(process.env.REPORT_TTL_MINUTES) || 1440) * 60 * 1000;

const reports = new Map();

function save(report) {
  reports.set(report.id, { report, expiresAt: Date.now() + TTL_MS });
  return report;
}

function get(id) {
  const entry = reports.get(id);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    reports.delete(id);
    return null;
  }
  return entry.report;
}

function cleanup() {
  const now = Date.now();
  for (const [id, entry] of reports.entries()) {
    if (now > entry.expiresAt) reports.delete(id);
  }
}

setInterval(cleanup, 10 * 60 * 1000).unref();

module.exports = { save, get, size: () => reports.size };
