const DANGEROUS_EXTENSIONS = [
  "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe",
  "wsf", "wsh", "msi", "msp", "jar", "ps1", "lnk", "hta", "reg", "cpl"
];

const MACRO_EXTENSIONS = ["docm", "xlsm", "pptm", "dotm", "xltm", "potm"];

const ARCHIVE_EXTENSIONS = ["zip", "rar", "7z", "iso", "img"];

function getExtensionChain(filename) {
  const parts = filename.toLowerCase().split(".");
  return parts.slice(1); // everything after the first dot
}

/**
 * @param {Array<string|{name:string,size?:number}>} attachments
 */
function analyzeAttachments(attachments = []) {
  const indicators = [];
  const iocFiles = [];

  for (const entry of attachments) {
    const name = typeof entry === "string" ? entry : entry.name;
    if (!name || !name.trim()) continue;
    iocFiles.push(name);

    const exts = getExtensionChain(name);
    if (exts.length === 0) continue;
    const finalExt = exts[exts.length - 1];

    // 1. Directly dangerous/executable extension
    if (DANGEROUS_EXTENSIONS.includes(finalExt)) {
      indicators.push({
        id: `attachment-executable-${name}`,
        category: "Attachment",
        severity: "critical",
        weight: 30,
        title: `Executable/script attachment (.${finalExt})`,
        detail: `"${name}" is a ${finalExt.toUpperCase()} file, a format that can run code on the recipient's machine. Legitimate account or security notices never require running an executable.`,
        evidence: name
      });
    }

    // 2. Double-extension disguise (invoice.pdf.exe)
    if (exts.length >= 2 && DANGEROUS_EXTENSIONS.includes(finalExt)) {
      indicators.push({
        id: `attachment-double-ext-${name}`,
        category: "Attachment",
        severity: "critical",
        weight: 20,
        title: "Double file extension used to disguise an executable",
        detail: `"${name}" appears as a document/image at a glance but ends in ".${finalExt}", a technique to trick recipients into opening a hidden executable.`,
        evidence: name
      });
    }

    // 3. Macro-enabled Office document
    if (MACRO_EXTENSIONS.includes(finalExt)) {
      indicators.push({
        id: `attachment-macro-${name}`,
        category: "Attachment",
        severity: "high",
        weight: 18,
        title: `Macro-enabled Office document (.${finalExt})`,
        detail: `"${name}" can contain VBA macros, one of the most common delivery mechanisms for phishing-linked malware payloads.`,
        evidence: name
      });
    }

    // 4. Archive that could conceal the actual payload
    if (ARCHIVE_EXTENSIONS.includes(finalExt)) {
      indicators.push({
        id: `attachment-archive-${name}`,
        category: "Attachment",
        severity: "medium",
        weight: 10,
        title: `Compressed archive attachment (.${finalExt})`,
        detail: `"${name}" is a compressed archive. Archives are frequently used to hide executables from mail-gateway content scanning; contents should be verified in a sandboxed environment before extraction.`,
        evidence: name
      });
    }
  }

  return { indicators, iocFiles };
}

module.exports = { analyzeAttachments, DANGEROUS_EXTENSIONS, MACRO_EXTENSIONS, ARCHIVE_EXTENSIONS };
