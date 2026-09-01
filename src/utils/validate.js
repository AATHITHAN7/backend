function validateAnalyzeInput(body) {
  const errors = [];
  if (!body || typeof body !== "object") {
    return ["Request body must be a JSON object."];
  }
  if (!body.senderEmail || typeof body.senderEmail !== "string" || !body.senderEmail.includes("@")) {
    errors.push("senderEmail is required and must be a valid-looking email address.");
  }
  if (body.urls && !Array.isArray(body.urls)) {
    errors.push("urls must be an array of strings or {href, text} objects.");
  }
  if (body.attachments && !Array.isArray(body.attachments)) {
    errors.push("attachments must be an array of strings or {name} objects.");
  }
  if (body.subject && typeof body.subject !== "string") errors.push("subject must be a string.");
  if (body.body && typeof body.body !== "string") errors.push("body must be a string.");
  return errors;
}

module.exports = { validateAnalyzeInput };
