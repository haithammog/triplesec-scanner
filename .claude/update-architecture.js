#!/usr/bin/env node
/**
 * update-architecture.js
 * 
 * PostToolUse hook: fires after every Write/Edit/MultiEdit.
 * Reads the changed file + current ARCHITECTURE.md, asks Claude
 * whether this change is architecturally meaningful, and if so,
 * updates only the relevant section(s) of ARCHITECTURE.md.
 * 
 * Requires: node 18+ (fetch built-in), jq available in PATH.
 * Place at: .claude/update-architecture.js
 */

const fs = require("fs");
const path = require("path");

// ── Config ────────────────────────────────────────────────────────────────────
const ARCH_FILE = path.join(process.cwd(), "ARCHITECTURE.md");
const MAX_LINES = 150;
const MODEL = "claude-haiku-4-5-20251001"; // fast + cheap for hook use
const SKIP_PATTERNS = [
  /ARCHITECTURE\.md$/,       // don't recurse on the file itself
  /\.claude\//,              // skip hook/config files
  /node_modules\//,
  /\.git\//,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /\.log$/,
  /dist\//,
  /build\//,
  /\.min\.js$/,
  /\.map$/,
];

// ── Read hook input from stdin ────────────────────────────────────────────────
let hookInput = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (hookInput += chunk));
process.stdin.on("end", async () => {
  try {
    const input = JSON.parse(hookInput || "{}");
    const filePath =
      input?.tool_input?.file_path ||
      input?.tool_input?.path ||
      input?.file_path ||
      "";

    if (!filePath) process.exit(0);

    // Skip non-meaningful files
    const relPath = path.relative(process.cwd(), filePath);
    if (SKIP_PATTERNS.some((p) => p.test(relPath))) process.exit(0);

    // Skip if ARCHITECTURE.md doesn't exist yet
    if (!fs.existsSync(ARCH_FILE)) process.exit(0);

    const currentArch = fs.readFileSync(ARCH_FILE, "utf8");

    // Read the changed file (truncate if huge — we only need enough context)
    let changedContent = "";
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, "utf8");
      const lines = raw.split("\n");
      // Send first 120 lines — enough for signatures, imports, class definitions
      changedContent = lines.slice(0, 120).join("\n");
      if (lines.length > 120) changedContent += "\n... (truncated)";
    }

    // ── Ask Claude ──────────────────────────────────────────────────────────
    const prompt = `You are maintaining a living architecture document for a software project.

A file was just modified: ${relPath}

Changed file content (first 120 lines):
\`\`\`
${changedContent}
\`\`\`

Current ARCHITECTURE.md:
\`\`\`markdown
${currentArch}
\`\`\`

Decide if this change is architecturally meaningful. A change IS meaningful if:
- A new module, class, or major function was added or removed
- A function signature or public API changed
- A new external dependency or API integration was added
- The data flow changed
- A known issue was resolved or a new one was introduced
- An entry point (CLI command, API route) was added or changed

A change is NOT meaningful if:
- It is a minor bug fix with no structural impact
- It is a comment, docstring, or formatting change
- It is a test file update that does not reflect structural change
- It touches only internal implementation details with no public impact

Respond ONLY with a valid JSON object, no markdown, no explanation:
{
  "meaningful": true or false,
  "reason": "one sentence explaining why",
  "updated_architecture": "the full updated ARCHITECTURE.md content, or null if not meaningful"
}

Rules for updated_architecture (if meaningful):
- Update ONLY the section(s) affected by this change
- Keep the file under ${MAX_LINES} lines — trim stale entries if needed
- Preserve all sections, even if empty
- Keep module map line references accurate
- Do not add commentary or explanations inside the MD file`;

    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 2048,
        messages: [{ role: "user", content: prompt }],
      }),
    });

    if (!response.ok) {
      // Fail silently — never block Claude Code on a hook error
      process.exit(0);
    }

    const data = await response.json();
    const rawText = data?.content?.[0]?.text || "";

    // Strip possible markdown fences
    const clean = rawText.replace(/```json|```/g, "").trim();
    const result = JSON.parse(clean);

    if (result.meaningful && result.updated_architecture) {
      fs.writeFileSync(ARCH_FILE, result.updated_architecture, "utf8");
      // Echo to Claude Code's context so it knows the doc was updated
      process.stdout.write(
        `[arch] ARCHITECTURE.md updated (${relPath}): ${result.reason}\n`
      );
    }

    process.exit(0);
  } catch (_err) {
    // Always exit 0 — hook errors must never block Claude Code
    process.exit(0);
  }
});
