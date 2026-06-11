/**
 * Patterns that must never appear in smoke test output.
 * These are structural checks — we verify their absence, never their value.
 */
const SECRET_PATTERNS = [
  /cfut_[a-zA-Z0-9_-]{20,}/,   // Cloudflare tokens
  /sk-ant-[a-zA-Z0-9_-]{20,}/,  // Anthropic API keys
  /sk-[a-zA-Z0-9_-]{20,}/,      // OpenAI API keys
  /AIza[a-zA-Z0-9_-]{35,}/,     // Gemini API keys
  /cs_[a-zA-Z0-9_-]{20,}/,      // CrowdSec LAPI keys (common prefix)
];

/**
 * Asserts the given text contains no recognizable secret patterns.
 * Call on every page body before asserting content.
 */
export function assertNoSecretLeakage(text: string, location: string): void {
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`[SMOKE SECURITY] Possible secret leaked at ${location}. Pattern: ${pattern}`);
    }
  }
}

/**
 * Redacts any recognizable secrets from a string for safe logging.
 */
export function redact(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(new RegExp(pattern.source, 'g'), '[REDACTED]');
  }
  return out;
}
