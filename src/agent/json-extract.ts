/**
 * Extract and parse the first complete, brace-balanced JSON object
 * embedded in `text`. String-aware: braces inside JSON string literals
 * do not affect nesting depth. Each `{` position is tried in turn; the
 * first balanced span that `JSON.parse` accepts is returned, so prose
 * before the object (or a stray `{`) does not break extraction.
 *
 * Returns the parsed value, or `null` if no parseable object is found.
 *
 * Replaces the previous greedy `text.match(/\{[\s\S]*\}/)`, which spanned
 * the first `{` to the LAST `}` and failed on prose braces or >1 object.
 */
export function extractJson<T = unknown>(text: string): T | null {
  for (let start = text.indexOf("{"); start !== -1; start = text.indexOf("{", start + 1)) {
    const span = balancedSpan(text, start);
    if (span === null) continue;
    try {
      return JSON.parse(span) as T;
    } catch {
      // This `{` did not begin a valid object; try the next one.
    }
  }
  return null;
}

/**
 * Return the substring from `start` (a `{`) to its matching `}`,
 * ignoring braces inside double-quoted string literals. Returns `null`
 * if the braces never balance before the end of `text`.
 */
function balancedSpan(text: string, start: number): string | null {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}
