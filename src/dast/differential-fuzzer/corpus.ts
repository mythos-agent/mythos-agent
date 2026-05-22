export interface CorpusEntry {
  family: string;
  url: string;
}

/**
 * Hand-curated URL-confusion seed patterns, grouped by family. These are
 * the inputs where real-world URL parsers are known to disagree; the
 * mutator expands them into the full fuzzing input set.
 */
export const CORPUS: CorpusEntry[] = [
  // embedded-at — userinfo "@" confusion (the classic SSRF-bypass family)
  { family: "embedded-at", url: "http://expected.com@evil.com/" },
  { family: "embedded-at", url: "http://expected.com@evil.com@good.com/" },
  { family: "embedded-at", url: "http://user@evil.com:80@good.com/" },
  { family: "embedded-at", url: "http://good.com%2F@evil.com/" },
  { family: "embedded-at", url: "http://good.com#@evil.com/" },
  { family: "embedded-at", url: "http://good.com?@evil.com/" },
  // backslash — backslash treated as slash by some parsers
  { family: "backslash", url: "http://good.com\\@evil.com/" },
  { family: "backslash", url: "http:\\\\evil.com/" },
  { family: "backslash", url: "http://good.com\\.evil.com/" },
  { family: "backslash", url: "https:/\\evil.com/" },
  { family: "backslash", url: "http://evil.com\\good.com/" },
  // missing-slash — scheme without "//"
  { family: "missing-slash", url: "http:evil.com/" },
  { family: "missing-slash", url: "http:/evil.com/" },
  { family: "missing-slash", url: "http:///evil.com/" },
  { family: "missing-slash", url: "https:example.com:8080/" },
  // whitespace — tab / CR / LF inside the URL
  { family: "whitespace", url: "http://good.com\t@evil.com/" },
  { family: "whitespace", url: "http://evil\n.com/" },
  { family: "whitespace", url: "http://evil.com\r/" },
  { family: "whitespace", url: "ht\ttp://evil.com/" },
  { family: "whitespace", url: " http://evil.com/" },
  { family: "whitespace", url: "http://evil.com /" },
  // unicode-idn — unicode, IDN homoglyphs, fullwidth characters
  { family: "unicode-idn", url: "http://evil。com/" },
  { family: "unicode-idn", url: "http://ｅｖｉｌ.com/" },
  { family: "unicode-idn", url: "http://good.com․evil.com/" },
  { family: "unicode-idn", url: "http://xn--80ak6aa92e.com/" },
  { family: "unicode-idn", url: "http://evil .com/" },
  // control-char — NUL and other control bytes (escape sequences, not literal bytes)
  { family: "control-char", url: "http://evil.com\x00.good.com/" },
  { family: "control-char", url: "http://good.com\x01@evil.com/" },
  { family: "control-char", url: "http://evil\x7f.com/" },
  { family: "control-char", url: "http://\x00evil.com/" },
  { family: "control-char", url: "http://evil.com\x0b\x0c/" },
  // userinfo-port — port and userinfo edge cases
  { family: "userinfo-port", url: "http://evil.com:0x50/" },
  { family: "userinfo-port", url: "http://evil.com:+80/" },
  { family: "userinfo-port", url: "http://evil.com:80:80/" },
  { family: "userinfo-port", url: "http://user:pass:extra@evil.com/" },
  { family: "userinfo-port", url: "http://evil.com:/" },
  // ip-oddity — non-canonical IP representations
  { family: "ip-oddity", url: "http://0x7f000001/" },
  { family: "ip-oddity", url: "http://2130706433/" },
  { family: "ip-oddity", url: "http://127.1/" },
  { family: "ip-oddity", url: "http://0177.0.0.1/" },
  { family: "ip-oddity", url: "http://[::ffff:127.0.0.1]/" },
  { family: "ip-oddity", url: "http://127.0.0.1.evil.com/" },
];

export function loadCorpus(): CorpusEntry[] {
  return CORPUS;
}
