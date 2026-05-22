import { describe, it, expect } from "vitest";
import { PARSERS } from "../parsers.js";

describe("PARSERS", () => {
  it("exposes all three parser ids", () => {
    expect(Object.keys(PARSERS).sort()).toEqual(["legacy-url", "native-url", "url-parse"]);
  });

  it("native-url extracts components from a normal URL", () => {
    const r = PARSERS["native-url"]("http://user:pw@example.com:8080/path");
    expect(r.hostname).toBe("example.com");
    expect(r.protocol).toBe("http:");
    expect(r.port).toBe("8080");
    expect(r.username).toBe("user");
    expect(r.error).toBeUndefined();
  });

  it("native-url returns an error result (no throw) on a malformed input", () => {
    const r = PARSERS["native-url"]("not a url");
    expect(r.error).toBeDefined();
    expect(r.hostname).toBeUndefined();
  });

  it("url-parse extracts a hostname", () => {
    expect(PARSERS["url-parse"]("http://example.com/path").hostname).toBe("example.com");
  });

  it("legacy-url extracts a hostname and splits auth into username/password", () => {
    const r = PARSERS["legacy-url"]("http://user:pw@example.com/path");
    expect(r.hostname).toBe("example.com");
    expect(r.username).toBe("user");
    expect(r.password).toBe("pw");
  });
});
