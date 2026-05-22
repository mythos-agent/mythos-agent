import { parse as legacyParse } from "node:url";
import urlParse from "url-parse";
import type { ParserId, ParserResult } from "./types.js";

/** WHATWG `URL` — the spec reference. */
function nativeUrl(input: string): ParserResult {
  try {
    const u = new URL(input);
    return {
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port,
      username: u.username,
      password: u.password,
      pathname: u.pathname,
    };
  } catch (e) {
    return { error: String(e) };
  }
}

/** The `url-parse` npm package — deliberately lenient. */
function urlParseAdapter(input: string): ParserResult {
  try {
    const u = urlParse(input);
    return {
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port,
      username: u.username,
      password: u.password,
      pathname: u.pathname,
    };
  } catch (e) {
    return { error: String(e) };
  }
}

/** Node's legacy `url.parse` — deprecated but still widely used. */
function legacyUrl(input: string): ParserResult {
  try {
    const u = legacyParse(input);
    let username: string | undefined;
    let password: string | undefined;
    if (u.auth) {
      const idx = u.auth.indexOf(":");
      username = idx >= 0 ? u.auth.slice(0, idx) : u.auth;
      password = idx >= 0 ? u.auth.slice(idx + 1) : undefined;
    }
    return {
      protocol: u.protocol ?? undefined,
      hostname: u.hostname ?? undefined,
      port: u.port ?? undefined,
      username,
      password,
      pathname: u.pathname ?? undefined,
    };
  } catch (e) {
    return { error: String(e) };
  }
}

/** The three URL parsers under differential test, keyed by id. */
export const PARSERS: Record<ParserId, (input: string) => ParserResult> = {
  "native-url": nativeUrl,
  "url-parse": urlParseAdapter,
  "legacy-url": legacyUrl,
};
