import { describe, it, expect } from "vitest";
import { extractJson } from "../json-extract.js";

describe("extractJson", () => {
  it("parses a bare JSON object", () => {
    expect(extractJson('{"a":1}')).toEqual({ a: 1 });
  });
  it("parses JSON prefaced by prose", () => {
    expect(extractJson('Here is my answer:\n{"a":1}')).toEqual({ a: 1 });
  });
  it("ignores braces inside string values", () => {
    expect(extractJson('{"a":"text with } brace"}')).toEqual({ a: "text with } brace" });
  });
  it("returns the first valid object when two are present", () => {
    expect(extractJson('{"a":1} {"b":2}')).toEqual({ a: 1 });
  });
  it("skips a prose brace and finds the real object", () => {
    expect(extractJson('note: use {curly} carefully. {"a":1}')).toEqual({ a: 1 });
  });
  it("handles nested objects", () => {
    expect(extractJson('{"a":{"b":{"c":1}}}')).toEqual({ a: { b: { c: 1 } } });
  });
  it("returns null for truncated JSON", () => {
    expect(extractJson('{"a":1, "b":')).toBeNull();
  });
  it("returns null when there is no object", () => {
    expect(extractJson("no json here")).toBeNull();
  });
  it("handles an escaped backslash before a closing quote", () => {
    // JS source '{"a":"x\\\\"}' is the text  {"a":"x\\"}  whose JSON
    // string value decodes to  x\  (one backslash).
    expect(extractJson('{"a":"x\\\\"}')).toEqual({ a: "x\\" });
  });
  it("returns null for an unterminated string literal", () => {
    expect(extractJson('{"a":"oops')).toBeNull();
  });
});
