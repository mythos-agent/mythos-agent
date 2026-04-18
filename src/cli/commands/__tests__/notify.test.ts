import { describe, it, expect } from "vitest";
import { assertPublicWebhookUrl } from "../notify.js";

describe("assertPublicWebhookUrl", () => {
  it("accepts public https URLs", () => {
    expect(assertPublicWebhookUrl("https://hooks.slack.com/services/abc").toString()).toContain(
      "hooks.slack.com"
    );
    expect(() => assertPublicWebhookUrl("https://discord.com/api/webhooks/123/xyz")).not.toThrow();
    expect(() =>
      assertPublicWebhookUrl("https://example.webhook.office.com/webhookb2/abc")
    ).not.toThrow();
  });

  it("accepts public http URLs (left to operator discretion)", () => {
    expect(() => assertPublicWebhookUrl("http://example.com/hook")).not.toThrow();
  });

  it("rejects malformed URLs", () => {
    expect(() => assertPublicWebhookUrl("not-a-url")).toThrow(/Invalid webhook URL/);
    expect(() => assertPublicWebhookUrl("")).toThrow(/Invalid webhook URL/);
  });

  it("rejects non-http(s) schemes", () => {
    expect(() => assertPublicWebhookUrl("ftp://example.com/hook")).toThrow(/must use http/);
    expect(() => assertPublicWebhookUrl("file:///etc/passwd")).toThrow(/must use http/);
    expect(() => assertPublicWebhookUrl("gopher://example.com/_foo")).toThrow(/must use http/);
  });

  it("rejects localhost and .localhost", () => {
    expect(() => assertPublicWebhookUrl("http://localhost/hook")).toThrow(/internal host/);
    expect(() => assertPublicWebhookUrl("https://localhost:8080/hook")).toThrow(/internal host/);
    expect(() => assertPublicWebhookUrl("http://svc.localhost/hook")).toThrow(/internal host/);
  });

  it("rejects cloud metadata hostnames", () => {
    expect(() => assertPublicWebhookUrl("http://metadata.google.internal/computeMetadata")).toThrow(
      /internal host/
    );
    expect(() => assertPublicWebhookUrl("http://metadata/")).toThrow(/internal host/);
    expect(() => assertPublicWebhookUrl("http://metadata.azure.com/")).toThrow(/internal host/);
  });

  it("rejects AWS/GCP IMDS IP (169.254.169.254)", () => {
    expect(() =>
      assertPublicWebhookUrl("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    ).toThrow(/private\/metadata IP/);
  });

  it("rejects RFC 1918 private IPv4", () => {
    expect(() => assertPublicWebhookUrl("http://10.0.0.1/")).toThrow(/private/);
    expect(() => assertPublicWebhookUrl("http://192.168.1.1/")).toThrow(/private/);
    expect(() => assertPublicWebhookUrl("http://172.16.0.1/")).toThrow(/private/);
    expect(() => assertPublicWebhookUrl("http://172.31.255.255/")).toThrow(/private/);
  });

  it("accepts non-private IPv4 on the 172.x edge (172.15, 172.32)", () => {
    expect(() => assertPublicWebhookUrl("http://172.15.0.1/")).not.toThrow();
    expect(() => assertPublicWebhookUrl("http://172.32.0.1/")).not.toThrow();
  });

  it("rejects loopback and 0.0.0.0", () => {
    expect(() => assertPublicWebhookUrl("http://127.0.0.1:6379/")).toThrow(/private/);
    expect(() => assertPublicWebhookUrl("http://127.5.5.5/")).toThrow(/private/);
    expect(() => assertPublicWebhookUrl("http://0.0.0.0/")).toThrow(/private/);
  });

  it("rejects multicast / reserved ranges", () => {
    expect(() => assertPublicWebhookUrl("http://224.0.0.1/")).toThrow(/private/);
    expect(() => assertPublicWebhookUrl("http://255.255.255.255/")).toThrow(/private/);
  });

  it("rejects IPv6 loopback and private ranges", () => {
    expect(() => assertPublicWebhookUrl("http://[::1]/")).toThrow(/private\/loopback IPv6/);
    expect(() => assertPublicWebhookUrl("http://[fe80::1]/")).toThrow(/private\/loopback IPv6/);
    expect(() => assertPublicWebhookUrl("http://[fc00::1]/")).toThrow(/private\/loopback IPv6/);
    expect(() => assertPublicWebhookUrl("http://[fd12:3456:789a::1]/")).toThrow(
      /private\/loopback IPv6/
    );
  });
});
