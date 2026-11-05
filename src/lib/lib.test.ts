import { describe, expect, it, beforeEach } from "vitest";
import type { KeystoreEntry, OpenKeystore } from "../types/crypto";
import { daysUntilExpiry, entryHealth, expiryStatus, findingsFor, formatDuration, setThresholds, summarize } from "./metrics";
import { aliasTaken, cnOf, entryKey, normalizeEntries, splitList, uniqueAlias } from "./keystore";
import { baseName, dirName, safeFileStem, withExtension } from "./files";

const DAY = 86_400;
const now = () => Math.floor(Date.now() / 1000);

function entry(alias: string, opts: Partial<KeystoreEntry> & { daysLeft?: number | null; selfSigned?: boolean } = {}): KeystoreEntry {
  const { daysLeft = 365, selfSigned = true, ...rest } = opts;
  const chain =
    daysLeft === null
      ? []
      : [
          {
            version: 3,
            serial_number: "01",
            signature_algorithm: "SHA256withECDSA",
            subject: `CN=${alias}.example`,
            issuer: selfSigned ? `CN=${alias}.example` : "CN=Some CA",
            valid_from: "",
            valid_to: "",
            not_before: now() - 10 * DAY,
            not_after: now() + daysLeft * DAY,
            days_remaining: daysLeft,
            is_ca: false,
            self_signed: selfSigned,
            public_key_algorithm: "ECDSA",
            key_size: 256,
            sans: [],
            key_usage: [],
            extended_key_usage: ["TLS Web Server Authentication"],
            extensions: [],
            sha256_fingerprint: "",
            sha1_fingerprint: "",
            md5_fingerprint: "",
            pem: "",
          },
        ];
  return {
    id: alias,
    alias,
    entry_type: daysLeft === null ? "SecretKey" : "KeyPair",
    algorithm: daysLeft === null ? "AES" : "ECDSA",
    key_size: 256,
    creation_date: new Date((now() - 10 * DAY) * 1000).toISOString().slice(0, 10),
    expiry_date: daysLeft === null ? "" : new Date((now() + daysLeft * DAY) * 1000).toISOString().slice(0, 10),
    subject: `CN=${alias}.example`,
    issuer: "CN=x",
    serial_number: "01",
    sha256_fingerprint: "",
    sha1_fingerprint: "",
    chain_length: chain.length,
    certificate_chain: chain,
    locked: false,
    labels: [],
    is_expired: false,
    is_weak: false,
    weak_reasons: [],
    is_post_quantum: false,
    ...rest,
  };
}

const ks = (entries: KeystoreEntry[], path = "/tmp/a.p12"): OpenKeystore => ({
  id: "ks-1",
  name: "a.p12",
  format: "PKCS12",
  path,
  description: "",
  password_protected: true,
  created_at: "",
  updated_at: "",
  entries,
  dirty: false,
  sealed: false,
});

describe("expiry and health", () => {
  beforeEach(() => setThresholds(30, 90));

  it("classifies by days remaining", () => {
    expect(expiryStatus(entry("a", { daysLeft: -3 }))).toBe("expired");
    expect(expiryStatus(entry("a", { daysLeft: 10 }))).toBe("critical");
    expect(expiryStatus(entry("a", { daysLeft: 60 }))).toBe("warning");
    expect(expiryStatus(entry("a", { daysLeft: 400 }))).toBe("ok");
    expect(expiryStatus(entry("a", { daysLeft: null }))).toBe("never");
    expect(daysUntilExpiry(entry("a", { daysLeft: null }))).toBeNull();
  });

  it("respects configured thresholds", () => {
    setThresholds(7, 14);
    expect(expiryStatus(entry("a", { daysLeft: 10 }))).toBe("warning");
    expect(expiryStatus(entry("a", { daysLeft: 60 }))).toBe("ok");
  });

  it("weak keys are at risk regardless of expiry", () => {
    const weak = entry("w", { is_weak: true, weak_reasons: ["RSA key is only 1024 bits"] });
    expect(entryHealth(weak)).toBe("at-risk");
    expect(findingsFor(weak)[0]).toMatchObject({ severity: "high", title: "Weak cryptography" });
  });

  it("summarizes an inventory with a health score", () => {
    const s = summarize([entry("ok"), entry("soon", { daysLeft: 5 }), entry("gone", { daysLeft: -1 }), entry("k", { daysLeft: null })]);
    expect(s).toMatchObject({ total: 4, keyPairs: 3, secrets: 1, expired: 1, expiringCritical: 1 });
    expect(s.healthScore).toBe(Math.round(100 * (1 - (1 + 0.5) / 4)));
    expect(summarize([]).healthScore).toBe(100);
  });

  it("flags incomplete chains and self-signed servers", () => {
    expect(findingsFor(entry("s")).map((f) => f.title)).toContain("Self-signed server certificate");
    expect(findingsFor(entry("c", { selfSigned: false })).map((f) => f.title)).toContain("Incomplete chain");
  });

  it("formats durations compactly", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(12)).toBe("12 d");
    expect(formatDuration(-12)).toBe("12 d");
    expect(formatDuration(120)).toBe("4 mo");
    expect(formatDuration(365 * 2 + 60)).toBe("2y 2m");
  });
});

describe("keystore helpers", () => {
  it("keys entries by keystore path and alias", () => {
    expect(entryKey({ id: "ks-1", path: "/x/a.jks" }, "web")).toBe("/x/a.jks::web");
    expect(entryKey({ id: "ks-1", path: "" }, "web")).toBe("ks-1::web");
    const n = normalizeEntries(ks([entry("web")]));
    expect(n.entries[0].id).toBe("/tmp/a.p12::web");
  });

  it("makes aliases unique case-insensitively", () => {
    const k = ks([entry("web"), entry("Web-2")]);
    expect(aliasTaken(k, "WEB")).toBe(true);
    expect(aliasTaken(k, "web", "web")).toBe(false);
    expect(uniqueAlias(k, "web")).toBe("web-3");
    expect(uniqueAlias(k, "api")).toBe("api");
    expect(uniqueAlias(k, "  ")).toBe("entry");
  });

  it("extracts CNs and splits lists", () => {
    expect(cnOf("CN=Acme\\, Inc., O=Acme, C=US")).toBe("Acme, Inc.");
    expect(cnOf("O=NoCn")).toBe("O=NoCn");
    expect(splitList("a.example, b.example\n10.0.0.1,,")).toEqual(["a.example", "b.example", "10.0.0.1"]);
  });
});

describe("file helpers", () => {
  it("handles paths and extensions", () => {
    expect(baseName("/home/u/keys/app.p12")).toBe("app.p12");
    expect(baseName("C:\\keys\\app.jks")).toBe("app.jks");
    expect(dirName("/home/u/keys/app.p12")).toBe("/home/u/keys");
    expect(withExtension("app.p12", "jks")).toBe("app.jks");
    expect(withExtension("app", "p12")).toBe("app.p12");
    expect(safeFileStem("api server/prod")).toBe("api_server_prod");
  });
});
