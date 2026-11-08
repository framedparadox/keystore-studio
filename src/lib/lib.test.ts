import { describe, expect, it, beforeEach } from "vitest";
import type { KeystoreEntry, OpenKeystore } from "../types/crypto";
import { daysUntilExpiry, entryHealth, expiryStatus, findingsFor, formatDuration, setThresholds, summarize } from "./metrics";
import {
  aliasTaken,
  byTypeThenAlias,
  canonicalAlias,
  cnOf,
  entryKey,
  entryMatches,
  entryTypeName,
  findIssuingCa,
  isKeyLocked,
  keyPasswordMatches,
  normalizeEntries,
  pkcs12BuildReady,
  profileUsages,
  renewalTerm,
  saveProblems,
  splitList,
  uniqueAlias,
} from "./keystore";
import { CERT_OUTPUTS, CONVERTERS, KEY_OUTPUTS, PUBLIC_OUTPUTS, cliHint, outputName, shellQuote } from "./convert";
import { csvField } from "./csv";
import { diffEntries } from "./diff";
import { classifyError } from "./api";
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

  it("builds certificate profiles without RSA-only key usage on elliptic curves", () => {
    expect(profileUsages("server", "ECDSA")).toEqual({ isCa: false, ku: ["digitalSignature"], eku: ["serverAuth"] });
    expect(profileUsages("server", "Ed25519").ku).not.toContain("keyEncipherment");
    expect(profileUsages("server", "RSA")).toEqual({ isCa: false, ku: ["digitalSignature", "keyEncipherment"], eku: ["serverAuth"] });
    expect(profileUsages("client", "ECDSA").eku).toEqual(["clientAuth"]);
    expect(profileUsages("codesign", "ECDSA").eku).toEqual(["codeSigning"]);
    expect(profileUsages("ca", "RSA").isCa).toBe(true);
    expect(profileUsages("ca", "RSA").eku).toEqual([]);
  });

  it("lowercases Java keystore aliases and keeps PKCS#12 case", () => {
    expect(canonicalAlias("JKS", " API ")).toBe("api");
    expect(canonicalAlias("JCEKS", "API")).toBe("api");
    expect(canonicalAlias("PKCS12", "API")).toBe("API");
  });

  it("selects the issuing CA by key id", () => {
    const ca = entry("root", { selfSigned: true });
    ca.certificate_chain[0].is_ca = true;
    ca.certificate_chain[0].subject_key_id = "AA:BB";
    ca.private_key_pem = "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n";
    const other = entry("other", { selfSigned: true });
    other.certificate_chain[0].is_ca = true;
    other.certificate_chain[0].subject = ca.subject;
    other.certificate_chain[0].subject_key_id = "CC:DD";
    other.private_key_pem = ca.private_key_pem;
    const leaf = entry("web", { selfSigned: false });
    leaf.issuer = ca.subject;
    leaf.certificate_chain[0].issuer = ca.subject;
    leaf.certificate_chain[0].authority_key_id = "aa:bb";
    expect(findIssuingCa(leaf, [ks([ca, other, leaf])])?.alias).toBe("root");
    leaf.certificate_chain[0].authority_key_id = "ccdd";
    expect(findIssuingCa(leaf, [ks([ca, other, leaf])])?.alias).toBe("other");
  });

  it("extracts CNs and splits lists", () => {
    expect(cnOf("CN=Acme\\, Inc., O=Acme, C=US")).toBe("Acme, Inc.");
    expect(cnOf("O=NoCn")).toBe("O=NoCn");
    expect(splitList("a.example, b.example\n10.0.0.1,,")).toEqual(["a.example", "b.example", "10.0.0.1"]);
  });
});

describe("milestone helpers", () => {
  it("escapes csv fields the way the inventory writer does", () => {
    expect(csvField("hello")).toBe('"hello"');
    expect(csvField('say "hi"')).toBe('"say ""hi"""');
    expect(csvField("=cmd")).toBe(`"'=cmd"`);
  });

  it("diffs keystores by alias and fingerprint", () => {
    const diff = diffEntries(
      [{ alias: "a", fingerprint: "1" }, { alias: "b", fingerprint: "2" }],
      [{ alias: "b", fingerprint: "9" }, { alias: "c", fingerprint: "3" }],
    );
    expect(diff).toEqual({ added: ["c"], removed: ["a"], changed: ["b"] });
  });

  it("caps a server renewal at 398 days and explains the cap", () => {
    const server = entry("web", { daysLeft: 800 });
    server.certificate_chain[0].not_before = now() - 10 * DAY;
    server.certificate_chain[0].not_after = now() + 800 * DAY;
    server.certificate_chain[0].extended_key_usage = ["TLS Web Server Authentication"];
    const term = renewalTerm(server);
    expect(term.cap).toBe(398);
    expect(term.days).toBe(398);
    expect(term.note).toContain("398");
  });

  it("blocks saving secret keys into JKS and refuses to write BKS", () => {
    const entries = [{ entry_type: "SecretKey", locked: false }, { entry_type: "KeyPair", locked: true }];
    expect(saveProblems(entries, "PKCS12", "JKS").join(" ")).toContain("secret");
    expect(saveProblems(entries, "PKCS12", "PKCS12")).toEqual([]);
    expect(saveProblems([], "BKS", "BKS").join(" ")).toContain("read-only");
  });

  it("classifies engine errors and flags a JKS store", () => {
    expect(classifyError("wrong-password: nope").kind).toBe("wrong-password");
    expect(classifyError("changed-on-disk: file").kind).toBe("changed-on-disk");
    expect(classifyError("unrecognized: bad header").kind).toBe("unrecognized");
    expect(classifyError("unrecognised: bad header").kind).toBe("unrecognized");
    expect(classifyError("unsupported: BCFKS").kind).toBe("unsupported");
    expect(classifyError("invalid: truncated file").kind).toBe("invalid");
    expect(classifyError("apk: Android APKs use v2").kind).toBe("apk");
    expect(classifyError("something else").kind).toBe("other");
    const jks = findingsFor(entry("a"), { format: "JKS" });
    expect(jks.some((f) => f.title === "JKS store")).toBe(true);
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

describe("pkcs12BuildReady", () => {
  const ok = { hasCertificate: true, hasKey: true, passphrase: "pw", confirm: "pw" };

  it("accepts a certificate, a key and a confirmed passphrase", () => {
    expect(pkcs12BuildReady(ok)).toBe(true);
  });

  it("requires both the certificate and the key", () => {
    expect(pkcs12BuildReady({ ...ok, hasCertificate: false })).toBe(false);
    expect(pkcs12BuildReady({ ...ok, hasKey: false })).toBe(false);
  });

  it("requires a non-empty passphrase that matches its confirmation", () => {
    expect(pkcs12BuildReady({ ...ok, passphrase: "", confirm: "" })).toBe(false);
    expect(pkcs12BuildReady({ ...ok, confirm: "different" })).toBe(false);
  });
});

describe("key pair locking", () => {
  const kp = entry("web");
  const cert = entry("anchor", { entry_type: "TrustedCertificate" });
  const secret = entry("aes", { daysLeft: null });

  it("locks key pairs until they are unlocked, when unlocking is required", () => {
    expect(isKeyLocked(kp, new Set(), true)).toBe(true);
    expect(isKeyLocked(kp, new Set([kp.id]), true)).toBe(false);
    expect(isKeyLocked(kp, new Set(), false)).toBe(false);
  });

  it("never locks certificates, and locks secret keys only when the engine could not decrypt them", () => {
    expect(isKeyLocked(cert, new Set(), true)).toBe(false);
    expect(isKeyLocked(secret, new Set(), true)).toBe(false);
    expect(isKeyLocked({ ...secret, locked: true }, new Set([secret.id]), false)).toBe(true);
  });

  it("keeps a key with its own password locked whatever the session says", () => {
    expect(isKeyLocked({ ...kp, locked: true }, new Set([kp.id]), false)).toBe(true);
  });

  it("checks the key password against the key's own password, else the store password", () => {
    expect(keyPasswordMatches(kp, "store-pw", "store-pw")).toBe(true);
    expect(keyPasswordMatches(kp, "other", "store-pw")).toBe(false);
    expect(keyPasswordMatches({ ...kp, key_password: "own-pw" }, "store-pw", "store-pw")).toBe(false);
    expect(keyPasswordMatches({ ...kp, key_password: "own-pw" }, "own-pw", "store-pw")).toBe(true);
    expect(keyPasswordMatches(kp, "", "")).toBe(false);
    expect(keyPasswordMatches(kp, "x", undefined)).toBe(false);
  });
});

describe("entry listing", () => {
  it("orders key pairs, then secret keys, then certificates, each by alias", () => {
    const list = [entry("zeta", { entry_type: "TrustedCertificate" }), entry("b"), entry("aes", { daysLeft: null }), entry("a10"), entry("a2")];
    expect([...list].sort(byTypeThenAlias).map((e) => e.alias)).toEqual(["a2", "a10", "b", "aes", "zeta"]);
  });

  it("matches alias, subject and fingerprints with or without colons", () => {
    const e = entry("api", { sha256_fingerprint: "AB:CD:EF" });
    expect(entryMatches(e, "")).toBe(true);
    expect(entryMatches(e, "API")).toBe(true);
    expect(entryMatches(e, "api.example")).toBe(true);
    expect(entryMatches(e, "abcd")).toBe(true);
    expect(entryMatches(e, "cd:ef")).toBe(true);
    expect(entryMatches(e, "nope")).toBe(false);
  });

  it("names CA certificates apart from other trusted certificates", () => {
    const anchor = entry("root", { entry_type: "TrustedCertificate" });
    expect(entryTypeName(anchor)).toBe("Trusted certificate");
    anchor.certificate_chain[0].is_ca = true;
    expect(entryTypeName(anchor)).toBe("CA certificate");
    expect(entryTypeName(entry("k"))).toBe("Key pair");
  });
});

describe("conversion catalog", () => {
  it("lists each converter once", () => {
    const ids = CONVERTERS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(expect.arrayContaining(["certificate", "private_key", "public_key", "keystore", "pkcs12", "extract", "encoding"]));
  });

  it("offers exactly the targets the engine accepts", () => {
    // Mirrors CERT_TARGETS, KEY_TARGETS and PUBLIC_TARGETS in src-tauri/src/convert.rs.
    expect(CERT_OUTPUTS.map((t) => t.value).sort()).toEqual(["der", "pem", "pkcs7_der", "pkcs7_pem", "pkipath"]);
    expect(KEY_OUTPUTS.map((t) => t.value).sort()).toEqual(["jwk", "pkcs8_der", "pkcs8_encrypted_der", "pkcs8_encrypted_pem", "pkcs8_pem", "traditional_der", "traditional_pem"]);
    expect(PUBLIC_OUTPUTS.map((t) => t.value).sort()).toEqual(["der", "jwk", "openssh", "pem", "pkcs1_pem"]);
    expect(KEY_OUTPUTS.every((t) => t.sensitive)).toBe(true);
    expect(KEY_OUTPUTS.filter((t) => t.needsPassword).map((t) => t.value)).toEqual(["pkcs8_encrypted_pem", "pkcs8_encrypted_der"]);
  });

  it("suggests an output name from the input file", () => {
    expect(outputName("/certs/server.pem", "certificate", "cer")).toBe("server.cer");
    expect(outputName("C:\\keys\\id.pub.pem", "key", "jwk.json")).toBe("id.jwk.json");
    expect(outputName(null, "My CA", "pem")).toBe("My_CA.pem");
    expect(outputName("/a/store.p12", "keystore", "p12", "-converted")).toBe("store-converted.p12");
    expect(outputName("", "", "pem")).toBe("converted.pem");
  });

  it("quotes paths for the shell only when needed", () => {
    expect(shellQuote("/tmp/a.pem")).toBe("/tmp/a.pem");
    expect(shellQuote("/tmp/my key.pem")).toBe("'/tmp/my key.pem'");
    expect(shellQuote("it's.pem")).toBe(`'it'\\''s.pem'`);
  });

  it("gives a command-line equivalent where a standard tool exists", () => {
    expect(cliHint("certificate", "pkcs7_pem", "/c/chain.pem")).toBe("openssl crl2pkcs7 -nocrl -certfile /c/chain.pem -out certificate.p7b");
    expect(cliHint("certificate", "pkipath")).toBeNull();
    expect(cliHint("private_key", "jwk")).toBeNull();
    expect(cliHint("keystore", "PKCS12", "/k/a.jks")).toContain("-deststoretype PKCS12");
    expect(cliHint("extract", "chain:none")).toContain("-nokeys");
    expect(cliHint("extract", "leaf:pkcs8")).toContain("-clcerts -nodes");
    expect(cliHint("encoding", "der")).toContain("openssl asn1parse");
    expect(cliHint("encoding", "CERTIFICATE REQUEST")).toContain("openssl req -inform DER");
  });
});
