import { describe, expect, it, beforeEach } from "vitest";
import type { KeystoreEntry, OpenKeystore } from "../types/crypto";
import { daysUntilExpiry, entryHealth, entryMix, expiryStatus, findingsFor, formatDuration, plural, setThresholds, summarize } from "./metrics";
import {
  aliasTaken,
  byTypeThenAlias,
  canonicalAlias,
  cnOf,
  entryIdRemap,
  entryKey,
  entryMatches,
  entryTypeName,
  findIssuingCa,
  isCaEntry,
  isKeyLocked,
  keyPasswordMatches,
  lockState,
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
import { isThemePreference, resolveTheme } from "./theme";
import { HELP_GROUPS, searchHelp } from "./help";
import { detectOs, joinPath, listFolderCommand, nullInput, shellQuote as quoteFor, shortcutLabel } from "./platform";
import { baseName, dirName, safeFileStem, withExtension } from "./files";
import { connectTarget, formatTestNetConnection, parseTestNetConnection, parseTlsTarget } from "./net";
import {
  aliasForCertificate,
  certificateId,
  certificateName,
  isCertificateBundle,
  isCertificateId,
  isCertificateProbe,
  mergeCertificates,
  persistCertificates,
  shortFingerprint,
  toOpenCertificates,
} from "./certificates";

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
  it("maps entry ids that an undo or redo changed, by fingerprint", () => {
    const fp = (alias: string, sha: string) => ({ ...entry(alias), id: `/tmp/a.p12::${alias}`, sha256_fingerprint: sha });
    const before = [{ ...ks([fp("renamed", "AA"), fp("same", "BB")]), id: "k1" }];
    const after = [{ ...ks([fp("original", "AA"), fp("same", "BB")]), id: "k1" }];
    expect(entryIdRemap(before, after)).toEqual({ "/tmp/a.p12::renamed": "/tmp/a.p12::original" });
    // An entry that only disappears (an undone add) or only appears (an undone delete) maps to nothing.
    expect(entryIdRemap(before, [{ ...ks([fp("same", "BB")]), id: "k1" }])).toEqual({});
    // Two candidates with one fingerprint are ambiguous, and an empty fingerprint never matches.
    expect(entryIdRemap([{ ...ks([fp("x", "AA")]), id: "k1" }], [{ ...ks([fp("y", "AA"), fp("z", "AA")]), id: "k1" }])).toEqual({});
    expect(entryIdRemap([{ ...ks([fp("x", "")]), id: "k1" }], [{ ...ks([fp("y", "")]), id: "k1" }])).toEqual({});
  });

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

  it("still finds an issuing CA whose key has its own password", () => {
    // Regression: a locked CA was dropped from the issuer search and reported as "not open".
    const ca = entry("root", { selfSigned: true });
    ca.certificate_chain[0].is_ca = true;
    ca.certificate_chain[0].subject_key_id = "AA:BB";
    ca.private_key_pem = null;
    ca.locked = true;
    const leaf = entry("web", { selfSigned: false });
    leaf.issuer = ca.subject;
    leaf.certificate_chain[0].issuer = ca.subject;
    leaf.certificate_chain[0].authority_key_id = "aa:bb";
    expect(isCaEntry(ca)).toBe(true);
    expect(findIssuingCa(leaf, [ks([ca, leaf])])?.alias).toBe("root");
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

  it("gives the Lock column one state per entry: no key, locked, own key password or unlocked", () => {
    expect(lockState(cert, false)).toBe("no-key");
    // A certificate never shows a lock, even if something marks it locked.
    expect(lockState({ ...cert, locked: true }, true)).toBe("no-key");
    expect(lockState(kp, isKeyLocked(kp, new Set(), true))).toBe("locked");
    expect(lockState(kp, isKeyLocked(kp, new Set([kp.id]), true))).toBe("unlocked");
    expect(lockState({ ...kp, locked: true }, true)).toBe("own-password");
    const sk = { ...kp, entry_type: "SecretKey" as const };
    expect(lockState(sk, false)).toBe("unlocked");
    expect(lockState({ ...sk, locked: true }, true)).toBe("own-password");
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

describe("review fixes", () => {
  beforeEach(() => setThresholds(30, 90));

  it("rounds durations to whole months before splitting off years", () => {
    // 729 days used to read "1y": the leftover 364 days rounded to 12 months and were dropped.
    expect(formatDuration(729)).toBe("2y");
    expect(formatDuration(365)).toBe("1y");
    expect(formatDuration(400)).toBe("1y 1m");
    expect(formatDuration(3650)).toBe("10y");
    expect(formatDuration(-729)).toBe("2y");
  });

  it("parses a TLS target the way the engine does", () => {
    expect(parseTlsTarget("https://example.com:8443/x?y", 443)).toEqual({ host: "example.com", port: 8443 });
    expect(parseTlsTarget("example.com", 443)).toEqual({ host: "example.com", port: 443 });
    expect(parseTlsTarget("[::1]:9443", 443)).toEqual({ host: "::1", port: 9443 });
    expect(parseTlsTarget("::1", 443)).toEqual({ host: "::1", port: 443 });
    expect(parseTlsTarget("user@host.test:636", 443)).toEqual({ host: "host.test", port: 636 });
    expect(parseTlsTarget("LDAPS://dir.test", 636)).toEqual({ host: "dir.test", port: 636 });
    expect(parseTlsTarget("host:notaport", 443)).toBeNull();
    expect(parseTlsTarget("host:70000", 443)).toBeNull();
    expect(parseTlsTarget("  ", 443)).toBeNull();
    expect(connectTarget({ host: "::1", port: 9443 })).toBe("[::1]:9443");
    expect(connectTarget({ host: "example.com", port: 443 })).toBe("example.com:443");
  });

  it("suggests an openssl command that matches the input encoding", () => {
    expect(cliHint("certificate", "pem")).toBe("openssl x509 -in certificate.der -inform DER -out certificate.pem");
    expect(cliHint("certificate", "pem", "/c/leaf.cer")).toContain("-inform DER");
    expect(cliHint("certificate", "pem", "/c/chain.pem")).toBe("openssl x509 -in /c/chain.pem -out certificate.pem");
  });

  it("neutralises CSV fields that start with a tab or carriage return", () => {
    expect(csvField("\t=1+1")).toBe(`"'\t=1+1"`);
    expect(csvField("\r=1+1")).toBe(`"'\r=1+1"`);
    expect(csvField("CN=a")).toBe(`"CN=a"`);
  });

  it("flags a duplicate subject key id only when the keys differ", () => {
    const withKey = (alias: string, ski: string, spki: string) => {
      const e = entry(alias);
      e.certificate_chain[0] = { ...e.certificate_chain[0], subject_key_id: ski, spki_sha256: spki };
      return e;
    };
    const a = withKey("a", "AB:CD", "key-1");
    // The same CA in a keystore and in a truststore: same key id, same key. Normal.
    const copy = withKey("copy", "AB:CD", "key-1");
    expect(findingsFor(a, { siblings: [a, copy] }).map((f) => f.title)).not.toContain("Duplicate subject key id");
    // A different key claiming the same key id: chain building cannot tell them apart.
    const clash = withKey("clash", "AB:CD", "key-2");
    expect(findingsFor(a, { siblings: [a, clash] }).map((f) => f.title)).toContain("Duplicate subject key id");
  });

  it("reports a JKS store without marking every entry as needing action", () => {
    const f = findingsFor(entry("a"), { format: "JKS" }).find((x) => x.title === "JKS store");
    expect(f?.severity).toBe("low");
  });

  it("describes an inventory with correct plurals and without empty types", () => {
    expect(plural(1, "secret key")).toBe("1 secret key");
    expect(plural(2, "secret key")).toBe("2 secret keys");
    expect(entryMix({ keyPairs: 6, trusted: 0, secrets: 1 })).toBe("6 key pairs · 1 secret key");
    expect(entryMix({ keyPairs: 1, trusted: 3, secrets: 0 })).toBe("1 key pair · 3 certificates");
    expect(entryMix({ keyPairs: 0, trusted: 0, secrets: 0 })).toBe("No entries");
  });
});

describe("certificates page", () => {
  const FP = "3F:A2:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:9C:01";
  const cert = (alias: string, fp: string) => {
    const e = entry(alias, { entry_type: "TrustedCertificate", sha256_fingerprint: fp, subject: `CN=${alias} Root CA,O=Example` });
    e.certificate_chain[0].pem = `-----BEGIN CERTIFICATE-----\n${alias}\n-----END CERTIFICATE-----\n`;
    return e;
  };
  const origin = { path: "/certs/chain.pem", source: "chain.pem", openedAt: "2026-11-08T00:00:00Z" };

  it("keys a certificate by its SHA-256 fingerprint, apart from keystore entries", () => {
    expect(certificateId(FP)).toBe("cert::3fa200112233445566778899aabbccddeeff00112233445566778899aabb9c01");
    expect(certificateId(FP.toLowerCase())).toBe(certificateId(FP));
    expect(isCertificateId(certificateId(FP))).toBe(true);
    // A keystore entry key is `path::alias`; neither a path nor an in-memory id starts with "cert::".
    expect(isCertificateId(entryKey({ id: "ks-1", path: "/tmp/cert.p12" }, "cert"))).toBe(false);
    expect(isCertificateId(entryKey({ id: "ks-1", path: "" }, "x"))).toBe(false);
    expect(shortFingerprint(certificateId(FP))).toBe("3F:A2:…:9C:01");
  });

  it("names a certificate after its CN and makes a keystore alias from it", () => {
    expect(certificateName("CN=Example Root CA,O=Example")).toBe("Example Root CA");
    expect(certificateName("O=No Common Name")).toBe("O=No Common Name");
    expect(aliasForCertificate("CN=Example Root CA,O=Example")).toBe("example-root-ca");
    expect(aliasForCertificate("CN=***")).toBe("certificate");
  });

  it("turns engine entries into listed certificates keyed and named for the page", () => {
    const [c] = toOpenCertificates([cert("one", FP)], origin);
    expect(c.id).toBe(certificateId(FP));
    expect(c.entry.id).toBe(c.id);
    expect(c.entry.alias).toBe("one Root CA");
    expect(c).toMatchObject({ path: "/certs/chain.pem", source: "chain.pem", opened_at: origin.openedAt });
  });

  it("lists each certificate once, newest file first, keeping the order inside a file", () => {
    const [a, b] = toOpenCertificates([cert("a", "AA"), cert("b", "BB")], origin);
    const [b2, c] = toOpenCertificates([cert("b", "BB"), cert("c", "CC")], { ...origin, source: "other.pem" });
    const first = mergeCertificates([], [a, b, a]);
    expect(first.list.map((x) => x.entry.alias)).toEqual(["a Root CA", "b Root CA"]);
    expect(first.duplicates).toHaveLength(1);
    const second = mergeCertificates(first.list, [b2, c]);
    expect(second.list.map((x) => x.id)).toEqual([c.id, a.id, b.id]);
    expect(second.added.map((x) => x.id)).toEqual([c.id]);
    // The duplicate reported is the one already listed (its original source), not the new copy.
    expect(second.duplicates[0].source).toBe("chain.pem");
  });

  it("routes certificate files and PKCS#7 bundles to the page, and keeps signatures in Examine", () => {
    expect(isCertificateProbe("certificate")).toBe(true);
    expect(isCertificateProbe("certificate_chain")).toBe(true);
    for (const k of ["csr", "crl", "private_key", "public_key", "pkcs7", "keystore", "jar", "unknown"] as const) expect(isCertificateProbe(k)).toBe(false);
    const certs = [cert("a", "AA").certificate_chain[0]];
    expect(isCertificateBundle({ kind: "pkcs7", format: "PKCS#7 certificate bundle", certificates: certs })).toBe(true);
    // CMS signed data carries its signer's certificate, but it is a signature, not a bundle.
    expect(isCertificateBundle({ kind: "pkcs7", format: "DER (binary)", certificates: certs })).toBe(false);
    expect(isCertificateBundle({ kind: "pkcs7", format: "PKCS#7 certificate bundle", certificates: [] })).toBe(false);
    expect(isCertificateBundle({ kind: "certificate_chain", format: "PEM", certificates: certs })).toBe(true);
  });

  it("persists only public certificate data", () => {
    const list = toOpenCertificates([cert("a", "AA")], origin);
    const saved = persistCertificates(list);
    expect(saved).toEqual([{ path: "/certs/chain.pem", source: "chain.pem", opened_at: origin.openedAt, pem: list[0].entry.certificate_chain[0].pem }]);
    expect(Object.keys(saved[0]).sort()).toEqual(["opened_at", "path", "pem", "source"]);
  });
});

describe("Test-NetConnection in the built-in terminal", () => {
  it("reads the command as PowerShell does, including -DetailedInformation, aliases and prefixes", () => {
    expect(parseTestNetConnection("Test-NetConnection -ComputerName example.com -Port 443 -DetailedInformation")).toEqual({ target: "example.com", port: 443, level: "detailed" });
    expect(parseTestNetConnection("test-netconnection example.com -port 8443")).toEqual({ target: "example.com", port: 8443, level: "standard" });
    expect(parseTestNetConnection("tnc -cn db.internal -RemotePort:5432 -InformationLevel Quiet")).toEqual({ target: "db.internal", port: 5432, level: "quiet" });
    expect(parseTestNetConnection("TNC server -CommonTCPPort RDP -InformationLevel detailed")).toEqual({ target: "server", port: 3389, level: "detailed" });
    expect(parseTestNetConnection('Test-NetConnection -Comp "example.com" -P 443 -Detailed')).toEqual({ target: "example.com", port: 443, level: "detailed" });
  });

  it("takes the port from a URL or host:port, which wins over -Port", () => {
    expect(parseTestNetConnection("tnc https://example.com:8443/health -Port 443")).toEqual({ target: "example.com", port: 8443, level: "standard" });
    expect(parseTestNetConnection("tnc [::1]:22")).toEqual({ target: "::1", port: 22, level: "standard" });
  });

  it("leaves every other command to the shell", () => {
    expect(parseTestNetConnection("openssl s_client -connect example.com:443")).toBeNull();
    expect(parseTestNetConnection("Test-Connection example.com")).toBeNull();
    expect(parseTestNetConnection("")).toBeNull();
  });

  it("explains what it cannot do instead of guessing", () => {
    const err = (c: string) => (parseTestNetConnection(c) as { error: string }).error;
    expect(err("tnc example.com")).toMatch(/Add -Port/);
    expect(err("tnc -Port 443")).toMatch(/Name the server/);
    expect(err("tnc example.com -Port 70000")).toMatch(/1 to 65535/);
    expect(err("tnc example.com -TraceRoute")).toMatch(/not built in/);
    expect(err("tnc example.com -C 443")).toMatch(/ambiguous/);
    expect(err("tnc example.com -Bogus 1")).toMatch(/no parameter -Bogus/);
    expect(err("tnc example.com -CommonTCPPort FTP")).toMatch(/HTTP, RDP, SMB or WINRM/);
  });

  const ok = {
    computer_name: "example.com",
    remote_port: 443,
    name_resolution: ["172.66.147.243", "104.20.23.154"],
    resolve_ms: 29,
    remote_address: "172.66.147.243",
    source_address: "10.0.0.122",
    interface_alias: "en0",
    tcp_test_succeeded: true,
    tcp_ms: 17,
    attempts: [{ address: "172.66.147.243", succeeded: true, elapsed_ms: 17 }],
    tested_at: "2026-11-09 03:22:21 UTC",
  };

  it("prints the object as a PowerShell list, with every resolved address in detailed mode", () => {
    expect(formatTestNetConnection(ok, "standard")).toEqual({
      warnings: [],
      output: ["ComputerName     : example.com", "RemoteAddress    : 172.66.147.243", "RemotePort       : 443", "InterfaceAlias   : en0", "SourceAddress    : 10.0.0.122", "TcpTestSucceeded : True"].join("\n"),
    });
    const detailed = formatTestNetConnection(ok, "detailed").output.split("\n");
    expect(detailed).toContain("NameResolutionResults : 172.66.147.243");
    expect(detailed).toContain("                      : 104.20.23.154");
    expect(detailed).toContain("TcpConnectTime        : 17 ms");
    expect(detailed[detailed.length - 1]).toBe("TcpTestSucceeded      : True");
    expect(formatTestNetConnection(ok, "quiet").output).toBe("True");
  });

  it("warns as PowerShell does when the connection or the name lookup fails", () => {
    const refused = { ...ok, tcp_test_succeeded: false, tcp_ms: null, source_address: null, interface_alias: null, failure: "refused" as const };
    const r = formatTestNetConnection(refused, "standard");
    expect(r.warnings).toEqual(["WARNING: TCP connect to (172.66.147.243 : 443) failed"]);
    expect(r.output).toMatch(/TcpTestSucceeded : False$/);
    const unresolved = { ...refused, name_resolution: [], remote_address: null, failure: "name-resolution" as const };
    expect(formatTestNetConnection(unresolved, "quiet")).toEqual({ warnings: ["WARNING: Name resolution of example.com failed"], output: "False" });
  });
});

describe("theme", () => {
  it("resolves the system preference and rejects unknown values", () => {
    expect(resolveTheme("system", "dark")).toBe("dark");
    expect(resolveTheme("system", "light")).toBe("light");
    expect(resolveTheme("light", "dark")).toBe("light");
    expect(resolveTheme("dark", "light")).toBe("dark");
    expect(isThemePreference("dark")).toBe(true);
    expect(isThemePreference("black")).toBe(false);
    expect(isThemePreference(undefined)).toBe(false);
  });
});

describe("help", () => {
  it("finds topics by every word of the query, in questions and answers", () => {
    expect(searchHelp("")).toBe(HELP_GROUPS);
    const vault = searchHelp("master key").flatMap((g) => g.topics.map((t) => t.id));
    expect(vault).toContain("forgot-master");
    expect(searchHelp("KEYTOOL storepass").flatMap((g) => g.topics.map((t) => t.id))).toEqual(["terminal-stopped"]);
    expect(searchHelp("zzzz-nothing")).toEqual([]);
  });

  it("has unique topic ids and no empty answers", () => {
    const ids = HELP_GROUPS.flatMap((g) => g.topics.map((t) => t.id));
    expect(new Set(ids).size).toBe(ids.length);
    for (const t of HELP_GROUPS.flatMap((g) => g.topics)) expect(t.answer.join("").trim()).not.toBe("");
  });
});

describe("platform", () => {
  it("detects the OS from each webview's user agent", () => {
    expect(detectOs("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0")).toBe("windows");
    expect(detectOs("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)")).toBe("macos");
    expect(detectOs("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko)")).toBe("linux");
  });

  it("quotes paths for cmd.exe on Windows and sh elsewhere", () => {
    expect(quoteFor("C:\\keys\\a.p12", "windows")).toBe("C:\\keys\\a.p12");
    expect(quoteFor("C:\\My Keys\\a.p12", "windows")).toBe('"C:\\My Keys\\a.p12"');
    expect(quoteFor("/home/u/my keys/a.p12", "linux")).toBe("'/home/u/my keys/a.p12'");
    expect(quoteFor("/Users/u/a.p12", "macos")).toBe("/Users/u/a.p12");
  });

  it("uses each shell's null device and folder listing", () => {
    expect(nullInput("windows")).toBe("<NUL");
    expect(nullInput("linux")).toBe("</dev/null");
    expect(listFolderCommand("C:\\Users\\me\\AppData\\Roaming\\keystore-studio", "windows")).toBe("dir C:\\Users\\me\\AppData\\Roaming\\keystore-studio");
    expect(listFolderCommand("/home/me/.local/share/keystore-studio", "linux")).toBe("ls -la /home/me/.local/share/keystore-studio");
  });

  it("joins with the folder's own separator", () => {
    expect(joinPath("C:\\Users\\me\\keystore-studio", "state.json")).toBe("C:\\Users\\me\\keystore-studio\\state.json");
    expect(joinPath("/home/me/keystore-studio/", "state.json")).toBe("/home/me/keystore-studio/state.json");
  });

  it("writes shortcuts the macOS way only on macOS", () => {
    expect(shortcutLabel("Save (Ctrl+S)", "macos")).toBe("Save (⌘S)");
    expect(shortcutLabel("Ctrl+Shift+Z", "macos")).toBe("⌘⇧Z");
    expect(shortcutLabel("Ctrl+`", "macos")).toBe("⌃`");
    expect(shortcutLabel("Ctrl K", "macos")).toBe("⌘K");
    expect(shortcutLabel("Ctrl+Shift+Z", "windows")).toBe("Ctrl+Shift+Z");
  });
});
