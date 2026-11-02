import { CertificateInfo, KeystoreEntry, KeystoreFile, KeystoreFormat } from "../types/crypto";

/** What the home page should do with a dropped file. */
export type ImportResult =
  | { kind: "keystore"; fileName: string; keystore: KeystoreFile; note?: string }
  | { kind: "examine"; fileName: string; text: string }
  | { kind: "unsupported"; fileName: string; reason: string };

const KEYSTORE_EXT: Record<string, KeystoreFormat> = {
  jks: "JKS",
  keystore: "JKS",
  jceks: "JCEKS",
  bks: "BKS",
  bcfks: "BCFKS",
  uber: "UBER",
  p12: "PKCS12",
  pfx: "PKCS12",
};
const TEXT_EXT = new Set(["pem", "crt", "cer", "der", "csr", "crl", "key", "pub", "txt", "jwt"]);

export const ACCEPTED_EXTENSIONS = [...Object.keys(KEYSTORE_EXT), ...TEXT_EXT].map((e) => `.${e}`).join(",");

const extOf = (name: string) => (name.includes(".") ? name.split(".").pop()!.toLowerCase() : "");

// ---- minimal DER reader -------------------------------------------------

interface Tlv {
  tag: number;
  start: number; // start of value
  end: number; // end of value
  next: number; // offset after this TLV
}

function readTlv(b: Uint8Array, off: number): Tlv {
  const tag = b[off];
  let len = b[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p++];
  }
  if (p + len > b.length) throw new Error("truncated DER");
  return { tag, start: p, end: p + len, next: p + len };
}

function children(b: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let p = t.start; p < t.end; ) {
    const c = readTlv(b, p);
    out.push(c);
    p = c.next;
  }
  return out;
}

const OID_NAMES: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
};

function oidToString(b: Uint8Array, t: Tlv): string {
  const parts: number[] = [];
  let v = 0;
  for (let i = t.start; i < t.end; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  const first = parts.shift() ?? 0;
  return [Math.floor(first / 40), first % 40, ...parts].join(".");
}

function nameToString(b: Uint8Array, name: Tlv): string {
  const rdns: string[] = [];
  for (const set of children(b, name)) {
    for (const atv of children(b, set)) {
      const [oid, val] = children(b, atv);
      const key = OID_NAMES[oidToString(b, oid)] ?? oidToString(b, oid);
      rdns.push(`${key}=${new TextDecoder().decode(b.slice(val.start, val.end))}`);
    }
  }
  return rdns.join(", ");
}

function parseTime(b: Uint8Array, t: Tlv): Date {
  const s = new TextDecoder().decode(b.slice(t.start, t.end));
  const full = t.tag === 0x17 ? (Number(s.slice(0, 2)) >= 50 ? "19" : "20") + s : s;
  return new Date(
    Date.UTC(+full.slice(0, 4), +full.slice(4, 6) - 1, +full.slice(6, 8), +full.slice(8, 10), +full.slice(10, 12), +full.slice(12, 14))
  );
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (x) => x.toString(16).padStart(2, "0").toUpperCase());

async function fingerprint(algo: "SHA-1" | "SHA-256", der: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest(algo, der as BufferSource));
  return hex(digest).join(":");
}

export function derToPem(der: Uint8Array): string {
  let bin = "";
  der.forEach((x) => (bin += String.fromCharCode(x)));
  const body = btoa(bin).replace(/(.{64})/g, "$1\n");
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

/** Parse the fields of an X.509 certificate that the UI shows. Throws if the bytes are not a certificate. */
export async function parseCertificate(der: Uint8Array): Promise<CertificateInfo> {
  const cert = readTlv(der, 0);
  if (cert.tag !== 0x30) throw new Error("not a certificate");
  const tbs = children(der, cert)[0];
  const f = children(der, tbs);
  const hasVersion = f[0].tag === 0xa0;
  const o = hasVersion ? 1 : 0;
  const serial = hex(der.slice(f[o].start, f[o].end)).join("");
  const sigAlgOid = oidToString(der, children(der, f[o + 1])[0]);
  const issuer = nameToString(der, f[o + 2]);
  const [nb, na] = children(der, f[o + 3]).map((t) => parseTime(der, t));
  const subject = nameToString(der, f[o + 4]);
  const spki = children(der, f[o + 5]);
  const keyOid = oidToString(der, children(der, spki[0])[0]);

  let algo = keyOid;
  let keySize = 0;
  if (keyOid === "1.2.840.113549.1.1.1") {
    algo = "RSA";
    const seq = readTlv(der, spki[1].start + 1); // skip the unused-bits byte
    const n = children(der, seq)[0];
    keySize = (n.end - n.start - (der[n.start] === 0 ? 1 : 0)) * 8;
  } else if (keyOid === "1.2.840.10045.2.1") {
    algo = "EC";
    keySize = 256;
  } else if (keyOid === "1.3.101.112") {
    algo = "Ed25519";
    keySize = 256;
  }

  const sigNames: Record<string, string> = {
    "1.2.840.113549.1.1.11": "SHA256withRSA",
    "1.2.840.113549.1.1.12": "SHA384withRSA",
    "1.2.840.113549.1.1.5": "SHA1withRSA",
    "1.2.840.10045.4.3.2": "SHA256withECDSA",
    "1.3.101.112": "Ed25519",
  };

  return {
    version: hasVersion ? der[f[0].start + 2] + 1 : 1,
    serial_number: serial,
    signature_algorithm: sigNames[sigAlgOid] ?? sigAlgOid,
    subject,
    issuer,
    valid_from: nb.toISOString().replace("T", " ").slice(0, 19) + " UTC",
    valid_to: na.toISOString().replace("T", " ").slice(0, 19) + " UTC",
    days_remaining: Math.floor((na.getTime() - Date.now()) / 86_400_000),
    is_ca: subject === issuer,
    public_key_algorithm: algo,
    key_size: keySize,
    sans: [],
    key_usage: [],
    extended_key_usage: [],
    extensions: [],
    sha256_fingerprint: await fingerprint("SHA-256", der),
    sha1_fingerprint: await fingerprint("SHA-1", der),
    md5_fingerprint: "",
    pem: derToPem(der),
  };
}

// ---- JKS / JCEKS --------------------------------------------------------

async function entryFromCerts(
  id: string,
  alias: string,
  type: KeystoreEntry["entry_type"],
  certs: CertificateInfo[],
  created: Date
): Promise<KeystoreEntry> {
  const leaf = certs[0];
  return {
    id,
    alias,
    entry_type: type,
    algorithm: leaf.public_key_algorithm,
    key_size: leaf.key_size,
    creation_date: created.toISOString().slice(0, 10),
    expiry_date: leaf.valid_to.slice(0, 10),
    last_modified: "Imported",
    subject: leaf.subject,
    issuer: leaf.issuer,
    serial_number: leaf.serial_number,
    sha256_fingerprint: leaf.sha256_fingerprint,
    sha1_fingerprint: leaf.sha1_fingerprint,
    chain_length: certs.length,
    certificate_chain: certs,
    locked: type === "KeyPair",
    labels: ["Imported"],
    is_expired: leaf.days_remaining < 0,
    is_weak: leaf.public_key_algorithm === "RSA" && leaf.key_size > 0 && leaf.key_size < 2048,
    is_post_quantum: false,
  };
}

function makeKeystore(name: string, format: KeystoreFormat, entries: KeystoreEntry[], encrypted: boolean): KeystoreFile {
  return {
    id: `ks-import-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    name,
    format,
    path: name,
    description: encrypted ? "Imported by drag and drop (contents encrypted)" : "Imported by drag and drop",
    password_protected: true,
    created_at: new Date().toISOString().slice(0, 10),
    updated_at: "Just now",
    entries,
  };
}

async function parseJavaKeystore(
  bytes: Uint8Array,
  name: string,
  format: KeystoreFormat
): Promise<{ ks: KeystoreFile; note?: string }> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = view.getUint32(4);
  const count = view.getUint32(8);
  let p = 12;
  const utf = () => {
    const len = view.getUint16(p);
    const s = new TextDecoder().decode(bytes.slice(p + 2, p + 2 + len));
    p += 2 + len;
    return s;
  };
  const entries: KeystoreEntry[] = [];
  let note: string | undefined;

  try {
    for (let i = 0; i < count; i++) {
      const tag = view.getUint32(p);
      p += 4;
      const alias = utf();
      const created = new Date(Number(view.getBigUint64(p)));
      p += 8;
      const id = `entry-import-${Date.now()}-${i}`;
      if (tag === 1) {
        const keyLen = view.getUint32(p);
        p += 4 + keyLen; // encrypted private key: not readable without the password
        const n = view.getUint32(p);
        p += 4;
        const certs: CertificateInfo[] = [];
        for (let c = 0; c < n; c++) {
          if (version === 2) utf();
          const len = view.getUint32(p);
          p += 4;
          certs.push(await parseCertificate(bytes.slice(p, p + len)));
          p += len;
        }
        if (certs.length) entries.push(await entryFromCerts(id, alias, "KeyPair", certs, created));
      } else if (tag === 2) {
        if (version === 2) utf();
        const len = view.getUint32(p);
        p += 4;
        const cert = await parseCertificate(bytes.slice(p, p + len));
        p += len;
        entries.push(await entryFromCerts(id, alias, "TrustedCertificate", [cert], created));
      } else {
        note = `Stopped at entry ${i + 1}: secret-key entries are encrypted and cannot be listed without the password.`;
        break;
      }
    }
  } catch {
    note = "The file ended unexpectedly; showing the entries that could be read.";
  }

  return { ks: makeKeystore(name, format, entries, false), note };
}

// ---- entry point --------------------------------------------------------

export async function importFile(file: File): Promise<ImportResult> {
  const name = file.name;
  const ext = extOf(name);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const magic = bytes.length >= 4 ? new DataView(bytes.buffer, bytes.byteOffset).getUint32(0) : 0;

  if (magic === 0xfeedfeed || magic === 0xcececece) {
    const format: KeystoreFormat = magic === 0xcececece ? "JCEKS" : KEYSTORE_EXT[ext] ?? "JKS";
    const { ks, note } = await parseJavaKeystore(bytes, name, format);
    return { kind: "keystore", fileName: name, keystore: ks, note };
  }

  if (KEYSTORE_EXT[ext]) {
    const format = KEYSTORE_EXT[ext];
    return {
      kind: "keystore",
      fileName: name,
      keystore: makeKeystore(name, format, [], true),
      note: `${format} contents are encrypted. The store was added; entries are not listed until it is unlocked.`,
    };
  }

  if (TEXT_EXT.has(ext) || ext === "") {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    if (text.includes("-----BEGIN") || /^[\w-]+\.[\w-]+\.[\w-]*$/.test(text.trim())) {
      return { kind: "examine", fileName: name, text };
    }
    if (bytes[0] === 0x30) {
      try {
        await parseCertificate(bytes);
        return { kind: "examine", fileName: name, text: derToPem(bytes) };
      } catch {
        /* not a DER certificate */
      }
    }
  }

  return { kind: "unsupported", fileName: name, reason: "Not a recognised keystore, certificate, key, CSR or CRL." };
}
