import { shellQuote } from "./platform";
/*
 * The catalog behind the Convert page and its sidebar entries: what each converter reads and
 * writes, the output formats it offers, and the equivalent command line for the terminal hint.
 * The conversions themselves run in the engine (src-tauri/src/convert.rs).
 */

export type ConverterId = "certificate" | "truststore" | "private_key" | "public_key" | "keystore" | "pkcs12" | "extract" | "encoding";

export interface ConverterInfo {
  id: ConverterId;
  title: string;
  /** Name in the sidebar, short enough to fit. */
  nav: string;
  /** One line describing the formats, for tooltips and the command palette. */
  short: string;
  description: string;
  from: string;
  to: string;
}

export const CONVERTERS: ConverterInfo[] = [
  {
    id: "certificate",
    title: "Certificate format",
    nav: "Certificate format",
    short: "PEM · DER · PKCS#7",
    description: "Re-encode a certificate or a chain. Bundles are ordered leaf first.",
    from: "PEM, DER, PKCS#7, PkiPath, Netscape sequence",
    to: "PEM, DER, PKCS#7, PkiPath",
  },
  {
    id: "truststore",
    title: "Certificates → truststore",
    nav: "Build truststore",
    short: "CA bundle → keystore",
    description: "Put every certificate of a bundle into a keystore as trusted certificates, the way keytool -importcert does one at a time.",
    from: "PEM, DER, PKCS#7, PkiPath",
    to: "PKCS#12, JKS, JCEKS, BKS, UBER, BCFKS",
  },
  {
    id: "private_key",
    title: "Private key format",
    nav: "Private key format",
    short: "PKCS#8 · PKCS#1 · OpenSSH · JWK",
    description: "Change how a private key is encoded, or add and remove its password.",
    from: "PKCS#8 (incl. scrypt, PBES1), PKCS#1, SEC1, DSA, OpenSSL encrypted PEM, OpenSSH, JWK",
    to: "PKCS#8, encrypted PKCS#8 (AES or legacy 3DES), PKCS#1 / SEC1, OpenSSH, JWK",
  },
  {
    id: "public_key",
    title: "Public key",
    nav: "Public key",
    short: "PEM · OpenSSH · SSH2 · JWK",
    description: "Extract the public key from a certificate, CSR or private key, or re-encode one.",
    from: "Certificate, CSR, private key, PEM, DER, OpenSSH, SSH2 (RFC 4716), JWK",
    to: "PEM, DER, PKCS#1, OpenSSH, SSH2, JWK",
  },
  {
    id: "keystore",
    title: "Keystore format",
    nav: "Keystore format",
    short: "PKCS#12 · JKS · BKS · BCFKS",
    description: "Write a keystore in another format or with a new password. The source file is left unchanged.",
    from: "PKCS#12, JKS, JCEKS, BKS, UBER, BCFKS",
    to: "PKCS#12, JKS, JCEKS, BKS, UBER, BCFKS",
  },
  {
    id: "pkcs12",
    title: "Key + certificate → PKCS#12",
    nav: "Build PKCS#12",
    short: "Build a .p12 / .pfx",
    description: "Bundle a certificate (or chain) and its private key into one password-protected file.",
    from: "Certificate + private key",
    to: "PKCS#12 (.p12 / .pfx)",
  },
  {
    id: "extract",
    title: "Keystore → PEM",
    nav: "Keystore → PEM",
    short: "Export keys and certificates",
    description: "Write the certificates and private keys of a keystore to one PEM file, like openssl pkcs12 -nodes.",
    from: "PKCS#12, JKS, JCEKS, BKS, UBER, BCFKS",
    to: "PEM bundle",
  },
  {
    id: "encoding",
    title: "PEM ↔ DER",
    nav: "PEM ↔ DER",
    short: "Any certificate, CSR, CRL or key",
    description: "Strip the PEM armour to get DER, or add it back. The label is detected from the content.",
    from: "PEM, DER, bare base64",
    to: "DER or PEM",
  },
];

export const converterInfo = (id: ConverterId) => CONVERTERS.find((c) => c.id === id)!;

export interface OutputTarget {
  value: string;
  label: string;
  hint: string;
  ext: string;
  /** Printable output that can be previewed. */
  text: boolean;
  /** Holds private key material. */
  sensitive?: boolean;
  /** Needs a password to encrypt the output. */
  needsPassword?: boolean;
  /** Takes a password to encrypt the output, but works without one. */
  optionalPassword?: boolean;
}

export const CERT_OUTPUTS: OutputTarget[] = [
  { value: "pem", label: "PEM", hint: "BEGIN CERTIFICATE blocks. Keeps every certificate.", ext: "pem", text: true },
  { value: "der", label: "DER (.cer / .crt)", hint: "Binary. Holds one certificate, the leaf.", ext: "cer", text: false },
  { value: "pkcs7_pem", label: "PKCS#7 bundle, PEM (.p7b)", hint: "A chain for Windows, IIS and Java.", ext: "p7b", text: true },
  { value: "pkcs7_der", label: "PKCS#7 bundle, DER (.p7b / .p7c)", hint: "Binary form of the same bundle.", ext: "p7b", text: false },
  { value: "pkipath", label: "PkiPath (.pkipath)", hint: "Java CertPath encoding, trust anchor first.", ext: "pkipath", text: false },
];

export const KEY_OUTPUTS: OutputTarget[] = [
  { value: "pkcs8_pem", label: "PKCS#8, PEM", hint: "BEGIN PRIVATE KEY. The modern default.", ext: "key", text: true, sensitive: true },
  { value: "pkcs8_encrypted_pem", label: "Encrypted PKCS#8, PEM", hint: "BEGIN ENCRYPTED PRIVATE KEY, AES-256.", ext: "key", text: true, sensitive: true, needsPassword: true },
  { value: "traditional_pem", label: "PKCS#1 / SEC1, PEM", hint: "BEGIN RSA / EC PRIVATE KEY, for older tools.", ext: "key", text: true, sensitive: true },
  { value: "openssh", label: "OpenSSH", hint: "BEGIN OPENSSH PRIVATE KEY, as ssh-keygen writes it. Encrypted when a password is set.", ext: "key", text: true, sensitive: true, optionalPassword: true },
  { value: "pkcs8_encrypted_3des_pem", label: "Encrypted PKCS#8, legacy 3DES", hint: "PBE-SHA1-3DES, for Java 8 and readers without PBES2.", ext: "key", text: true, sensitive: true, needsPassword: true },
  { value: "pkcs8_der", label: "PKCS#8, DER", hint: "Binary PKCS#8 (.der / .p8).", ext: "der", text: false, sensitive: true },
  { value: "pkcs8_encrypted_der", label: "Encrypted PKCS#8, DER", hint: "Binary, AES-256.", ext: "der", text: false, sensitive: true, needsPassword: true },
  { value: "traditional_der", label: "PKCS#1 / SEC1, DER", hint: "Binary traditional form.", ext: "der", text: false, sensitive: true },
  { value: "jwk", label: "JWK (private)", hint: "JSON Web Key with the private parameters.", ext: "jwk.json", text: true, sensitive: true },
];

export const PUBLIC_OUTPUTS: OutputTarget[] = [
  { value: "pem", label: "PEM", hint: "BEGIN PUBLIC KEY (SubjectPublicKeyInfo).", ext: "pub.pem", text: true },
  { value: "openssh", label: "OpenSSH", hint: "One line for authorized_keys.", ext: "pub", text: true },
  { value: "ssh2", label: "SSH2 (RFC 4716)", hint: "---- BEGIN SSH2 PUBLIC KEY ----, for PuTTY and commercial SSH.", ext: "pub", text: true },
  { value: "jwk", label: "JWK (public)", hint: "JSON Web Key with an RFC 7638 key id.", ext: "jwk.json", text: true },
  { value: "der", label: "DER", hint: "Binary SubjectPublicKeyInfo.", ext: "pub.der", text: false },
  { value: "pkcs1_pem", label: "PKCS#1, PEM (RSA only)", hint: "BEGIN RSA PUBLIC KEY.", ext: "pub.pem", text: true },
];

/** Labels offered when wrapping DER in PEM. Empty means "detect from the content". */
export const PEM_LABELS = ["CERTIFICATE", "CERTIFICATE REQUEST", "X509 CRL", "PKCS7", "PUBLIC KEY", "RSA PUBLIC KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

const stemOf = (path: string) =>
  (path.split(/[\\/]/).pop() || path)
    .replace(/\.(jwk\.json|pub\.pem|pub\.der)$/i, "")
    .replace(/\.[^.]+$/, "");

/** Suggested output file name: the input's stem (or `fallback`) plus `ext`. */
export function outputName(inputPath: string | null | undefined, fallback: string, ext: string, suffix = ""): string {
  const stem = (inputPath ? stemOf(inputPath) : "") || fallback;
  const clean = stem.trim().replace(/[^\w.-]+/g, "_").replace(/^_+|_+$/g, "") || "converted";
  return `${clean}${suffix}.${ext}`;
}

/** Quoting for the shell the built-in terminal runs (cmd.exe on Windows, sh elsewhere). */
export { shellQuote };

/**
 * The OpenSSL, keytool or ssh-keygen command that does the same conversion, for the terminal
 * hint. Null when no standard tool does it (JWK, PkiPath).
 */
const KEYSTORE_EXT: Record<string, string> = { PKCS12: "p12", JKS: "jks", JCEKS: "jceks", BKS: "bks", UBER: "uber", BCFKS: "bcfks" };
const BOUNCY_CASTLE = ["BKS", "UBER", "BCFKS"];
/** keytool reads and writes the Bouncy Castle formats only with its provider on the command line. */
const BC_PROVIDER = " -providerpath bcprov.jar -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider";
const keystoreTypeOf = (path: string): string | null => {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  const found = Object.entries(KEYSTORE_EXT).find(([, e]) => e === ext || (e === "p12" && ext === "pfx"));
  return found ? found[0] : null;
};

export function cliHint(converter: ConverterId, target: string, input?: string | null, output?: string | null): string | null {
  const q = shellQuote;
  switch (converter) {
    case "certificate": {
      const src = q(input || (target === "pem" ? "certificate.der" : "chain.pem"));
      const out = (ext: string) => q(output || `certificate.${ext}`);
      switch (target) {
        case "pem": {
          // To PEM the input is usually DER; a PEM input needs no -inform (PEM is the default).
          const der = !input || /\.(der|cer)$/i.test(input);
          return `openssl x509 -in ${src}${der ? " -inform DER" : ""} -out ${out("pem")}`;
        }
        case "der":
          return `openssl x509 -in ${src} -outform DER -out ${out("cer")}`;
        case "pkcs7_pem":
          return `openssl crl2pkcs7 -nocrl -certfile ${src} -out ${out("p7b")}`;
        case "pkcs7_der":
          return `openssl crl2pkcs7 -nocrl -certfile ${src} -outform DER -out ${out("p7b")}`;
        default:
          return null;
      }
    }
    case "private_key": {
      const src = q(input || "key.pem");
      const out = q(output || "converted.key");
      switch (target) {
        case "pkcs8_pem":
          return `openssl pkcs8 -topk8 -nocrypt -in ${src} -out ${out}`;
        case "pkcs8_der":
          return `openssl pkcs8 -topk8 -nocrypt -in ${src} -outform DER -out ${out}`;
        case "pkcs8_encrypted_pem":
          return `openssl pkcs8 -topk8 -v2 aes-256-cbc -in ${src} -out ${out}`;
        case "pkcs8_encrypted_der":
          return `openssl pkcs8 -topk8 -v2 aes-256-cbc -in ${src} -outform DER -out ${out}`;
        case "traditional_pem":
          return `openssl pkey -in ${src} -traditional -out ${out}`;
        case "traditional_der":
          return `openssl pkey -in ${src} -traditional -outform DER -out ${out}`;
        case "pkcs8_encrypted_3des_pem":
          return `openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES -in ${src} -out ${out}`;
        case "openssh":
          // ssh-keygen rewrites a key file in its own format when it changes the passphrase.
          return `cp ${src} ${out} && ssh-keygen -p -f ${out}`;
        default:
          return null;
      }
    }
    case "public_key": {
      const src = q(input || "key.pem");
      const out = q(output || "public.pem");
      switch (target) {
        case "pem":
          return `openssl pkey -in ${src} -pubout -out ${out}`;
        case "der":
          return `openssl pkey -in ${src} -pubout -outform DER -out ${out}`;
        case "pkcs1_pem":
          return `openssl rsa -in ${src} -RSAPublicKey_out -out ${out}`;
        case "openssh":
          return `ssh-keygen -y -f ${src} > ${out}`;
        case "ssh2":
          return `ssh-keygen -e -m RFC4716 -f ${src} > ${out}`;
        default:
          return null;
      }
    }
    case "keystore": {
      const [type, ext] = target.includes(":") ? target.split(":") : [target, KEYSTORE_EXT[target] ?? "p12"];
      const source = input || "source.jks";
      const sourceType = keystoreTypeOf(source);
      const bc = BOUNCY_CASTLE.includes(type) || BOUNCY_CASTLE.includes(sourceType ?? "");
      return `keytool -importkeystore -srckeystore ${q(source)}${sourceType ? ` -srcstoretype ${sourceType}` : ""} -destkeystore ${q(output || `converted.${ext}`)} -deststoretype ${type}${bc ? BC_PROVIDER : ""}`;
    }
    case "truststore": {
      const bc = BOUNCY_CASTLE.includes(target);
      return `keytool -importcert -noprompt -trustcacerts -alias ca -file ${q(input || "ca.pem")} -keystore ${q(output || `truststore.${KEYSTORE_EXT[target] ?? "p12"}`)} -storetype ${target}${bc ? BC_PROVIDER : ""}`;
    }
    case "pkcs12":
      return `openssl pkcs12 -export${target === "legacy" ? " -legacy" : ""} -inkey ${q(input || "key.pem")} -in certificate.pem -out ${q(output || "bundle.p12")}`;
    case "extract": {
      const [certs, keys] = target.split(":");
      const flags = [certs === "none" ? "-nocerts" : certs === "leaf" ? "-clcerts" : "", keys === "none" ? "-nokeys" : keys === "encrypted" ? "" : "-nodes"].filter(Boolean).join(" ");
      return `openssl pkcs12 -in ${q(input || "store.p12")} -out ${q(output || "store.pem")}${flags ? ` ${flags}` : ""}`;
    }
    case "encoding": {
      const src = q(input || "in.pem");
      if (target === "der") return `openssl asn1parse -in ${src} -out ${q(output || "out.der")} -noout`;
      const cmd: Record<string, string> = { CERTIFICATE: "x509", "CERTIFICATE REQUEST": "req", "X509 CRL": "crl", PKCS7: "pkcs7" };
      const tool = cmd[target] ?? (target.includes("PRIVATE KEY") ? "pkey" : target.includes("PUBLIC KEY") ? "pkey -pubin" : "x509");
      return `openssl ${tool} -inform DER -in ${q(input || "in.der")} -out ${q(output || "out.pem")}`;
    }
  }
}
