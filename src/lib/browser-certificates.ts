import "reflect-metadata";
import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  PublicKey,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
  X509Certificates,
} from "@peculiar/x509";
import type { CertificateInfo, DataSource, KeystoreEntry, X509ExtensionInfo } from "../types/crypto";

const extensionNames: Record<string, string> = {
  "2.5.29.14": "Subject Key Identifier",
  "2.5.29.15": "Key Usage",
  "2.5.29.17": "Subject Alternative Name",
  "2.5.29.19": "Basic Constraints",
  "2.5.29.35": "Authority Key Identifier",
  "2.5.29.37": "Extended Key Usage",
};

const hex = (value: ArrayBuffer) =>
  [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
const fingerprint = (value: ArrayBuffer) => hex(value).match(/.{2}/g)?.join(":") ?? "";
const isoDate = (date: Date) => date.toISOString();

function decodeCertificates(data: DataSource): X509Certificate[] {
  const text = data.text?.trim();
  if (text) {
    const pemBlocks = [...text.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)];
    if (pemBlocks.length) return pemBlocks.map(([pem]) => new X509Certificate(pem));
  }

  const encoded = text || data.base64;
  if (!encoded) throw new Error("No certificate data was provided.");

  try {
    return [new X509Certificate(encoded)];
  } catch (certificateError) {
    try {
      const certificates = [...new X509Certificates(encoded)];
      if (certificates.length) return certificates;
    } catch {
      throw new Error(certificateError instanceof Error ? certificateError.message : "Could not parse this certificate.");
    }
    throw new Error("No X.509 certificates were found in this file.");
  }
}

const keyUsageNames: [KeyUsageFlags, string][] = [
  [KeyUsageFlags.digitalSignature, "Digital Signature"],
  [KeyUsageFlags.nonRepudiation, "Non Repudiation"],
  [KeyUsageFlags.keyEncipherment, "Key Encipherment"],
  [KeyUsageFlags.dataEncipherment, "Data Encipherment"],
  [KeyUsageFlags.keyAgreement, "Key Agreement"],
  [KeyUsageFlags.keyCertSign, "Certificate Sign"],
  [KeyUsageFlags.cRLSign, "CRL Sign"],
  [KeyUsageFlags.encipherOnly, "Encipher Only"],
  [KeyUsageFlags.decipherOnly, "Decipher Only"],
];

const extendedUsageNames: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
  "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
  "1.3.6.1.5.5.7.3.3": "Code Signing",
  "1.3.6.1.5.5.7.3.4": "E-mail Protection",
  "1.3.6.1.5.5.7.3.8": "Time Stamping",
  "1.3.6.1.5.5.7.3.9": "OCSP Signing",
};

async function describeCertificate(certificate: X509Certificate): Promise<CertificateInfo> {
  const publicKey = certificate.publicKey;
  const keyAlgorithm = publicKey.algorithm;
  const rawAlgorithm = keyAlgorithm.name;
  const publicKeyAlgorithm = rawAlgorithm.includes("RSA")
    ? "RSA"
    : rawAlgorithm === "ECDSA"
      ? "ECDSA"
      : rawAlgorithm;
  const curve = "namedCurve" in keyAlgorithm && typeof keyAlgorithm.namedCurve === "string" ? keyAlgorithm.namedCurve : null;
  const modulusLength = "modulusLength" in keyAlgorithm && typeof keyAlgorithm.modulusLength === "number" ? keyAlgorithm.modulusLength : null;
  const keySize =
    modulusLength !== null
      ? modulusLength
      : curve
        ? Number(/(?:P-|secp)(\d+)/i.exec(curve)?.[1] ?? 0)
        : ["Ed25519", "Ed448"].includes(rawAlgorithm)
          ? rawAlgorithm === "Ed448"
            ? 448
            : 256
          : 0;

  const basicConstraints = certificate.getExtension(BasicConstraintsExtension);
  const keyUsage = certificate.getExtension(KeyUsagesExtension);
  const extendedUsage = certificate.getExtension(ExtendedKeyUsageExtension);
  const alternativeNames = certificate.getExtension(SubjectAlternativeNameExtension);
  const subjectKeyId = certificate.getExtension(SubjectKeyIdentifierExtension)?.keyId ?? null;
  const authorityKeyId = certificate.getExtension(AuthorityKeyIdentifierExtension)?.keyId ?? null;
  const generalNamePrefixes: Record<string, string> = { dns: "DNS", email: "email", ip: "IP", url: "URI", dn: "DirName", id: "RID" };
  const sans =
    alternativeNames?.names.items.map((name) => {
      const prefix = generalNamePrefixes[name.type] ?? name.type;
      return `${prefix}:${name.value}`;
    }) ?? [];
  const usages = keyUsage ? keyUsageNames.filter(([flag]) => (keyUsage.usages & flag) !== 0).map(([, name]) => name) : [];
  const extendedUsages = extendedUsage?.usages.map((usage) => extendedUsageNames[String(usage)] ?? String(usage)) ?? [];
  const extensionInfo: X509ExtensionInfo[] = certificate.extensions.map((extension) => {
    const value =
      extension.type === "2.5.29.19"
        ? basicConstraints?.ca
          ? `CA:TRUE${basicConstraints.pathLength == null ? "" : `, pathlen:${basicConstraints.pathLength}`}`
          : "CA:FALSE"
        : extension.type === "2.5.29.15"
          ? usages.join(", ")
          : extension.type === "2.5.29.17"
            ? sans.join(", ")
            : extension.type === "2.5.29.37"
              ? extendedUsages.join(", ")
              : extension.type === "2.5.29.14"
                ? subjectKeyId ?? ""
                : extension.type === "2.5.29.35"
                  ? authorityKeyId ?? ""
                  : hex(extension.value);
    return { oid: extension.type, name: extensionNames[extension.type] ?? extension.type, critical: extension.critical, value };
  });

  const notBefore = certificate.notBefore;
  const notAfter = certificate.notAfter;
  const signature = certificate.signatureAlgorithm;
  const hashName = typeof signature.hash === "object" ? signature.hash.name : signature.hash ?? "";
  const signatureName = signature.name.includes("RSA") ? "RSA" : signature.name;
  const signatureAlgorithm = `${hashName.replace("-", "")}with${signatureName}`;
  const [sha256, sha1, spkiSha256] = await Promise.all([
    fingerprintFromThumbprint(certificate, "SHA-256"),
    fingerprintFromThumbprint(certificate, "SHA-1"),
    fingerprintFromThumbprint(publicKey, "SHA-256"),
  ]);
  const daysRemaining = Math.floor((notAfter.getTime() - Date.now()) / 86_400_000);
  const weakReasons = [
    ...(publicKeyAlgorithm === "RSA" && keySize < 2048 ? ["RSA key is smaller than 2048 bits"] : []),
    ...(hashName.toUpperCase() === "SHA-1" ? ["Certificate uses SHA-1"] : []),
  ];

  return {
    version: 3,
    serial_number: certificate.serialNumber,
    signature_algorithm: signatureAlgorithm,
    subject: certificate.subject,
    issuer: certificate.issuer,
    valid_from: isoDate(notBefore),
    valid_to: isoDate(notAfter),
    not_before: Math.floor(notBefore.getTime() / 1000),
    not_after: Math.floor(notAfter.getTime() / 1000),
    days_remaining: daysRemaining,
    is_ca: basicConstraints?.ca ?? false,
    path_len: basicConstraints?.pathLength ?? null,
    self_signed: certificate.subject === certificate.issuer,
    public_key_algorithm: publicKeyAlgorithm,
    key_size: keySize,
    curve,
    sans,
    key_usage: usages,
    extended_key_usage: extendedUsages,
    extensions: extensionInfo,
    subject_key_id: subjectKeyId,
    authority_key_id: authorityKeyId,
    sha256_fingerprint: sha256,
    sha1_fingerprint: sha1,
    spki_sha256: spkiSha256,
    pem: certificate.toString(),
  };
}

async function fingerprintFromThumbprint(
  value: X509Certificate | PublicKey,
  algorithm: "SHA-1" | "SHA-256"
) {
  const digest = await value.getThumbprint(algorithm);
  return fingerprint(digest);
}

async function toEntry(certificate: X509Certificate): Promise<KeystoreEntry> {
  const info = await describeCertificate(certificate);
  const weakReasons = [
    ...(info.public_key_algorithm === "RSA" && info.key_size < 2048 ? ["RSA key is smaller than 2048 bits"] : []),
    ...(info.signature_algorithm.toUpperCase().includes("SHA1") ? ["Certificate uses SHA-1"] : []),
  ];
  return {
    id: `preview:${info.sha256_fingerprint}`,
    alias: info.subject,
    entry_type: "TrustedCertificate",
    algorithm: info.public_key_algorithm,
    key_size: info.key_size,
    curve: info.curve,
    creation_date: info.valid_from.slice(0, 10),
    expiry_date: info.valid_to.slice(0, 10),
    subject: info.subject,
    issuer: info.issuer,
    serial_number: info.serial_number,
    sha256_fingerprint: info.sha256_fingerprint,
    sha1_fingerprint: info.sha1_fingerprint,
    chain_length: 1,
    certificate_chain: [info],
    private_key_pem: null,
    public_key_pem: certificate.publicKey.toString(),
    secret_key_hex: null,
    locked: false,
    protected_key: null,
    key_password: null,
    labels: [],
    is_expired: info.not_after * 1000 < Date.now(),
    is_weak: weakReasons.length > 0,
    weak_reasons: weakReasons,
    is_post_quantum: false,
  };
}

export async function parseBrowserCertificates(data: DataSource): Promise<KeystoreEntry[]> {
  const certificates = decodeCertificates(data);
  if (!certificates.length) throw new Error("No X.509 certificates were found in this file.");
  return Promise.all(certificates.map(toEntry));
}
