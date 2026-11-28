import { describe, expect, it } from "vitest";
import { parseBrowserCertificates } from "./browser-certificates";

const derCertificate =
  "MIIB/DCCAaagAwIBAgIBATANBgkqhkiG9w0BAQQFADCBhjELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExJjAkBgkqhkiG9w0BCQEWF2lzc3VlckBib3VuY3ljYXN0bGUub3JnMB4XDTE0MDIyODExMjcxMVoXDTE0MDQyOTExMjcxMVowgYcxCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMScwJQYJKoZIhvcNAQkBFhhzdWJqZWN0QGJvdW5jeWNhc3RsZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBETANBgkqhkiG9w0BAQQFAANBAJ/ZhfF21NykhbEYRQrAo/yRr9XfpmBTVUSlLJXYoNVVRT5u9SGQqmPNfHElrTvNMZQPC0ridDZtBWb6S2tg9/E=";

describe("browser certificate preview", () => {
  it("parses DER files and pasted PEM into certificate entries", async () => {
    const [fromDer] = await parseBrowserCertificates({ base64: derCertificate });
    const [fromPem] = await parseBrowserCertificates({ text: fromDer.certificate_chain[0].pem });

    expect(fromDer.entry_type).toBe("TrustedCertificate");
    expect(fromDer.subject).toContain("The Legion of the Bouncy Castle");
    expect(fromDer.sha256_fingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(fromDer.certificate_chain[0].not_before).toBeGreaterThan(0);
    expect(fromPem.sha256_fingerprint).toBe(fromDer.sha256_fingerprint);
  });

  it("rejects input that contains no certificate", async () => {
    await expect(parseBrowserCertificates({ text: "not a certificate" })).rejects.toThrow();
  });
});
