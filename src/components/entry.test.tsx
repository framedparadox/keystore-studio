import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { KeystoreEntry } from "../types/crypto";
import { ValidityCell } from "./entry";

const entry: KeystoreEntry = {
  id: "certificate",
  alias: "certificate",
  entry_type: "TrustedCertificate",
  algorithm: "RSA",
  key_size: 2048,
  creation_date: "2023-01-01",
  expiry_date: "2024-01-01",
  subject: "CN=certificate",
  issuer: "CN=certificate",
  serial_number: "01",
  sha256_fingerprint: "",
  sha1_fingerprint: "",
  chain_length: 0,
  certificate_chain: [],
  locked: false,
  labels: [],
  is_expired: true,
  is_weak: false,
  weak_reasons: [],
  is_post_quantum: false,
};

describe("ValidityCell", () => {
  it("says how long is left, or how long ago it expired, with an accessible description", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2025-01-01T00:00:00Z"));
    try {
      const expired = renderToStaticMarkup(<ValidityCell entry={entry} />);
      expect(expired).toContain('aria-label="Expired 1y ago"');
      expect(expired).toContain(">1y ago</span>");
      expect(renderToStaticMarkup(<ValidityCell entry={{ ...entry, expiry_date: "2026-01-01" }} />)).toContain(">1y left</span>");
    } finally {
      vi.useRealTimers();
    }
  });
});
