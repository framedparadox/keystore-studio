import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ShieldAlert, AlertTriangle, CheckCircle2, Copy, Check, Terminal, ShieldCheck } from "lucide-react";
import { SecurityAuditReport } from "../types/crypto";

export const ScannerView: React.FC = () => {
  const [report, setReport] = useState<SecurityAuditReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const fetchAudit = async () => {
    setLoading(true);
    try {
      const res = await invoke<SecurityAuditReport>("run_security_audit");
      setReport(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudit();
  }, []);

  const copyFix = (cli: string, id: string) => {
    navigator.clipboard.writeText(cli);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="flex-1 flex flex-col p-6 overflow-hidden">
      {/* View Header */}
      <div className="flex items-center justify-between pb-4 border-b border-[#E2E8F0]">
        <div>
          <h2 className="text-[20px] font-semibold text-[#1E293B]">Health & Security Scanner</h2>
          <p className="text-[13px] text-[#64748B]">
            Automated cryptographic vulnerability audit flagging weak keys, deprecated hashes, and upcoming expirations.
          </p>
        </div>

        <button
          onClick={fetchAudit}
          disabled={loading}
          className="px-3.5 py-1.5 rounded-lg bg-[#0A3464] hover:bg-[#07274C] text-white text-[12.5px] font-medium transition cursor-pointer flex items-center space-x-1.5"
        >
          <ShieldCheck className="w-4 h-4" />
          <span>{loading ? "Scanning..." : "Re-Run Health Scan"}</span>
        </button>
      </div>

      {report && (
        <div className="flex-1 flex flex-col pt-5 space-y-5 overflow-y-auto pr-1">
          {/* Top Score Cards */}
          <div className="grid grid-cols-4 gap-4">
            <div className="p-4 bg-white border border-[#E2E8F0] rounded-2xl shadow-xs">
              <span className="text-[11.5px] font-medium text-[#64748B] block">Overall Security Score</span>
              <div className="flex items-baseline space-x-2 mt-1">
                <span className="text-[28px] font-bold text-[#059669]">{report.health_score}</span>
                <span className="text-[14px] text-[#64748B]">/ 100</span>
              </div>
              <span className="text-[11px] text-[#059669] font-medium">Standard Compliance Met</span>
            </div>

            <div className="p-4 bg-white border border-[#E2E8F0] rounded-2xl shadow-xs">
              <span className="text-[11.5px] font-medium text-[#64748B] block">Weak Keys (RSA &lt; 2048)</span>
              <div className="mt-1">
                <span className="text-[28px] font-bold text-[#DC2626]">{report.weak_keys_count}</span>
              </div>
              <span className="text-[11px] text-[#DC2626] font-medium">1 Insecure Key Requires Rotation</span>
            </div>

            <div className="p-4 bg-white border border-[#E2E8F0] rounded-2xl shadow-xs">
              <span className="text-[11.5px] font-medium text-[#64748B] block">Deprecated Hashes (SHA-1/MD5)</span>
              <div className="mt-1">
                <span className="text-[28px] font-bold text-[#D97706]">{report.deprecated_hashes_count}</span>
              </div>
              <span className="text-[11px] text-[#D97706] font-medium">SHA-1 Collision Risk</span>
            </div>

            <div className="p-4 bg-white border border-[#E2E8F0] rounded-2xl shadow-xs">
              <span className="text-[11.5px] font-medium text-[#64748B] block">Expiring Soon (&lt; 30 Days)</span>
              <div className="mt-1">
                <span className="text-[28px] font-bold text-[#2563EB]">{report.expiring_soon_count}</span>
              </div>
              <span className="text-[11px] text-[#2563EB] font-medium">Certificates Needing Renewal</span>
            </div>
          </div>

          {/* Issue Cards */}
          <div className="space-y-3">
            <h3 className="text-[14px] font-bold uppercase tracking-wider text-[#475569]">
              Audit Findings & Recommended CLI Fixes
            </h3>

            {report.issues.map((issue, idx) => (
              <div
                key={idx}
                className="p-4 bg-white border border-[#E2E8F0] rounded-xl flex flex-col space-y-2.5 shadow-xs"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10.5px] font-bold ${
                        issue.severity === "CRITICAL"
                          ? "bg-[#FEE2E2] text-[#991B1B]"
                          : issue.severity === "WARNING"
                          ? "bg-[#FEF3C7] text-[#92400E]"
                          : "bg-[#EFF6FF] text-[#1E40AF]"
                      }`}
                    >
                      {issue.severity}
                    </span>
                    <h4 className="text-[14.5px] font-semibold text-[#0F172A]">{issue.title}</h4>
                  </div>

                  <button
                    onClick={() => copyFix(issue.cli_fix, `fix-${idx}`)}
                    className="flex items-center space-x-1 px-2.5 py-1 text-[11.5px] bg-[#F8FAFC] border border-[#CBD5E1] rounded-md text-[#334155] hover:bg-[#F1F5F9] cursor-pointer"
                  >
                    {copied === `fix-${idx}` ? (
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                    ) : (
                      <Copy className="w-3.5 h-3.5 text-[#2563EB]" />
                    )}
                    <span>{copied === `fix-${idx}` ? "Copied" : "Copy Remediation CLI"}</span>
                  </button>
                </div>

                <p className="text-[12.5px] text-[#475569] leading-relaxed">{issue.description}</p>
                <p className="text-[12px] text-[#059669] font-medium">Recommendation: {issue.recommendation}</p>

                <div className="bg-[#0F172A] text-[#38BDF8] font-mono text-[11px] p-2.5 rounded-lg overflow-x-auto">
                  <code>{issue.cli_fix}</code>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
