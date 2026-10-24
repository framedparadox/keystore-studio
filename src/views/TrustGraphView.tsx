import React, { useState } from "react";
import { GitFork, CheckCircle2, AlertTriangle, XCircle, ArrowRight, ShieldCheck, RefreshCw } from "lucide-react";

export const TrustGraphView: React.FC = () => {
  const [simulateBroken, setSimulateBroken] = useState(false);
  const [selectedNode, setSelectedNode] = useState<string>("leaf");

  const nodes = [
    {
      id: "root",
      type: "Root CA",
      cn: "CertForge Global Root CA G3",
      org: "CertForge Trust Network",
      validity: "2020 - 2045",
      algorithm: "RSA 4096 / SHA-384",
      status: "TRUSTED_ROOT",
      fingerprint: "7A:B4:88:99:34:F1:C0:E4:99:02:11:78:44:66:33:AA",
    },
    {
      id: "intermediate",
      type: "Intermediate CA",
      cn: "CertForge Enterprise Issuing CA 2",
      org: "CertForge Trust Network",
      validity: simulateBroken ? "EXPIRED (2024-01-01)" : "2023 - 2030",
      algorithm: "ECDSA P-384 / SHA-384",
      status: simulateBroken ? "BROKEN_LINK" : "VALID_CHAIN",
      fingerprint: "EE:09:44:12:BC:77:22:10:99:AB:40:21:DE:45:90:11",
    },
    {
      id: "leaf",
      type: "End-Entity (Server TLS)",
      cn: "api.certforge.internal",
      org: "Cloud Platform Systems",
      validity: "2025 - 2027",
      algorithm: "RSA 4096 / SHA-256",
      status: simulateBroken ? "UNTRUSTED_CHAIN" : "VALID",
      fingerprint: "A9:4B:88:2E:7C:1F:09:44:81:AA:62:30:19:D8:EF:90",
    },
  ];

  const currentNode = nodes.find((n) => n.id === selectedNode) || nodes[2];

  return (
    <div className="flex-1 flex flex-col p-6 overflow-hidden">
      {/* View Header */}
      <div className="flex items-center justify-between pb-4 border-b border-[#E2E8F0]">
        <div>
          <h2 className="text-[20px] font-semibold text-[#1E293B]">Visual Trust Graph</h2>
          <p className="text-[13px] text-[#64748B]">
            Interactive certificate hierarchy inspector. Pinpoints broken links, untrusted anchors, and expired intermediates.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setSimulateBroken(!simulateBroken)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border text-[12.5px] font-medium transition cursor-pointer ${
              simulateBroken
                ? "bg-[#FEF2F2] border-[#FCA5A5] text-[#991B1B]"
                : "bg-white border-[#CBD5E1] text-[#334155] hover:bg-[#F8FAFC]"
            }`}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>{simulateBroken ? "Restore Valid Chain" : "Simulate Broken Chain"}</span>
          </button>
        </div>
      </div>

      {/* Main Graph Canvas */}
      <div className="flex-1 grid grid-cols-12 gap-6 pt-5 overflow-hidden">
        {/* Node Chain Diagram (8 cols) */}
        <div className="col-span-8 bg-white border border-[#E2E8F0] rounded-2xl p-6 flex flex-col justify-between shadow-xs overflow-y-auto">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-[12px] font-bold uppercase tracking-wider text-[#64748B]">
                Chain Path: Root Anchor &rarr; Intermediates &rarr; Leaf
              </span>
              <span
                className={`flex items-center space-x-1 px-2.5 py-1 text-[11.5px] font-semibold rounded-full ${
                  simulateBroken
                    ? "bg-[#FEE2E2] text-[#DC2626]"
                    : "bg-[#DCFCE7] text-[#166534]"
                }`}
              >
                {simulateBroken ? (
                  <>
                    <XCircle className="w-3.5 h-3.5 text-[#DC2626]" />
                    <span>Broken Trust Chain (Handshake Failure)</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-[#166534]" />
                    <span>Trust Chain Verified (100% OK)</span>
                  </>
                )}
              </span>
            </div>

            {/* Visual Node Chain Flow */}
            <div className="space-y-4 pt-2">
              {nodes.map((node, index) => {
                const isSelected = selectedNode === node.id;
                const isBroken = simulateBroken && (node.id === "intermediate" || node.id === "leaf");

                return (
                  <div key={node.id} className="relative">
                    {/* Node Card */}
                    <div
                      onClick={() => setSelectedNode(node.id)}
                      className={`p-4 rounded-xl border-2 transition-all cursor-pointer flex items-center justify-between ${
                        isSelected
                          ? "border-[#2563EB] bg-[#EFF6FF]/60 shadow-sm"
                          : isBroken
                          ? "border-[#F87171] bg-[#FEF2F2]/50 hover:border-[#EF4444]"
                          : "border-[#E2E8F0] bg-white hover:border-[#CBD5E1] hover:bg-[#F8FAFC]"
                      }`}
                    >
                      <div className="flex items-center space-x-3.5">
                        <div
                          className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 ${
                            isBroken
                              ? "bg-[#FEE2E2] text-[#DC2626]"
                              : "bg-[#EFF6FF] text-[#2563EB]"
                          }`}
                        >
                          <ShieldCheck className="w-5 h-5" />
                        </div>

                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="text-[11px] font-bold uppercase tracking-wider text-[#64748B]">
                              {node.type}
                            </span>
                            {isBroken ? (
                              <span className="text-[10.5px] font-semibold px-2 py-0.2 rounded-full bg-[#FEE2E2] text-[#991B1B]">
                                Trust Broken
                              </span>
                            ) : (
                              <span className="text-[10.5px] font-semibold px-2 py-0.2 rounded-full bg-[#DCFCE7] text-[#166534]">
                                Valid
                              </span>
                            )}
                          </div>
                          <h4 className="text-[14.5px] font-semibold text-[#0F172A] mt-0.5">
                            {node.cn}
                          </h4>
                          <span className="text-[12px] text-[#64748B]">
                            {node.org} • {node.algorithm}
                          </span>
                        </div>
                      </div>

                      <div className="text-right">
                        <span className="text-[11px] text-[#64748B] block">Validity Window</span>
                        <span className={`text-[12px] font-mono font-medium ${isBroken ? "text-[#DC2626]" : "text-[#0F172A]"}`}>
                          {node.validity}
                        </span>
                      </div>
                    </div>

                    {/* Connecting Link Arrow */}
                    {index < nodes.length - 1 && (
                      <div className="flex justify-center my-1.5">
                        <div className={`w-0.5 h-5 ${isBroken ? "bg-[#F87171]" : "bg-[#93C5FD]"}`} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Bottom Diagnostic Alert */}
          <div className="mt-4 p-3 rounded-xl bg-[#F8FAFC] border border-[#E2E8F0] text-[12px] text-[#475569] flex items-center justify-between">
            <span>
              Diagnostic Engine: {simulateBroken ? "Detected invalid signature path from Root to Intermediate." : "All cryptographic signatures in chain verified."}
            </span>
            <span className="font-mono text-[11px] text-[#2563EB]">
              openssl verify -CAfile root.pem intermediate.pem
            </span>
          </div>
        </div>

        {/* Selected Node Details (4 cols) */}
        <div className="col-span-4 bg-[#F8FAFC] border border-[#E2E8F0] rounded-2xl p-5 flex flex-col justify-between shadow-xs select-text">
          <div className="space-y-4">
            <div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#64748B]">
                Certificate Node Inspector
              </span>
              <h3 className="text-[16px] font-semibold text-[#0F172A] mt-0.5">
                {currentNode.cn}
              </h3>
              <span className="text-[12px] text-[#2563EB] font-medium">{currentNode.type}</span>
            </div>

            <div className="space-y-2.5 text-[12px]">
              <div>
                <span className="text-[#64748B] block text-[11px]">Organization (O)</span>
                <span className="text-[#0F172A] font-medium">{currentNode.org}</span>
              </div>
              <div>
                <span className="text-[#64748B] block text-[11px]">Algorithm / Modulus</span>
                <span className="font-mono text-[#0F172A]">{currentNode.algorithm}</span>
              </div>
              <div>
                <span className="text-[#64748B] block text-[11px]">SHA-256 Fingerprint</span>
                <div className="bg-white border border-[#CBD5E1] p-1.5 rounded-md font-mono text-[10.5px] text-[#334155] break-all">
                  {currentNode.fingerprint}
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-[#E2E8F0]">
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#2563EB] block mb-1">
                Verification CLI Command
              </span>
              <div className="bg-[#0F172A] text-[#38BDF8] p-2.5 rounded-lg font-mono text-[10.5px] overflow-x-auto">
                <code>openssl x509 -in cert.crt -text -noout</code>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
