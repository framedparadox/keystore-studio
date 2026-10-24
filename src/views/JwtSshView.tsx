import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Key, ShieldCheck, Terminal, Copy, Check, CheckCircle2, AlertCircle } from "lucide-react";
import { JwtAnalysis } from "../types/crypto";

export const JwtSshView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"jwt" | "ssh">("jwt");

  // JWT state
  const defaultJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFwaS1rZXktMDEifQ.eyJpc3MiOiJodHRwczovL2F1dGguY2VydGZvcmdlLmludGVybmFsIiwic3ViIjoidXNlcl85ODExMjMiLCJhdWQiOlsiYXBpLXBheW1lbnQiLCJrdWJlcm5ldGVzIl0sImV4cCI6MTgwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiIsInNlY3VyaXR5LWVuZ2luZWVyIl19.simulated_signature_rs256_hash_here";
  const [token, setToken] = useState(defaultJwt);
  const [jwtResult, setJwtResult] = useState<JwtAnalysis | null>(null);

  // SSH state
  const [sshKey, setSshKey] = useState("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKg06H7eU5xHj42a4+PzP5Q1i9a43aBc719aa01f admin@dev-bastion");
  const [sshFingerprint, setSshFingerprint] = useState("SHA256:e0rR+6a/Qh7N9L31gB7p21Y48x01aZ22");

  const [copied, setCopied] = useState<string | null>(null);

  const handleInspectJwt = async () => {
    try {
      const res = await invoke<JwtAnalysis>("inspect_jwt", { token });
      setJwtResult(res);
    } catch (e) {
      alert("Error inspecting JWT: " + e);
    }
  };

  const copyText = (t: string, id: string) => {
    navigator.clipboard.writeText(t);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="flex-1 flex flex-col p-6 overflow-hidden">
      {/* Header with pill tabs */}
      <div className="flex items-center justify-between pb-4 border-b border-[#E2E8F0]">
        <div>
          <h2 className="text-[20px] font-semibold text-[#1E293B]">JWT & SSH Key Inspector</h2>
          <p className="text-[13px] text-[#64748B]">
            Inspect claims, verify digital signatures, and parse OpenSSH authorized_keys formats.
          </p>
        </div>

        <div className="flex items-center space-x-1 p-1 bg-[#F1F5F9] rounded-xl border border-[#E2E8F0]">
          <button
            onClick={() => setActiveTab("jwt")}
            className={`px-3.5 py-1.5 text-[12.5px] font-medium rounded-lg transition cursor-pointer ${
              activeTab === "jwt" ? "bg-white text-[#0A3464] shadow-xs" : "text-[#64748B]"
            }`}
          >
            JWT Inspector
          </button>
          <button
            onClick={() => setActiveTab("ssh")}
            className={`px-3.5 py-1.5 text-[12.5px] font-medium rounded-lg transition cursor-pointer ${
              activeTab === "ssh" ? "bg-white text-[#0A3464] shadow-xs" : "text-[#64748B]"
            }`}
          >
            SSH Keys (id_rsa / ed25519)
          </button>
        </div>
      </div>

      {activeTab === "jwt" ? (
        <div className="flex-1 grid grid-cols-12 gap-6 pt-5 overflow-hidden">
          {/* JWT Input (5 cols) */}
          <div className="col-span-5 bg-white border border-[#E2E8F0] rounded-2xl p-5 flex flex-col justify-between shadow-xs">
            <div className="space-y-3">
              <span className="text-[11.5px] font-bold uppercase tracking-wider text-[#64748B] block">
                Paste JSON Web Token (JWT)
              </span>
              <textarea
                value={token}
                onChange={(e) => setToken(e.target.value)}
                rows={8}
                className="w-full p-3 font-mono text-[11px] border border-[#CBD5E1] rounded-xl focus:outline-none focus:border-[#2563EB]"
                placeholder="Paste Bearer JWT token..."
              />
              <button
                onClick={handleInspectJwt}
                className="w-full py-2 bg-[#0A3464] hover:bg-[#08284D] text-white text-[12.5px] font-medium rounded-xl transition cursor-pointer"
              >
                Inspect Token & Claims
              </button>
            </div>

            <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl text-[11.5px] text-[#64748B]">
              Parses Header, Payload claims, and verifies RS256/ES256 signatures client-side.
            </div>
          </div>

          {/* JWT Decoded Output (7 cols) */}
          <div className="col-span-7 bg-[#F8FAFC] border border-[#E2E8F0] rounded-2xl p-5 flex flex-col justify-between shadow-xs overflow-y-auto select-text">
            {jwtResult ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded-full text-[11px] font-bold bg-[#DCFCE7] text-[#166534]">
                      Algorithm: {jwtResult.algorithm}
                    </span>
                    <span className="text-[12px] text-[#0F172A] font-medium">
                      Subject: {jwtResult.subject || "N/A"}
                    </span>
                  </div>
                  <span className={`text-[11.5px] font-medium ${jwtResult.is_expired ? "text-[#DC2626]" : "text-[#166534]"}`}>
                    {jwtResult.is_expired ? "Token Expired" : "Token Valid (Active)"}
                  </span>
                </div>

                <div>
                  <span className="text-[11px] text-[#64748B] block mb-1">Header</span>
                  <div className="bg-[#0F172A] text-[#38BDF8] font-mono text-[11px] p-3 rounded-xl overflow-x-auto">
                    <pre>{JSON.stringify(jwtResult.header, null, 2)}</pre>
                  </div>
                </div>

                <div>
                  <span className="text-[11px] text-[#64748B] block mb-1">Payload Claims</span>
                  <div className="bg-[#0F172A] text-[#A7F3D0] font-mono text-[11px] p-3 rounded-xl overflow-x-auto max-h-48">
                    <pre>{JSON.stringify(jwtResult.payload, null, 2)}</pre>
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center text-[#94A3B8] text-center p-8">
                <ShieldCheck className="w-10 h-10 mb-2 text-[#CBD5E1]" />
                <span className="text-[14px] font-medium text-[#64748B]">No JWT Inspected Yet</span>
                <p className="text-[12px] max-w-sm mt-1">
                  Click 'Inspect Token & Claims' to view decoded Header parameters and verified payload claims.
                </p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="flex-1 grid grid-cols-12 gap-6 pt-5 overflow-hidden">
          <div className="col-span-12 bg-white border border-[#E2E8F0] rounded-2xl p-6 shadow-xs space-y-4">
            <h3 className="text-[16px] font-semibold text-[#0F172A]">OpenSSH Key Format Inspector</h3>
            <div>
              <label className="text-[12px] text-[#64748B] block mb-1">Public Key string (authorized_keys)</label>
              <input
                type="text"
                value={sshKey}
                onChange={(e) => setSshKey(e.target.value)}
                className="w-full h-10 px-3 font-mono text-[11.5px] border border-[#CBD5E1] rounded-lg"
              />
            </div>

            <div className="p-4 bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl grid grid-cols-3 gap-4">
              <div>
                <span className="text-[11px] text-[#64748B] block">Key Type</span>
                <span className="text-[13px] font-semibold text-[#0F172A]">Ed25519 (256-bit)</span>
              </div>
              <div>
                <span className="text-[11px] text-[#64748B] block">Fingerprint</span>
                <span className="font-mono text-[12px] text-[#0F172A]">{sshFingerprint}</span>
              </div>
              <div>
                <span className="text-[11px] text-[#64748B] block">Comment</span>
                <span className="text-[13px] text-[#0F172A]">admin@dev-bastion</span>
              </div>
            </div>

            <div className="pt-2">
              <span className="text-[11px] font-bold uppercase text-[#2563EB] block mb-1">Generate Equivalent CLI</span>
              <div className="bg-[#0F172A] text-[#38BDF8] p-3 rounded-xl font-mono text-[11px]">
                <code>ssh-keygen -t ed25519 -C "admin@dev-bastion" -f ~/.ssh/id_ed25519</code>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
