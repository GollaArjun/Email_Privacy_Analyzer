import React from 'react';
import {
  ShieldCheck,
  Cpu,
  Database,
  Lock,
  Layers,
  FileCheck,
  ExternalLink,
  Code2,
} from 'lucide-react';

const About = () => {
  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Hero */}
      <div className="text-center space-y-3">
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase tracking-widest">
          Architecture & Privacy Philosophy
        </span>
        <h2 className="text-2xl font-bold text-white tracking-tight">
          About Email Privacy Analyzer (EPA)
        </h2>
        <p className="text-xs text-slate-400 max-w-2xl mx-auto">
          An advanced cybersecurity and privacy analysis system designed to protect individuals and organizations from credential leakage, covert telemetry tracking, and sophisticated phishing lures.
        </p>
      </div>

      {/* Core Design Principles */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-panel p-5 space-y-2.5 border-slate-700/80">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center justify-center">
            <Lock className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-white">Zero Cloud Exposure</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            All AI reasoning is hosted on your infrastructure via local Ollama models. Your email content is never transmitted to external third-party AI APIs.
          </p>
        </div>

        <div className="glass-panel p-5 space-y-2.5 border-slate-700/80">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 flex items-center justify-center">
            <Cpu className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-white">Hybrid Threat Engine</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Combines deterministic regular expression pattern matchers, Microsoft Presidio NER, SPF/DKIM validation, and deep contextual LLM analysis.
          </p>
        </div>

        <div className="glass-panel p-5 space-y-2.5 border-slate-700/80">
          <div className="w-10 h-10 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-white">Non-Executing Sandbox</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            MIME structure parsing and attachment inspections are purely static. Executable binaries and scripts are inspected via hashes and headers without running.
          </p>
        </div>
      </div>

      {/* Technical Architecture */}
      <div className="glass-panel p-6 border-slate-700/80 space-y-4">
        <h3 className="text-sm font-bold text-white font-mono uppercase flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>System Architecture & Pipeline</span>
        </h3>

        <div className="p-4 rounded-lg bg-cyber-950 border border-slate-800 text-xs font-mono text-slate-300 space-y-2 leading-relaxed">
          <p className="text-cyan-400 font-bold">1. Ingestion Layer:</p>
          <p className="pl-4 text-slate-400">
            Accepts raw .EML files or Google OAuth 2.0 read-only mailbox messages. Decodes MIME structures, multipart payloads, and attachments.
          </p>

          <p className="text-cyan-400 font-bold">2. Security Extraction:</p>
          <p className="pl-4 text-slate-400">
            • Microsoft Presidio & Custom Recognizers detect Aadhaar, PAN, Passwords, API Keys, and IPs.<br />
            • Phishing Module identifies Punycode homographs, shorteners, IP hosts, and From vs Reply-To mismatches.<br />
            • Tracking Module detects 1x1 invisible pixels and ESP web beacons.<br />
            • Header Analyzer verifies SPF, DKIM, DMARC, and Received MTA hops.<br />
            • Attachment Module flags double extensions (.pdf.exe) and macro-enabled Office files.
          </p>

          <p className="text-cyan-400 font-bold">3. Explainable Risk Scoring:</p>
          <p className="pl-4 text-slate-400">
            Weights findings across 6 distinct categories with deduplication, normalized between 0-100 across 5 clear risk tiers.
          </p>

          <p className="text-cyan-400 font-bold">4. Hybrid AI Synthesis:</p>
          <p className="pl-4 text-slate-400">
            Passes sanitized, non-executable metadata to local Ollama (e.g. llama3) with strict prompt isolation to avoid prompt injection, generating actionable remediation advice.
          </p>
        </div>
      </div>

      {/* Technology Stack Table */}
      <div className="glass-panel p-6 border-slate-700/80 space-y-4">
        <h3 className="text-sm font-bold text-white font-mono uppercase flex items-center gap-2">
          <Code2 className="w-4 h-4 text-cyan-400" />
          <span>Core Technology Stack</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 rounded bg-cyber-950 border border-slate-800">
            <span className="text-slate-500 text-[10px] block">FRONTEND</span>
            <span className="text-white font-bold">React.js + Vite</span>
            <span className="text-slate-400 text-[11px] block">Tailwind CSS, Lucide, Recharts</span>
          </div>

          <div className="p-3 rounded bg-cyber-950 border border-slate-800">
            <span className="text-slate-500 text-[10px] block">BACKEND</span>
            <span className="text-white font-bold">FastAPI + Python</span>
            <span className="text-slate-400 text-[11px] block">Pydantic v2, Uvicorn</span>
          </div>

          <div className="p-3 rounded bg-cyber-950 border border-slate-800">
            <span className="text-slate-500 text-[10px] block">SECURITY & AI</span>
            <span className="text-white font-bold">Presidio + Ollama</span>
            <span className="text-slate-400 text-[11px] block">spacy, Fernet Cryptography</span>
          </div>

          <div className="p-3 rounded bg-cyber-950 border border-slate-800">
            <span className="text-slate-500 text-[10px] block">DATABASE</span>
            <span className="text-white font-bold">MongoDB Atlas</span>
            <span className="text-slate-400 text-[11px] block">PyMongo + In-Memory Fallback</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default About;
