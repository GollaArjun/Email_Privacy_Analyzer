import React, { useState, useEffect } from 'react';
import {
  UploadCloud,
  FileCode,
  ShieldAlert,
  Sparkles,
  AlertCircle,
  CheckCircle2,
  FileText,
  Zap,
} from 'lucide-react';
import { analyzerService } from '../services/api';

const STAGES = [
  { label: 'Parsing MIME structure and RFC 822 headers', pct: 20 },
  { label: 'Scanning for PII & credential leaks (Presidio + Rules)', pct: 45 },
  { label: 'Analyzing destination URLs, shorteners & punycode', pct: 65 },
  { label: 'Detecting 1x1 tracking pixels & attachment threats', pct: 85 },
  { label: 'Computing explainable risk score & synthesizing report', pct: 98 },
];

const AnalyzeEmail = ({ onAnalysisComplete }) => {
  const [activeTab, setActiveTab] = useState('upload'); // 'upload' | 'raw'
  const [file, setFile] = useState(null);
  const [rawText, setRawText] = useState('');
  const [samples, setSamples] = useState([]);
  const [selectedSample, setSelectedSample] = useState('');
  const [loading, setLoading] = useState(false);
  const [currentStageIdx, setCurrentStageIdx] = useState(0);
  const [error, setError] = useState('');
  const [dragActive, setDragActive] = useState(false);

  // Fetch sample test emails
  useEffect(() => {
    const fetchSamples = async () => {
      try {
        const data = await analyzerService.getSamples();
        setSamples(data);
      } catch (err) {
        console.warn('Could not load sample emails:', err);
      }
    };
    fetchSamples();
  }, []);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelected = (selectedFile) => {
    setError('');
    const ext = selectedFile.name.split('.').pop().toLowerCase();
    if (!['eml', 'msg', 'txt'].includes(ext)) {
      setError('Invalid file type. Please upload a standard .eml, .msg, or .txt email file.');
      return;
    }
    if (selectedFile.size > 20 * 1024 * 1024) {
      setError('File size exceeds the 20MB maximum safety threshold.');
      return;
    }
    setFile(selectedFile);
  };

  const handleSampleSelected = (sampleId) => {
    setSelectedSample(sampleId);
    const found = samples.find((s) => s.id === sampleId);
    if (found) {
      setRawText(found.content);
      setActiveTab('raw');
      setError('');
    }
  };

  const runAnalysis = async () => {
    setError('');
    setLoading(true);
    setCurrentStageIdx(0);

    // Progression timer to communicate analysis phases
    const interval = setInterval(() => {
      setCurrentStageIdx((prev) => (prev < STAGES.length - 1 ? prev + 1 : prev));
    }, 700);

    try {
      let reportData = null;
      if (activeTab === 'upload') {
        if (!file) {
          setError('Please select or drop an .eml email file first.');
          setLoading(false);
          clearInterval(interval);
          return;
        }
        reportData = await analyzerService.analyzeEml(file);
      } else {
        if (!rawText.trim()) {
          setError('Please paste RFC822 email text or choose a test sample above.');
          setLoading(false);
          clearInterval(interval);
          return;
        }
        reportData = await analyzerService.analyzeRaw(rawText);
      }

      clearInterval(interval);
      if (onAnalysisComplete && reportData) {
        onAnalysisComplete(reportData);
      }
    } catch (err) {
      clearInterval(interval);
      console.error('Analysis failed:', err);
      setError(
        err.response?.data?.detail ||
          'Security analysis failed. Please verify the email format and backend connection.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header Banner */}
      <div className="text-center space-y-2">
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase tracking-widest">
          Security Threat & Privacy Engine
        </span>
        <h2 className="text-2xl font-bold text-white tracking-tight">
          Analyze Email for Privacy Leaks & Phishing
        </h2>
        <p className="text-xs text-slate-400 max-w-xl mx-auto">
          Upload any standard .eml file or paste raw email headers & body. The engine scans for PII, tracking pixels, header spoofing, malicious attachments, and AI-assessed risks.
        </p>
      </div>

      {/* Quick Test Samples Selector */}
      {samples.length > 0 && (
        <div className="glass-panel p-4 border-slate-700/60 bg-cyber-900/40">
          <div className="flex items-center gap-2 mb-2">
            <Zap className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
              Quick Test: Pre-Packaged Synthetic Cyber Scenarios
            </h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
            {samples.map((s) => (
              <button
                key={s.id}
                onClick={() => handleSampleSelected(s.id)}
                className={`p-2.5 rounded-lg text-left border transition-all text-xs flex flex-col justify-between ${
                  selectedSample === s.id && activeTab === 'raw'
                    ? 'border-cyan-500 bg-cyan-500/10 text-white shadow-sm shadow-cyan-500/20'
                    : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-white hover:border-slate-700'
                }`}
              >
                <span className="font-semibold text-slate-200 line-clamp-1">{s.title}</span>
                <span className="text-[10px] text-slate-500 mt-1 line-clamp-2">{s.description}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Main Analyzer Card */}
      <div className="glass-panel p-6 border-slate-700/80">
        {/* Input Method Tabs */}
        <div className="flex border-b border-slate-800 mb-6">
          <button
            onClick={() => setActiveTab('upload')}
            className={`flex items-center gap-2 px-6 py-3 text-xs font-medium border-b-2 transition-all ${
              activeTab === 'upload'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload .EML File</span>
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`flex items-center gap-2 px-6 py-3 text-xs font-medium border-b-2 transition-all ${
              activeTab === 'raw'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Paste Raw Email / Headers</span>
          </button>
        </div>

        {/* Tab 1: Drag-and-Drop File Upload */}
        {activeTab === 'upload' && (
          <div className="space-y-4">
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              className={`border-2 border-dashed rounded-xl p-8 text-center transition-all ${
                dragActive
                  ? 'border-cyan-400 bg-cyan-500/10 shadow-cyber-cyan/20'
                  : file
                  ? 'border-emerald-500/60 bg-emerald-500/5'
                  : 'border-slate-700 hover:border-slate-600 bg-slate-900/30'
              }`}
            >
              <input
                id="file-upload"
                type="file"
                accept=".eml,.msg,.txt"
                onChange={(e) => e.target.files && handleFileSelected(e.target.files[0])}
                className="hidden"
              />

              {file ? (
                <div className="flex flex-col items-center space-y-2">
                  <div className="w-12 h-12 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center justify-center">
                    <CheckCircle2 className="w-6 h-6" />
                  </div>
                  <h4 className="text-sm font-semibold text-white">{file.name}</h4>
                  <p className="text-xs text-slate-400 font-mono">
                    {(file.size / 1024).toFixed(1)} KB &bull; Ready for security inspection
                  </p>
                  <label
                    htmlFor="file-upload"
                    className="mt-2 text-xs text-cyan-400 hover:underline cursor-pointer font-medium"
                  >
                    Choose a different file
                  </label>
                </div>
              ) : (
                <label htmlFor="file-upload" className="cursor-pointer block space-y-3">
                  <div className="w-12 h-12 rounded-full bg-slate-800 border border-slate-700 text-slate-300 flex items-center justify-center mx-auto transition-transform hover:scale-105">
                    <UploadCloud className="w-6 h-6 text-cyan-400" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-white">
                      Drop .EML email file here, or{' '}
                      <span className="text-cyan-400 underline">browse</span>
                    </p>
                    <p className="text-xs text-slate-500 mt-1">
                      Supports RFC 822 MIME .eml, .msg files up to 20MB. Safe non-executing sandbox.
                    </p>
                  </div>
                </label>
              )}
            </div>
          </div>
        )}

        {/* Tab 2: Raw Email Text Paste */}
        {activeTab === 'raw' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Paste complete email with headers (RFC822):</span>
              <span className="font-mono text-[11px]">{rawText.length} characters</span>
            </div>
            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="From: sender@example.com&#10;To: recipient@example.com&#10;Subject: Urgent Security Notice&#10;Date: Sun, 15 Nov 2026 12:00:00 +0000&#10;&#10;Email body content here..."
              rows={12}
              className="w-full bg-cyber-950 border border-slate-800 rounded-lg p-4 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
            />
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mt-4 p-3 rounded-lg border border-red-500/40 bg-red-500/10 text-red-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Multi-stage Scan Progress Indicator */}
        {loading && (
          <div className="mt-6 p-4 rounded-xl border border-cyan-500/30 bg-cyber-900/80 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-cyan-400 font-semibold flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                PHASE {currentStageIdx + 1} OF {STAGES.length}: {STAGES[currentStageIdx].label}
              </span>
              <span className="text-slate-400">{STAGES[currentStageIdx].pct}%</span>
            </div>
            
            {/* Visual Progress Bar */}
            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 via-emerald-400 to-cyan-400 transition-all duration-500"
                style={{ width: `${STAGES[currentStageIdx].pct}%` }}
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-5 gap-1.5 pt-1">
              {STAGES.map((st, i) => (
                <div
                  key={i}
                  className={`text-[10px] font-mono px-2 py-1 rounded border text-center transition-all ${
                    i < currentStageIdx
                      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                      : i === currentStageIdx
                      ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300 font-bold'
                      : 'border-slate-800 text-slate-600'
                  }`}
                >
                  Step {i + 1}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Execute Scan Button */}
        <div className="mt-6 flex items-center justify-between pt-4 border-t border-slate-800">
          <div className="text-[11px] text-slate-500 font-mono flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>HYBRID RULES + PRESIDIO PII + LLM REASONER</span>
          </div>

          <button
            onClick={runAnalysis}
            disabled={loading}
            className={`px-6 py-2.5 rounded-lg text-xs font-bold font-mono tracking-wider flex items-center gap-2 transition-all shadow-lg ${
              loading
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                : 'bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 shadow-cyan-500/20'
            }`}
          >
            {loading ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                <span>INSPECTING EMAIL...</span>
              </>
            ) : (
              <>
                <ShieldAlert className="w-4 h-4" />
                <span>EXECUTE SECURITY SCAN</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default AnalyzeEmail;
