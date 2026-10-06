import React, { useRef, useState } from "react";
import { analyzeResume } from "../api";

export default function UploadPanel({ onResult, onStart }) {
  const [mode, setMode] = useState("guarded");
  const [email, setEmail] = useState("candidate@example.com");
  const [fileName, setFileName] = useState("");
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const fileRef = useRef(null);
  const inputRef = useRef(null);

  function pick(file) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".pdf")) {
      setError("only PDF files are accepted");
      return;
    }
    fileRef.current = file;
    setFileName(file.name);
    setError("");
  }

  async function run() {
    if (!fileRef.current) {
      setError("choose a document first");
      return;
    }
    setLoading(true);
    setError("");
    onStart?.();
    try {
      const result = await analyzeResume(fileRef.current, mode, email);
      onResult(result);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="border border-ink-600 bg-ink-800">
      <div className="border-b border-ink-600 px-4 py-2.5 flex items-center justify-between">
        <h2 className="font-display text-sm text-paper tracking-tight">Submit a document</h2>
        <div className="flex border border-ink-600 text-[11px] font-mono">
          <button
            onClick={() => setMode("guarded")}
            className={`px-2.5 py-1 transition-colors ${
              mode === "guarded" ? "bg-brass text-ink-950" : "text-paper-muted hover:text-paper"
            }`}
          >
            guarded
          </button>
          <button
            onClick={() => setMode("naive")}
            className={`px-2.5 py-1 border-l border-ink-600 transition-colors ${
              mode === "naive" ? "bg-alarm text-ink-950" : "text-paper-muted hover:text-paper"
            }`}
          >
            naive
          </button>
        </div>
      </div>

      <div className="p-4 space-y-3">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            pick(e.dataTransfer.files?.[0]);
          }}
          onClick={() => inputRef.current?.click()}
          className={`cursor-pointer border border-dashed ${
            dragging ? "border-brass bg-brass/5" : "border-ink-500"
          } px-4 py-6 text-center transition-colors`}
        >
          <input
            ref={inputRef}
            type="file"
            accept="application/pdf"
            className="hidden"
            onChange={(e) => pick(e.target.files?.[0])}
          />
          <p className="font-mono text-xs text-paper-muted">
            {fileName || "drop a resume PDF here, or click to choose"}
          </p>
        </div>

        <label className="block">
          <span className="text-[11px] font-mono text-paper-dim">candidate email (for the mock send_email tool)</span>
          <input
            type="text"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full bg-ink-900 border border-ink-600 px-2.5 py-1.5 text-sm font-mono text-paper focus:outline-none focus:border-brass"
          />
        </label>

        {error && <p className="text-xs font-mono text-alarm-bright">{error}</p>}

        <button
          onClick={run}
          disabled={loading}
          className="w-full bg-brass hover:bg-brass-bright disabled:opacity-50 text-ink-950 font-body text-sm font-medium py-2 transition-colors"
        >
          {loading ? "Running through checkpoint…" : "Run through checkpoint"}
        </button>
        <p className="text-[11px] text-paper-dim leading-relaxed">
          <span className="text-brass">Guarded</span> runs the full six-stage defense.{" "}
          <span className="text-alarm-bright">Naive</span> runs the same document with no guardrails at all — the
          agent most people accidentally ship.
        </p>
      </div>
    </div>
  );
}
