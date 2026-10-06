import React from "react";

const LABELS = {
  ingestion: "Ingestion",
  guard: "Guard",
  isolation: "Isolation",
  scoring: "Scoring",
  output_scan: "Output scan",
  confirmation: "Confirmation",
};

const STATUS_STYLE = {
  idle: { ring: "border-ink-600", stamp: null, track: "bg-ink-600" },
  skipped: { ring: "border-ink-600", stamp: null, track: "bg-ink-600" },
  pass: { ring: "border-brass", stamp: { text: "ADMIT", cls: "text-brass border-brass" }, track: "bg-brass" },
  hold: { ring: "border-hold", stamp: { text: "HOLD", cls: "text-hold-bright border-hold" }, track: "bg-hold" },
  deny: { ring: "border-alarm", stamp: { text: "DENY", cls: "text-alarm-bright border-alarm" }, track: "bg-alarm" },
};

function GateGlyph({ className }) {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" className={className}>
      <path d="M5 21V9a7 7 0 0 1 14 0v12" stroke="currentColor" strokeWidth="1.6" />
      <line x1="4" y1="21" x2="20" y2="21" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}

export default function CheckpointStrip({ stages }) {
  return (
    <div className="w-full overflow-x-auto pb-2">
      <div className="flex items-start min-w-[760px]">
        {stages.map((stage, i) => {
          const style = STATUS_STYLE[stage.status] || STATUS_STYLE.idle;
          const isLast = i === stages.length - 1;
          return (
            <React.Fragment key={stage.id}>
              <div className="flex flex-col items-center w-32 shrink-0">
                <div className="text-[11px] font-mono text-paper-dim mb-2">
                  {String(i + 1).padStart(2, "0")}
                </div>
                <div
                  className={`relative w-full h-24 border ${style.ring} bg-ink-800 flex flex-col items-center justify-center gap-1.5 transition-colors duration-300`}
                >
                  <GateGlyph className="text-paper-muted opacity-70" />
                  <span className="font-body text-[11px] text-paper-muted text-center px-2 leading-tight">
                    {LABELS[stage.id]}
                  </span>

                  {style.stamp && (
                    <div
                      className={`stamp-animate absolute -top-3 -right-2 px-1.5 py-0.5 border-2 rounded-sm text-[9px] tracking-wide font-mono font-medium bg-ink-900/95 -rotate-6 ${style.stamp.cls}`}
                    >
                      {style.stamp.text}
                    </div>
                  )}
                </div>
                <div className="mt-2 text-[10px] font-mono text-paper-dim text-center leading-snug px-1 h-9 overflow-hidden">
                  {stage.detail}
                </div>
              </div>
              {!isLast && (
                <div className="flex items-center w-6 shrink-0 mt-11">
                  <div
                    className={`h-[2px] w-full ${style.track} ${
                      stage.status === "idle" ? "pulse-track" : ""
                    }`}
                  />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

export function deriveStages(result) {
  const order = ["ingestion", "guard", "isolation", "scoring", "output_scan", "confirmation"];
  if (!result) {
    return order.map((id) => ({ id, status: "idle", detail: "awaiting document" }));
  }

  const logsByStage = {};
  for (const entry of result.logs) {
    (logsByStage[entry.stage] ??= []).push(entry);
  }
  const sev = { allow: 0, hold: 1, deny: 2 };
  const worst = (entries) =>
    entries && entries.length
      ? entries.reduce((a, b) => (sev[b.verdict] >= sev[a.verdict] ? b : a), entries[0])
      : null;

  return order.map((id) => {
    if (id === "ingestion") {
      return { id, status: "pass", detail: `parsed ${result.filename}` };
    }
    if (id === "isolation") {
      const w = worst(logsByStage.isolation);
      return { id, status: w ? "pass" : "skipped", detail: w ? w.detail : "not reached" };
    }
    if (id === "scoring") {
      const w = worst(logsByStage.scoring); // only present on the HOLD/review path
      if (w) return { id, status: w.verdict, detail: w.detail };
      if (result.candidate_score != null) {
        return { id, status: "pass", detail: `score ${result.candidate_score}` };
      }
      return { id, status: "skipped", detail: "not reached" };
    }
    const w = worst(logsByStage[id]);
    return { id, status: w ? w.verdict : "skipped", detail: w ? w.detail : "not reached" };
  });
}
