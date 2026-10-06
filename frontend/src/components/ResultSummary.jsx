import React from "react";

const VERDICT_STYLE = {
  allow: "text-brass",
  hold: "text-hold-bright",
  deny: "text-alarm-bright",
};

export default function ResultSummary({ result }) {
  if (!result) {
    return (
      <div className="border border-ink-600 bg-ink-800 p-4 text-xs font-mono text-paper-dim">
        no run yet — submit a document to see a verdict
      </div>
    );
  }

  return (
    <div className="border border-ink-600 bg-ink-800">
      <div className="border-b border-ink-600 px-4 py-2.5">
        <h2 className="font-display text-sm text-paper tracking-tight">Result</h2>
      </div>
      <div className="p-4 grid grid-cols-2 gap-3 text-sm">
        <div>
          <div className="text-[11px] font-mono text-paper-dim">final verdict</div>
          <div className={`font-display text-lg ${VERDICT_STYLE[result.final_verdict] || "text-paper"}`}>
            {result.final_verdict.toUpperCase()}
          </div>
        </div>
        <div>
          <div className="text-[11px] font-mono text-paper-dim">candidate score</div>
          <div className="font-display text-lg text-paper">
            {result.candidate_score != null ? result.candidate_score.toFixed(2) : "—"}
          </div>
        </div>
        <div>
          <div className="text-[11px] font-mono text-paper-dim">blocked at</div>
          <div className="font-mono text-xs text-paper mt-1">{result.blocked_at_stage || "—"}</div>
        </div>
        <div>
          <div className="text-[11px] font-mono text-paper-dim">tools called</div>
          <div className="font-mono text-xs text-paper mt-1">
            {result.tool_calls_allowed.length ? result.tool_calls_allowed.join(", ") : "none"}
          </div>
        </div>
        {result.tool_calls_blocked.length > 0 && (
          <div className="col-span-2">
            <div className="text-[11px] font-mono text-paper-dim">tools blocked</div>
            <div className="font-mono text-xs text-alarm-bright mt-1">
              {result.tool_calls_blocked.join(", ")}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
