import React from "react";

const DOT = {
  allow: "bg-brass",
  hold: "bg-hold",
  deny: "bg-alarm",
};

export default function DecisionLedger({ logs }) {
  return (
    <div className="border border-ink-600 bg-ink-800">
      <div className="border-b border-ink-600 px-4 py-2.5 flex items-center justify-between">
        <h2 className="font-display text-sm text-paper tracking-tight">Decision ledger</h2>
        <span className="text-[11px] font-mono text-paper-dim">{logs.length} entries</span>
      </div>
      {logs.length === 0 ? (
        <div className="p-4 text-xs font-mono text-paper-dim">no entries yet</div>
      ) : (
        <div className="divide-y divide-ink-700 max-h-[420px] overflow-y-auto">
          {logs.map((entry, i) => (
            <div key={i} className="px-4 py-2.5 grid grid-cols-[auto_88px_1fr] gap-3 items-start text-xs">
              <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${DOT[entry.verdict] || "bg-ink-500"}`} />
              <span className="font-mono text-paper-muted uppercase tracking-tight pt-0.5">
                {entry.stage.replace("_", " ")}
              </span>
              <div>
                <p className="text-paper leading-snug">{entry.detail}</p>
                <p className="mt-0.5 font-mono text-[10px] text-paper-dim">
                  {entry.rule_id ? entry.rule_id : "no rule fired"} · hash {entry.input_hash}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
