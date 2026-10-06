import React, { useState } from "react";
import { confirmAction, rejectAction } from "../api";

export default function PendingActions({ runId, actions, onChange }) {
  const [busyIndex, setBusyIndex] = useState(null);

  async function act(fn, index) {
    setBusyIndex(index);
    try {
      await fn(runId, index);
      onChange(actions.filter((_, i) => i !== index));
    } finally {
      setBusyIndex(null);
    }
  }

  if (!actions || actions.length === 0) return null;

  return (
    <div className="border border-hold bg-hold/5">
      <div className="border-b border-hold/40 px-4 py-2.5">
        <h2 className="font-display text-sm text-paper tracking-tight">
          Pending confirmation <span className="text-hold-bright">· {actions.length} irreversible action(s)</span>
        </h2>
      </div>
      <div className="divide-y divide-ink-700">
        {actions.map((call, i) => (
          <div key={i} className="px-4 py-3 flex items-start justify-between gap-3">
            <div className="text-xs">
              <div className="font-mono text-paper">{call.tool_name}</div>
              <div className="font-mono text-[10px] text-paper-dim mt-1 max-w-md break-words">
                {JSON.stringify(call.arguments)}
              </div>
            </div>
            <div className="flex gap-2 shrink-0">
              <button
                disabled={busyIndex === i}
                onClick={() => act(confirmAction, i)}
                className="border border-brass text-brass text-[11px] font-mono px-2.5 py-1 hover:bg-brass hover:text-ink-950 transition-colors disabled:opacity-40"
              >
                confirm
              </button>
              <button
                disabled={busyIndex === i}
                onClick={() => act(rejectAction, i)}
                className="border border-alarm text-alarm-bright text-[11px] font-mono px-2.5 py-1 hover:bg-alarm hover:text-ink-950 transition-colors disabled:opacity-40"
              >
                reject
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
