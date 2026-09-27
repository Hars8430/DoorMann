import React, { useState } from "react";
import CheckpointStrip, { deriveStages } from "./components/CheckpointStrip.jsx";
import UploadPanel from "./components/UploadPanel.jsx";
import ResultSummary from "./components/ResultSummary.jsx";
import DecisionLedger from "./components/DecisionLedger.jsx";
import PendingActions from "./components/PendingActions.jsx";
import FieldReport from "./components/FieldReport.jsx";

export default function App() {
  const [tab, setTab] = useState("checkpoint");
  const [result, setResult] = useState(null);
  const [pending, setPending] = useState([]);
  const [running, setRunning] = useState(false);

  function handleResult(r) {
    setResult(r);
    setPending(r.pending_actions || []);
    setRunning(false);
  }

  const stages = deriveStages(running ? null : result);

  return (
    <div className="min-h-screen font-body">
      <header className="border-b border-ink-600">
        <div className="max-w-6xl mx-auto px-6 py-5 flex items-end justify-between">
          <div>
            <h1 className="font-display text-2xl text-paper tracking-tight">Doorman</h1>
            <p className="text-xs font-mono text-paper-dim mt-0.5">
              layered defense for a recruiting agent that reads hostile documents
            </p>
          </div>
          <nav className="flex border border-ink-600 text-xs font-mono">
            <button
              onClick={() => setTab("checkpoint")}
              className={`px-3.5 py-1.5 transition-colors ${
                tab === "checkpoint" ? "bg-paper text-ink-950" : "text-paper-muted hover:text-paper"
              }`}
            >
              checkpoint
            </button>
            <button
              onClick={() => setTab("report")}
              className={`px-3.5 py-1.5 border-l border-ink-600 transition-colors ${
                tab === "report" ? "bg-paper text-ink-950" : "text-paper-muted hover:text-paper"
              }`}
            >
              field report
            </button>
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        {tab === "checkpoint" ? (
          <>
            <section>
              <CheckpointStrip stages={stages} />
            </section>

            <section className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-4">
              <div className="space-y-4">
                <UploadPanel onStart={() => setRunning(true)} onResult={handleResult} />
                <ResultSummary result={result} />
              </div>
              <div className="space-y-4">
                {pending.length > 0 && (
                  <PendingActions runId={result?.run_id} actions={pending} onChange={setPending} />
                )}
                <DecisionLedger logs={result?.logs || []} />
              </div>
            </section>
          </>
        ) : (
          <FieldReport />
        )}
      </main>

      <footer className="max-w-6xl mx-auto px-6 py-8 text-[11px] font-mono text-paper-dim border-t border-ink-700 mt-4">
        every block is traceable to a rule in the decision ledger · prompting is a hint, tool scoping is the control
      </footer>
    </div>
  );
}
