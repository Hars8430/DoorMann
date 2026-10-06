const API_BASE = import.meta.env.VITE_API_BASE || "";

async function handle(res) {
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(text || `request failed: ${res.status}`);
  }
  return res.json();
}

export async function analyzeResume(file, mode, candidateEmail) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("mode", mode);
  formData.append("candidate_email", candidateEmail);
  const res = await fetch(`${API_BASE}/api/analyze`, { method: "POST", body: formData });
  return handle(res);
}

export async function confirmAction(runId, index) {
  const formData = new FormData();
  formData.append("index", String(index));
  const res = await fetch(`${API_BASE}/api/runs/${runId}/confirm`, { method: "POST", body: formData });
  return handle(res);
}

export async function rejectAction(runId, index) {
  const formData = new FormData();
  formData.append("index", String(index));
  const res = await fetch(`${API_BASE}/api/runs/${runId}/reject`, { method: "POST", body: formData });
  return handle(res);
}

export async function getEvalReport() {
  const res = await fetch(`${API_BASE}/api/eval-report`);
  return handle(res);
}
