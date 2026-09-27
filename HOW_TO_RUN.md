# How to Run Doorman

## Prerequisites

- **Python 3.11+** (3.13 recommended — tested with Python 3.13.7)
- **Ollama** installed and running (`ollama serve` in background, model `llama3.1` pulled)
- **Git** (optional, for version control)

## Step 1: Clone / navigate to the project

```bash
cd /path/to/doorman
```

## Step 2: Install dependencies

Use Python 3.13 to avoid the Windows Store python3 stub mismatch:

```bash
# If you have the python3.13 executable at a known path:
"/c/Users/harsh/AppData/Local/Programs/Python/Python313/python" -m pip install -r requirements.txt

# Or if python3.13 is on your PATH:
python3.13 -m pip install -r requirements.txt
```

Key dependencies:
- `PyMuPDF` (fitz) — PDF parsing with low-level font/color/coordinate API
- `langgraph` — pipeline orchestration
- `transformers` + `torch` — HuggingFace DeBERTa classifier
- `structlog` — structured JSON-lines logging
- `pyyaml` — config file parsing
- `openai` — OpenAI-compatible client (used to talk to Ollama)
- `jsonschema` — validation
- `pytest` — unit tests

**Note on PyMuPDF on Windows:** If `pip install PyMuPDF` fails with "Unable to find Visual Studio", the package may have installed as `fitz` (version 1.28.2) via a pre-built wheel. Verify with:
```bash
python -c "import fitz; print(fitz.__version__)"
```
If fitz is available, the ingestion node will use it. If not, it falls back to pdfplumber (which is installed as a dependency and doesn't need Visual Studio).

## Step 3: Verify Ollama is running

```bash
# Check that Ollama is running
curl http://localhost:11434/api/tags

# Should see something like:
# {"models":[{"name":"llama3.1","modified_at":"...","size":...}]}
```

If Ollama is not running:
```bash
# Start Ollama in the background
ollama serve &

# Pull the llama3.1 model (if not already pulled)
ollama pull llama3.1
```

## Step 4: Run the demo (smoke test)

This runs the full 7-stage pipeline on a benign synthetic resume and prints the result:

```bash
python src/main.py demo
```

Expected output:
- Pipeline runs through all 7 stages
- Classifies the resume (should be "allow" for a benign resume)
- Scores the candidate (should produce a structured score)
- Returns a verdict of "allowed" (no actions needed for a demo resume)
- Prints the score, classification, and pipeline summary

If the demo works, the pipeline is functional end-to-end.

## Step 5: Run the unit tests

```bash
python -m pytest tests/test_guardrails.py -v
```

This runs tests for:
- Heuristic guard patterns (R01-R06)
- Tool policy layer (structural allowlist enforcement)
- Scoring tools (structured output)
- Action tools (mock logging)
- HF guard (result structure)
- LLM judge (result structure)
- Integration smoke tests (heuristic + tool policy together)

All tests should pass before running the full eval.

## Step 6: Run the full evaluation harness

**Warning: this takes a long time.** 70 attacks x 2 modes (baseline + guarded) + 100 benign resumes = 240 pipeline runs, each calling Ollama. Budget several hours.

```bash
python src/main.py run-eval
```

This will:
1. Load the 70-attack corpus from `corpus/corpus.yaml`
2. Load the 100 benign resumes from `corpus/benign_resumes_p*.yaml`
3. Run each attack through the **baseline pipeline** (no guardrails — heuristic, HF, LLM judge all disabled; no context isolation framing)
4. Run each attack through the **guarded pipeline** (full 7-layer defense active)
5. Run each benign resume through the **guarded pipeline**
6. Compute metrics: ASR before vs. after, broken down by attack family; FPR on benign resumes
7. Write the full report to `output/results/eval_report.json`
8. Write structured JSON-lines logs to `output/logs/<attack_id>_<mode>/doorman.log`

**Configuration options:**
```bash
# Skip baseline (faster — just guardrails)
python src/main.py run-eval --no-baseline

# Skip guarded (just baseline for comparison)
python src/main.py run-eval --no-guarded

# Use a different Ollama model
python src/main.py run-eval --ollama-model llama3.2

# Tune the HF classifier threshold
python src/main.py run-eval --hf-threshold 0.7

# Use custom corpus/benign file paths
python src/main.py run-eval --corpus my_attacks.yaml --benign my_benign.yaml
```

## Step 7: Read the results

### Eval report (summary metrics)

```bash
cat output/results/eval_report.json | python -m json.tool
```

The report contains:
- `baseline`: total, blocked, asr (attack success rate = 1 - block rate)
- `guarded`: total, blocked, asr
- `baseline_asr_by_family` / `guarded_asr_by_family`: per-family breakdown
- `benign`: total, blocked, fpr (false positive rate)
- `attacks_by_family`: per-attack detail (verdict, rule ID, latency, logs)
- `benign_results`: per-resume detail
- `summary`: human-readable one-line summary

### Sample log lines (block traceable to rule IDs)

```bash
# Find all blocked decisions across all log files
grep '"verdict": "blocked"' output/logs/*/doorman.log | head -30

# Find blocks by specific rule
grep '"rule_id": "R01"' output/logs/*/doorman.log | head -10
grep '"rule_id": "R_HF01"' output/logs/*/doorman.log | head -10
grep '"rule_id": "R_LLM01"' output/logs/*/doorman.log | head -10

# List all log directories
ls output/logs/
```

Each log line is a self-contained JSON object:
```json
{
  "timestamp": "2024-...",
  "level": "info",
  "logger": "doorman.nodes.classify",
  "message": "guardrail_decision",
  "stage": "classify",
  "rule_id": "R01",
  "input_hash": "a1b2c3d4e5f6g7h8",
  "action_attempted": null,
  "verdict": "blocked",
  "detail": "Heuristic rule R01 (ignore_previous) matched: 'ignore previous instructions...' (confidence 0.60)",
  "signals": {"heuristic": {"verdict": "block"}}
}
```

### Per-family ASR table

From the eval report, extract the per-family breakdown:
```python
import json
with open('output/results/eval_report.json') as f:
    report = json.load(f)

print(f"{'Family':<35} {'Total':>6} {'Baseline ASR':>12} {'Guarded ASR':>12}")
print("-" * 70)
for fam in report['guarded_asr_by_family']:
    b = report['baseline_asr_by_family'][fam]['asr']
    g = report['guarded_asr_by_family'][fam]['asr']
    t = report['guarded_asr_by_family'][fam]['total']
    print(f"{fam:<35} {t:>6} {b*100:>11.1f}% {g*100:>11.1f}%")
```

## Step 8: Review the bypass (if you find one)

The plan calls for finding one real bypass in your finished system, documenting it, patching it, and re-testing. The process:

1. **Run the full eval** and look at which attacks succeeded against the guarded pipeline.
2. **Pick one** that got through — ideally one that reveals a structural weakness, not just "the heuristic didn't catch this phrasing."
3. **Document it:**
   - What the attack was (which corpus entry, what family)
   - Why it worked (which defense layer failed to catch it, and why)
   - What you changed (new rule, new pattern, new structural constraint)
   - The re-test proving it's closed (re-run that specific attack, show it's now blocked)
4. **Add it to your writeup.** This is the thing that makes an interviewer trust you did the work.

## Troubleshooting

### Ollama not reachable
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If connection refused, start Ollama
ollama serve

# Check that llama3.1 is available
ollama list
```

### HF classifier fails to load
The HF guard degrades gracefully — if the model can't load (no transformers, no download, out of memory), it returns "unknown" and the ensemble falls back to heuristic + LLM-judge signals. You'll see this in the logs:
```
HFGuard: failed to load model: ...
HFGuard: classification error: ...
```
The eval will still run, just with fewer signals in the ensemble.

### Pipeline times out on Ollama calls
If Ollama is slow or overloaded, pipeline runs may time out. The scoring node has a 60-second timeout; the LLM judge has a 30-second timeout. If these are too short for your hardware, increase them in `config/settings.yaml`:
```yaml
pipeline:
  timeout_s: 120  # scoring node timeout
```

### False positives on benign resumes
If the FPR is higher than expected (e.g., >5%), review which benign resumes are being blocked and why. Common causes:
- The heuristic is too aggressive on certain patterns
- The HF classifier threshold is too low
- The LLM judge is over-flagging

Tune the thresholds in `config/settings.yaml` and re-run:
```bash
python src/main.py run-eval --no-baseline --hf-threshold 0.7
```

### PDF ingestion fails
If PyMuPDF is not available, the ingest node falls back to pdfplumber (basic text extraction, no hidden text detection). Check the logs:
```bash
grep "ingest" output/logs/*/doorman.log | head -10
```
If you see "pymupdf: hidden text detection not available", install PyMuPDF properly or use a pre-built wheel.

## Expected workflow for the interview

1. **Run the demo first** — shows the pipeline works end-to-end
2. **Show the eval report** — walk through the ASR before/after and per-family table
3. **Show sample blocked log lines** — proves every block is traceable to a rule ID
4. **Walk through the attack corpus** — explain the 6 families and why each matters
5. **Talk through one attack in detail** — pick a representative attack from each family and explain how the defenses catch it (or don't)
6. **Discuss the bypass** — if you found one, walk through the discovery, fix, and re-test
7. **Explain the structural vs. persuasive distinction** — this is the key insight

## Project structure reminder

```
doorman/
├── config/settings.yaml          # all tunable params
├── corpus/
│   ├── corpus.yaml               # 70 attacks metadata
│   ├── corpus_p1.yaml through corpus_p3.yaml   # attack family metadata (split)
│   ├── benign_p2.yaml through benign_p7.yaml   # 100 benign resumes (split)
│   └── benign_resumes.yaml       # benign resumes metadata
├── corpus_payloads/
│   ├── A01-A15.txt through A61-A70.txt   # raw attack payloads
├── src/
│   ├── main.py                   # entry point
│   ├── pipeline.py               # LangGraph graph
│   ├── pipeline_state.py         # shared state
│   ├── config/loader.py          # config loader
│   ├── nodes/                    # 6 pipeline nodes
│   ├── tools/                    # scoring + action tools (mock)
│   ├── guards/                   # heuristic + HF + LLM-judge guards
│   ├── eval/run_eval.py          # evaluation harness
│   └── test_resume.py           # smoke test resume
├── tests/test_guardrails.py      # unit tests
├── output/                       # eval output (logs + results)
├── requirements.txt
├── README.md
└── HOW_TO_RUN.md                 # this file
```
