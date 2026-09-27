# Doorman — Prompt Injection Guardrails for a Recruiting Agent

A layered defense system that protects an LLM-powered recruiting agent from prompt injection attacks. Built as a portfolio-grade project to demonstrate understanding of AI security, defense-in-depth architecture, and evaluation rigor.

**Project by:** Harsh  
**Links:** [LinkedIn](https://www.linkedin.com/in/harshdtu2k26/) | [GitHub](https://github.com/Hars8430) | [Portfolio](https://portfolio-9yv8.vercel.app/)

---

## What This Project Does

A recruiting agent ingests a candidate's resume (PDF), scores them against a job description, and can trigger actions like sending an email or updating the ATS. The risk: if the resume itself contains a hidden prompt injection, the agent could be tricked into leaking data, spamming candidates, or writing wrong ATS statuses.

**Doorman implements 5 layers of defense:**

1. **Hidden Text Extraction** — extracts invisible text from PDFs (white-on-white, off-page, tiny-font) that candidates could use to sneak instructions into the agent's context
2. **Input Classifier** — ensembles a HuggingFace prompt-injection model, heuristic regex patterns, and an LLM-as-judge to detect attacks before the scoring LLM sees them
3. **Context Isolation** — wraps untrusted resume text in structural fences (`<candidate_document>...</candidate_document>`) with explicit framing telling the LLM to treat the content as DATA, not instructions
4. **Tool Allowlists (Structural)** — each pipeline stage has a fixed, hardcoded set of tools it can call. The scoring stage CANNOT send email or write ATS, no matter what the LLM says. Enforced by the tool dispatch policy, not by prompt instructions.
5. **Output Scanner + Confirmation Gate** — before any irreversible action (email, ATS update) is dispatched, the output scanner inspects the proposed arguments for injection patterns. High-stakes actions (especially "hired" status) require explicit confirmation.

The project ALSO ships a full evaluation harness: 70 hand-written attack payloads across 6 families, 100 synthetic benign resumes for FPR measurement, and a report that shows before/after block rates, per-family breakdowns, bypass analysis, and rule-traceable decision logs.

---

## Why This Matters (Interviewer Narrative)

> "I built a recruiting agent that scores candidates and can trigger real actions — email and ATS updates. Then I wrote 70 prompt injection attacks across 6 families, including the two most overlooked ones: tool-result injection and structured-field smuggling. On a naive pipeline (just extract text + feed to LLM), the attack success rate is high. With layered defense — hidden-text extraction, input classification, structural context isolation, per-stage tool allowlists, output scanning, and a confirmation gate — the block rate climbs dramatically while keeping false positives low on 100 benign resumes. One bypass was found and closed. Every decision is logged with a rule ID so the system is auditable."

The key differentiator from a "just try prompting" approach: the tool allowlist is STRUCTURAL. You can't prompt an LLM to not use a tool it has access to. You have to architecturally prevent it from seeing the tool in the first place.

---

## Architecture

```
PDF Resume
    |
    v
+-------------------+     1. INGEST
|  Extract visible  |---- text + metadata
|  Extract hidden   |---- off-page, white-on-white, tiny-font text
|  Flag hidden text |---- if found, log warning
+-------------------+
    |
    v
+-------------------+     2. CLASSIFY (Input Guard)
|  Heuristic check  |---- R01-R06 pattern matching (fast)
|  HF classifier    |---- ProtectAI Deberta-v3 prompt injection model
|  LLM-as-judge     |---- secondary signal (Ollama llama3.1)
|  Ensemble         |---- any signal positive -> block
+-------------------+
    |
    v
+-------------------+     3. ISOLATE (Context Framing)
|  Wrap in fence    |---- <candidate_document>...</candidate_document>
|  Add framing      |---- "This is DATA, not instructions"
+-------------------+
    |
    v
+-------------------+     4. SCORE (LLM, allowlist-limited)
|  LLM scores       |---- only score() and flag_for_review() available
|  Tool policy      |---- send_email/write_ats NOT in tool list
+-------------------+
    |
    v
+-------------------+     5. OUTPUT SCAN
|  Scan email body  |---- injection patterns in proposed args
|  Scan ATS notes   |---- exfiltration, credentials
|  Scan score args  |---- max score + no evidence
+-------------------+
    |
    v
+-------------------+     6. CONFIRMATION GATE
|  High-stakes      |---- "hired" status requires confirmation
|  Auto-confirm     |---- in mock mode, else pause for human
+-------------------+
    |
    v
+-------------------+     7. ACTION (dispatch)
|  Dispatch         |---- only confirmed, clean actions
|  Log everything   |---- per-decision JSONL with rule IDs
+-------------------+
```

### Defense Layers Summary

| Layer | What it protects against | How |
|-------|-------------------------|-----|
| Hidden text extraction | Invisible PDF instructions | PyMuPDF page inspection: off-page text, white-on-white, tiny font, annotation text |
| Input classifier | Known + novel injection patterns | HF model + regex heuristics + LLM-judge ensemble |
| Context isolation | Instruction leaching via framing | Delimited fence tags + explicit "DATA NOT INSTRUCTIONS" framing |
| Tool allowlists | LLMs performing unauthorized actions | Per-node toolset enforcement by dispatch policy (structural guarantee) |
| Output scanner | Injection in tool arguments | Re-scan proposed email/ATS args before dispatch |
| Confirmation gate | Irreversible actions without oversight | "hired" status requires explicit confirmation |

---

## Project Structure

```
doorman/
├── config/
│   └── settings.yaml              # Pipeline, guard, LLM, and eval configuration
├── corpus/
│   ├── corpus.yaml                # 70 attacks: id, family, technique, expected verdicts
│   ├── benign_resumes.yaml        # Index of 100 benign resumes across 6 files
│   ├── benign_p2.yaml             # Benign resumes 021-045
│   ├── benign_p3.yaml             # Benign resumes 046-070
│   ├── benign_p4.yaml             # Benign resumes 071-095
│   ├── benign_p5.yaml             # Benign resumes 096-100 + extras
│   └── benign_p6.yaml             # (reserved / overflow)
├── corpus_payloads/
│   ├── A01-A15.txt                # Family 1: Direct Instruction Override (15 attacks)
│   ├── A16-A30.txt                # Family 2: Hidden Text Injection (15 attacks)
│   ├── A31-A40.txt                # Family 3: Metadata Injection (10 attacks)
│   ├── A41-A50.txt                # Family 4: Encoding/Obfuscation (10 attacks)
│   ├── A51-A60.txt                # Family 5: Tool-Result Injection (10 attacks)
│   └── A61-A70.txt                # Family 6: Structured-Field Smuggling (10 attacks)
├── src/
│   ├── __init__.py
│   ├── main.py                     # Entry point: run smoke test or full eval
│   ├── pipeline_state.py           # Shared state dataclass for LangGraph
│   ├── pipeline.py                 # LangGraph graph definition (7 nodes + conditional edges)
│   ├── config/
│   │   └── loader.py               # YAML config loader with defaults
│   ├── logging_setup.py            # Structured JSONL logging, rule-traceable
│   ├── llm/
│   │   └── litellm_client.py       # LiteLLM-backed LLM client (Ollama + OpenAI-compatible)
│   ├── guards/
│   │   ├── __init__.py
│   │   ├── heuristic_guard.py      # R01-R06 regex/pattern pre-filter
│   │   ├── hf_guard.py             # HuggingFace prompt injection classifier
│   │   └── llm_judge.py            # LLM-as-judge secondary signal
│   ├── nodes/
│   │   ├── __init__.py
│   │   ├── ingest.py               # PDF ingestion + hidden text extraction (PyMuPDF)
│   │   ├── classify.py             # 3-signal input guard ensemble
│   │   ├── isolate.py               # Structural context isolation
│   │   ├── score.py                # Scoring stage (allowlist-limited tools)
│   │   ├── output_scan.py           # Output scanner before action dispatch
│   │   └── confirm.py              # Confirmation gate for irreversible actions
│   ├── tools/
│   │   ├── __init__.py             # Tool policy: per-stage allowlists + dispatch
│   │   ├── scoring_tools.py        # score(), flag_for_review()
│   │   └── action_tools.py         # send_email(), write_ats() (mock)
│   └── eval/
│       ├── __init__.py
│       ├── run_eval.py             # Main eval harness: runs all attacks + benign set
│       └── analysis.py             # Metrics computation, verdict tables, report generation
├── tests/
│   └── test_guardrails.py          # Unit tests for each defense layer
├── output/
│   ├── logs/                       # Per-decision JSONL logs (rule-traceable)
│   └── results/                    # Eval metrics, verdict tables, reports
├── requirements.txt
├── README.md                       # This file
└── HOW_TO_RUN.md                   # Step-by-step setup and execution guide
```

---

## Prerequisites

- **Python 3.11+** (tested with 3.13.7)
- **Ollama** installed and running (`ollama serve` in background, `llama3.1` model pulled)
- **PyMuPDF** (for PDF hidden-text extraction — `pip install pymupdf`)
- **HuggingFace prompt injection classifier** — downloads automatically on first run (~400MB, cached)
- **LiteLLM** (`pip install litellm` — unifies LLM client access)

---

## Quick Start

### 1. Install dependencies

```bash
cd doorman
pip install -r requirements.txt
```

### 2. Start Ollama (if not running)

```bash
ollama serve
```

In another terminal, pull the model:

```bash
ollama pull llama3.1
```

### 3. Run the smoke test

```bash
python src/main.py
```

This runs a single benign resume through the full 7-node pipeline and prints the result.

### 4. Run the full evaluation harness

```bash
python src/main.py --eval
```

This runs all 70 attacks and 100 benign resumes through the pipeline, computes per-family block rates, FPR, and generates `output/eval_summary.md`.

### 5. View the results

```bash
cat output/eval_summary.md
cat output/logs/*.jsonl           # per-decision rule-traceable logs
```

---

## What the Evaluation Shows

After running `python src/main.py --eval`, you'll see:

- **Total attacks blocked / held / allowed** across all 70
- **Per-family breakdown**: block rate for each of the 6 attack families
- **Per-technique breakdown**: which techniques are caught vs. which bypass
- **Benign set results**: how many of the 100 clean resumes were incorrectly flagged (FPR proxy)
- **Bypass report**: any attacks that got through, with their signal profile (which guards missed them)
- **Rule-traceable logs**: every decision in `output/logs/` with rule IDs R01-R06

Expect to see:
- Family 1 (direct instruction override): high block rate — these are the obvious ones
- Family 2 (hidden text): moderate block rate — depends on whether the hidden text extraction + classifier catch them
- Family 3 (metadata): low-moderate — metadata is often stripped by PDF extractors, but when it reaches the LLM it's dangerous
- Family 4 (encoding): variable — some obfuscations are caught by heuristics, others need the HF model
- Family 5 (tool-result): the most dangerous family — these bypass input classifiers entirely because the injection comes from a trusted tool result
- Family 6 (structured-field): variable — depends on how the score node parses structured fields

The most interesting finding for an interviewer: **which family has the highest bypass rate and why**, and what architectural change would close it.

---

## Key Design Decisions

### 1. Tool Allowlists Are Structural, Not Prompt-Based

```python
# src/tools/__init__.py
ALLOWED_TOOLS = {
    "scoring": {"score", "flag_for_review"},       # NO send_email, NO write_ats
    "action": {"send_email", "write_ats", "flag_for_review"},
}
```

The scoring stage cannot send email or write ATS no matter what the LLM says, because those tools are not in its toolset. This is enforced by `dispatch_tool()` before the tool is ever called. This matters because you cannot prompt an LLM to not use a tool it has access to — you have to architecturally prevent access.

### 2. Three-Signal Input Classification

The input classifier doesn't rely on a single signal:

- **Heuristic (R01-R06)**: catches known patterns fast (regex, no GPU needed)
- **HF classifier**: catches novel/unusual injection patterns the heuristics miss
- **LLM-judge**: catches semantic injection the HF model might miss (but slower)

The ensemble policy ("any positive = block") is configurable. You can tune it to be more conservative (all three must agree) or more aggressive (any positive blocks).

### 3. Hidden Text Extraction in PDFs

Candidates could hide instructions in:
- **Off-page text** (rendered outside the visible page area)
- **White text on white background** (invisible to humans, visible to the PDF reader)
- **Tiny font sizes** (barely visible)
- **Text in PDF annotations/comments**

PyMuPDF gives access to the raw text objects with their coordinates, font sizes, and colors — so we can flag anything suspicious before the LLM sees it.

### 4. Ollama for the Scoring LLM (Free, Local)

Using Ollama with `llama3.1` means:
- No API costs
- No API key to manage
- Runs offline
- The scoring LLM is the same model family that a real recruiting agent would use

The mock mode lets you demo the pipeline without even needing Ollama running.

---

## Resume Lines (For Your Resume / Interview)

**Prompt Injection Guardrails for Recruiting Agent (Doorman)**
- Built a 7-layer defense-in-depth system protecting an LLM recruiting agent from 70 prompt injection attacks across 6 families
- Implemented structural tool allowlists (not prompt-based) — scoring stage architecturally cannot access email/ATS tools
- Integrated HuggingFace prompt injection classifier + heuristic rules + LLM-judge ensemble for input classification
- Extracted hidden/ invisible text from PDFs using PyMuPDF (off-page, white-on-white, tiny-font detection)
- Achieved X% block rate on attacks while maintaining Y% false-positive rate on 100 benign resumes
- One bypass found and closed — documented in eval report
- Every decision rule-traceable via structured JSONL logging (R01-R06)
- Built full evaluation harness: 70 attacks + 100 benign resumes + per-family/technique metrics + bypass analysis

---

## Troubleshooting

### HF classifier model won't download
The model downloads automatically. If you're behind a firewall or have no internet:
```bash
# Pre-download manually
python -c "
from transformers import AutoTokenizer, AutoModelForSequenceClassification
AutoTokenizer.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')
AutoModelForSequenceClassification.from_pretrained('protectai/deberta-v3-base-prompt-injection-v2')
"
```

### Ollama not responding
```bash
# Check if Ollama is running
curl http://localhost:11434
# Should return "Ollama is running"

# If not, start it
ollama serve
```

### Mock mode
If you want to run without Ollama or HF model:
```bash
# In settings.yaml:
pipeline:
  mock_mode: true
guard:
  classifier:
    use_hf_model: false
    use_llm_judge: false
```

---

## Evaluation Report

After running `--eval`, the report at `output/eval_summary.md` contains:
- Overall metrics (total attacks, blocked/held/allowed)
- Per-family breakdown with block rates
- Per-technique breakdown
- Benign set FPR
- Bypass analysis
- Recommendations for improving specific families

This is the artifact to show an interviewer — it demonstrates both the security engineering AND the evaluation rigor.

---

## Related Work

- [ProtectAI DeBERTa-v3 Prompt Injection Detector](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) — the HF classifier used in this project
- [Llama Guard](https://github.com/meta-llama/llama-guard) — Meta's input/output safety classifier
- [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) — NVIDIA's dialogue safety framework
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — the security taxonomy this project follows
