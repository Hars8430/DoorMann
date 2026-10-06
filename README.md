# Doorman

Layered defense against prompt injection for a simulated recruiting agent —
an LLM agent that reads candidate-submitted resumes and portfolio PDFs,
scores them, emails candidates, and writes status to an ATS. Every document
it reads was written by someone with a direct incentive to manipulate the
outcome. This project assumes that, builds the pipeline anyway, and proves
the defense with numbers instead of a demo.

```
Overall attack success rate:  82% (no guardrails)  →  0% (guarded)
False positive rate on 100 benign resumes:  0%
```

Full numbers, broken down by attack family, are in [`eval/report.json`](eval/report.json)
and rendered in the dashboard's **field report** tab.

## Why this exists

Filtering the phrase "ignore previous instructions" is theater. The real
control is limiting what the agent is allowed to *do* once it's fooled — a
system prompt that politely asks the model not to fall for tricks is not a
security boundary, it's a suggestion. Doorman is built to demonstrate the
difference: a naive pipeline (`run_naive`) with no isolation and no tool
scoping sits right next to a guarded one (`run_guarded`) with six layers of
defense, and the eval harness runs the identical 60-attack corpus through
both so the gap is measurable, not asserted.

## Architecture

```
PDF → Ingestion → Guard → Isolation → Scoring → Output Scan → Confirmation
```

1. **Ingestion** (`backend/ingestion.py`) — parses the PDF at the span level
   (PyMuPDF), not just `get_text()`. Flags white-on-white text (by sampling
   the page's actual filled regions, so a name printed white on a navy
   header band is *not* mistaken for camouflage), sub-1.5pt font, off-page
   coordinates, zero-width Unicode splicing, suspicious PDF metadata
   fields, and linked URLs — the actual attack surface.
2. **Guard** (`backend/guard.py`) — a rule-based classifier that scores the
   document for injection likelihood. Every hit is a named, independently
   auditable rule (`INJ-001` … `INJ-011`), and hits are severity-weighted:
   a hidden payload or an override phrase is decisive, while a lone
   natural-language phrasing is merely recorded. Swappable for a
   HuggingFace prompt-injection model (`HFModelGuard`) or an ensemble of
   both.
3. **Isolation** — structural, not promptual. By the time content reaches
   the scorer, hidden spans are already gone; what remains is passed as
   fenced data, never as instructions.
4. **Scoring** (`backend/scorer.py`) — the allowlisted stage. It can only
   ever call `score()` / `flag_for_review()` — see `backend/policy.py`.
5. **Output scan** (`backend/scanner.py`) — inspects the *proposed tool
   call* before dispatch: an unsupported maxed score, a scope-escape
   attempt, an unauthorized offer in an email body.
6. **Confirmation** (`backend/confirmation.py`) — `send_email` and
   `write_ats` are one-way doors. They're queued, not executed, until
   something with actual authority approves them.

The core design bet: **tool scoping is the control, the system prompt is
just a hint.** The scoring stage is structurally incapable of calling
`send_email`, regardless of what the document tried to talk it into.

## Repo layout

```
backend/     pipeline, guard, policy, scanner, ingestion, scorer, tools, API
corpus/      generates 60 attacks (6 families × 10) + 100 benign resumes as real PDFs
eval/        run_eval.py (the ship-gate numbers) + bypass_case_study.py
frontend/    Vite + React + Tailwind dashboard ("Checkpoint")
```

## Running it

```bash
# backend
pip install -r requirements.txt
python corpus/generate_corpus.py     # writes corpus/attacks/*, corpus/benign/*
python eval/run_eval.py              # writes eval/report.json
uvicorn backend.main:app --reload --port 8000

# frontend (separate terminal)
cd frontend
npm install
npm run dev                          # proxies /api to localhost:8000
```

Everything above runs with **zero API keys** — the default guard is a
rule-based classifier and the default scorer is a deterministic
keyword-matcher, specifically so the whole thing is clonable and runnable
in one sitting. Two optional, opt-in production backends are stubbed and
documented in `backend/guard.py` (`HFModelGuard`) and `backend/scorer.py`
(`ClaudeScorer`) if you want to swap in a real model.

## Ship gate

| Metric | Result |
|---|---|
| Attack success rate, before guardrails | 82% (49/60) |
| Attack success rate, after guardrails | 0% (0/60) |
| False positive rate, 100 benign resumes | 0% (0/100) — the benign set is realistic, see below |
| Documented bypass found & closed | Homoglyph evasion of the phrase-matching rules — [`eval/bypass_case_study.py`](eval/bypass_case_study.py) |
| Every block traceable to a rule | Yes — every `LogEntry` carries a `rule_id`; see the decision ledger in the dashboard |

The benign set is deliberately not 100 copies of flat black-on-white text.
It cycles through formatting real candidates ship — template header bands
with the name in white on navy, conversational prose ("perfect fit",
"feel free to send an email to me", "act as the liaison"), portfolio links
including a long letters-only personal domain, Word-written metadata, a
résumé in Cyrillic, a Cyrillic name on an English résumé, and résumés that
match every job keyword. Those last two categories are what exposed the
false positives below; a flat corpus scored 0% on all of them.

By-family breakdown (before → after):

| Family | Before | After |
|---|---|---|
| direct_override | 90% | 0% |
| hidden_text | 70% | 0% |
| metadata_injection | 90% | 0% |
| encoding_obfuscation | 100% | 0% |
| tool_result_injection | 100% | 0% |
| structured_field_smuggling | 40% | 0% |

## False positives that were found and fixed

Real uploads flagged as suspicious were root-caused rather than papered
over. Each of these denied or held a perfectly genuine resume:

1. **A perfect keyword match was denied.** `OUT-001-UNSUPPORTED-MAX-SCORE`
   fired on `value >= 0.98`, so the *most* relevant resume in the pile —
   one containing every job keyword — was the one blocked. The scorer now
   reports `evidence_backed`, and the scanner denies a maxed score only
   when nothing outside the document supports it (or when `coerced` is set).
   An evidence-backed 1.0 is still logged under OUT-001, so the decision
   stays traceable to the rule that evaluated it.
2. **White-on-navy counted as hidden text.** Ingestion assumed a white page
   background, so any template that prints the candidate's name in white on
   a dark band was classified as white-on-white camouflage → `INJ-002` →
   held. It now samples the page's actual filled regions; light ink is only
   hidden when nothing dark sits behind it.
3. **Ordinary prose read as an attack.** "Perfect fit" hit the
   score-manipulation rule, "send an email to me" hit tool-naming, and bare
   "act as" hit persona-hijack. The patterns were tightened to what an
   instruction actually looks like, and remaining natural-language rules
   were down-weighted so one weak phrasing is recorded without holding the
   document.
4. **Non-Latin resumes read as encoding attacks.** The homoglyph ratio
   counted every non-ASCII letter, so a résumé written in Greek or Cyrillic
   — or with a Cyrillic name — was flagged as obfuscation. It now requires
   an otherwise-Latin document with lookalike characters spliced *between*
   Latin letters.
5. **Long personal domains read as attacker infrastructure.** The suspicious
   URL rule matched any 16+ character run followed by a dot anywhere in the
   link, so `dataengineeringresume.example` matched. It now checks the host:
   raw IPs, known shorteners, and machine-generated labels (long, no
   hyphens, containing digits).

Regression tests for all five live in [`tests/test_pipeline.py`](tests/test_pipeline.py),
and the realistic benign set is produced by `corpus/generate_corpus.py` —
which also now picks a Unicode font on any OS instead of hardcoding a
Linux-only path.

## Known limitations (documented on purpose, not hidden)

- The suspicious-URL host heuristic treats a long machine-generated label
  (letters + digits, no hyphens) as attacker infrastructure; a letters-only
  long label is assumed to be a personal domain. Deliberate tradeoff in the
  other direction — noted in `_suspicious_url`.
- Ingestion samples vector fills for the page background, not text drawn
  over images; white text over an image is still conservatively flagged.
- `NaiveScorer`'s "gullible model" is a deterministic stand-in (it reuses
  the guard's own rule hits to decide whether it would have complied)
  rather than a live LLM call, so the baseline is reproducible offline. See
  the comment in `backend/scorer.py` for the reasoning.
