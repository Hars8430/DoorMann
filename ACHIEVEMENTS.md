# Doorman — Achievements & Insights

Ship-gate numbers, what was built, what was broken, and everything worth
knowing about how the system behaves and why.

---

## 1. Achievements

### Headline numbers (from `eval/report.json`, regenerated on the final code)

| Metric | Result |
|---|---|
| Attack success rate, no guardrails | **82%** (49/60 attacks compromised the naive pipeline) |
| Attack success rate, guarded | **0%** (0/60) |
| False positives, 100 realistic benign resumes | **0/100** |
| Documented bypass found and closed | Homoglyph evasion — `eval/bypass_case_study.py` (before: MISSED → after: CAUGHT) |
| Every block traceable to a rule ID | Yes — enforced by `test_every_block_has_a_rule_id` |
| Test suite | 20/20 passing, including 8 regression tests for the false-positive bugs |
| API keys required to run the whole thing | **Zero** |

### By attack family (before → after)

| Family | Before | After |
|---|---|---|
| direct_override | 90% | 0% |
| hidden_text | 70% | 0% |
| metadata_injection | 90% | 0% |
| encoding_obfuscation | 100% | 0% |
| tool_result_injection | 100% | 0% |
| structured_field_smuggling | 40% | 0% |

### False positives found, root-caused, and fixed

Real uploads were being flagged as suspicious. Five separate causes:

1. **`OUT-001` denied legitimate perfect matches.** The scanner treated
   `value >= 0.98` as proof of coercion, so the *most relevant* resume in the
   pile — one containing every job keyword — was the one blocked. This alone
   explains "I uploaded a fine resume and it said suspicious."
2. **White-on-navy headers counted as hidden text.** Ingestion assumed a
   white page background, so a name printed white on a dark band (the most
   common resume template style there is) became `INJ-002` → HOLD.
3. **Ordinary prose read as attack instructions.** "Perfect fit" hit
   score-manipulation, "send an email to me" hit tool-naming, bare "act as"
   hit persona-hijack. Two weak hits → HOLD.
4. **Non-Latin resumes read as encoding attacks.** The homoglyph ratio
   counted every non-ASCII letter, flagging any résumé written in Greek,
   Cyrillic, etc., or containing a Cyrillic name.
5. **Long personal domains read as attacker infrastructure.** The URL rule
   matched any 16+ character run before a dot anywhere in the string, so
   `dataengineeringresume.example` matched.

Plus two platform crashes fixed: `corpus/generate_corpus.py` hardcoded a
Linux font path (dead on Windows/macOS), and `eval/bypass_case_study.py`
crashed printing Cyrillic on a cp1252 console.

### Verification performed

- `pytest` → 20/20 (exit 0)
- `eval/run_eval.py` → exit 0, ASR 82% → 0%, FPR 0/100
- `eval/repro_false_positive.py` → exit 0; asserts that 6 genuine resume
  shapes are allowed *and* that a control attack is denied (so "everything
  passes" cannot become vacuously true)
- `eval/bypass_case_study.py` → exit 0
- `npm run build` → success
- **End-to-end through the dashboard UI**, not just the build: genuine
  white-on-navy resume → `ALLOW`, score 1.00, email/ATS queued for human
  confirmation; hostile PDF → `DENY` at the guard with `INJ-001-DIRECT-OVERRIDE`

---

## 2. Insights

### 2.1 The core thesis: tool scoping is the control, the system prompt is a hint

The project's central argument is structural, not behavioral. A system prompt
asking a model not to fall for tricks is a suggestion, not a boundary. So:

- The scoring stage runs under a policy allowlist (`backend/policy.py`) that
  permits only `score` and `flag_for_review`. It is *structurally incapable*
  of calling `send_email` — a refactor that forgets this raises
  `PolicyViolation`.
- The output scanner inspects the proposed tool call as structured arguments
  before dispatch, so even a fooled model cannot act on its delusion.
- Irreversible actions are queued, never executed: `send_email` and
  `write_ats` require explicit human confirmation.

Defense in depth means a document has to win at *every* layer to do damage,
while the defender only needs one layer to hold. The eval shows exactly that
distribution.

### 2.2 Filtering phrases is theater — but named rules are still valuable

Only one of ten input rules is the famous "ignore previous instructions"
pattern. The rest attack the real surface: positioned/styled glyph runs,
metadata fields, link annotations, encoding tricks. Phrase matching exists
mainly so the eval can quantify how little it buys (family `direct_override`
is the easiest family to catch; the other five families are why the file
exists).

The other insight: **every hit is a named, independently auditable rule.**
That is what makes "traceable to a rule" true rather than aspirational —
each `LogEntry` carries a `rule_id`, and a test asserts it for every DENY.

### 2.3 Ingestion is where the signal lives

A PDF is not a string. It is positioned, styled glyph runs plus a metadata
dict plus annotations. `page.get_text()` throws away exactly the signal
(color, size, position) that separates an attack from a resume — which is
why Doorman walks spans itself and classifies each one *before* anything is
concatenated.

**The hard-won insight:** "hidden" is a property of the *relationship*
between ink and backdrop, not of the ink color alone. White text on a white
page is camouflage; white text on a navy band is the standard template.
Fixed by sampling the page's vector fills (`page.get_drawings()`) and only
calling light ink hidden when nothing dark sits behind it. A near miss in
this kind of heuristic is what turns a security tool into a false-positive
machine.

### 2.4 Not every rule deserves the same suspicion

The original guard counted hits: 1 hit → HOLD, 3 hits → DENY. That made a
single natural-language phrasing ("send an email to me") as damning as a
hidden override payload.

The fix separates *severity* from *traceability*:
- **Decisive** (deny outright): override phrases, hidden payload, metadata
  override, homoglyph splicing — impossible in a genuine résumé.
- **Strong** (one → hold for human review): structural and directive rules.
- **Weak** (recorded, but one alone is not suspicious): natural-language
  phrasings such as `INJ-011`.

Every hit is still logged with its ID. Severity changes only how much a hit
buys, and the eval proves detection did not regress: ASR stayed at 0%.

### 2.5 A maxed score and a coerced score are different things

The false-positive bug was an epistemic error: the scanner could not tell
"this resume contains every keyword" from "the document talked the scorer
into 1.0". The fix is to carry evidence with the claim — `ScoreResult.evidence_backed`
— and have `ClaudeScorer` corroborate the model's answer with keyword
evidence computed independently of the model. The model's own claim is not
evidence of the model's own claim.

Notably, an evidence-backed 1.0 still logs `OUT-001` as an informational
hit, so the decision remains traceable to the rule that evaluated it.

### 2.6 A flat benign corpus measures nothing

The original false-positive rate was "2% (2/100)" on resumes that were all
black-on-white, prose-free, English, link-free, and keyword-poor — i.e. the
corpus could not see any of the five bugs that break on real uploads. The
benign set now cycles through what candidates actually ship: template header
bands, conversational prose, portfolio links (including a long letters-only
domain), Word-written metadata, a Cyrillic résumé, a Cyrillic name on an
English résumé, and keyword-perfect matches.

**Insight:** the eval's attack side and benign side have to be adversarial
to the *same* degree, or the reported number is a property of the corpus,
not of the system.

### 2.7 How the "before" number is measured honestly

You cannot measure attack success on a live LLM reproducibly offline, so the
naive baseline uses `NaiveScorer` — a deterministic stand-in that reads
visible text + hidden spans + metadata as one blob and complies with whatever
it finds, with no isolation and no tool scoping. It reuses the *same* guard
detector, deliberately: the point is that these exact signals go completely
unactioned when nothing sits between the document and the tool call. The same
60 files go through both pipelines, so the gap is measured, not asserted.

### 2.8 What the attacker actually faces

- Structural detection (hidden text, metadata, links, encoding) catches
  families that phrase filters never see: `encoding_obfuscation` and
  `tool_result_injection` both started at 100% before guardrails.
- If something slips through, isolation means the scorer only ever sees
  `visible_text` with hidden spans already stripped — the payload is gone
  before it can influence anything.
- If the scorer *were* fooled, the output scan and confirmation queue still
  stop the irreversible action. That is the whole design in one sentence:
  **the document's goal is an email and an ATS write; neither can happen
  without passing a stage the document cannot reach.**

### 2.9 Honest limitations

- White text drawn over an *image* (not a vector fill) is still
  conservatively flagged — sampling rendered pixels is the next step.
- The suspicious-host heuristic lets letters-only long labels pass as personal
  domains (deliberate tradeoff); a letters-only generated host would slip.
- The homoglyph ratio needs a predominantly-Latin document, so an attack
  written entirely in a non-Latin script with no Latin text to blend into is
  not the signal it targets — phrase normalization still runs on every script.
- `NaiveScorer` is a stand-in for an ungoverned LLM, not a live model call,
  so "before" numbers are a lower bound on how bad the naive pipeline is.

---

## 3. Reproducing everything

```bash
pip install -r requirements.txt
python corpus/generate_corpus.py     # portable font picker; writes attacks/ + benign/
python eval/run_eval.py              # writes eval/report.json (ship-gate numbers)
python eval/repro_false_positive.py  # asserts genuine resumes pass + attack denied
python eval/bypass_case_study.py     # homoglyph bypass: before MISSED, after CAUGHT
python eval/show_runs.py my_resume.pdf   # print which rules fire on your own file
pytest tests/ -q                     # 20 tests, incl. 8 false-positive regressions

uvicorn backend.main:app --port 8000     # API
cd frontend && npm install && npm run dev  # dashboard on :5173
```

Everything runs with zero API keys. Optional production backends
(`HFModelGuard`, `ClaudeScorer`) are stubbed and documented in
`backend/guard.py` and `backend/scorer.py`.
