"""Print guarded-pipeline runs for every PDF given as argv (or the repro set)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.pipeline import run_guarded

JOB = ["python", "sql", "docker", "kubernetes", "aws"]

paths = sys.argv[1:] or sorted((Path(__file__).parent / "_repro").glob("*.pdf"))
for p in paths:
    r = run_guarded(str(p), JOB)
    name = Path(p).name
    print(f"{name:34s} -> {r.final_verdict.value:5s} candidate_score={r.candidate_score}")
    for e in r.logs:
        if e.rule_id:
            print(f"      {e.stage.value:12s} {e.verdict.value:5s} {e.rule_id} | {e.detail[:90]}")
