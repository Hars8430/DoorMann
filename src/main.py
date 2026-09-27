"""
Doorman pipeline runner — standalone module for running the pipeline
and the evaluation harness from the command line or programmatically.

This is the single "correct code file" that ties the whole project
together end-to-end.

Run as:
    python src/main.py                         # runs smoke test
    python src/main.py --eval                  # runs full eval harness
    python src/main.py --corpus                # shows corpus stats
    python src/main.py input.txt               # runs pipeline on a resume file
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

# Ensure src is importable when running from project root
_SRC_ROOT = Path(__file__).resolve().parent.parent / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from config.loader import load_config
from logging_setup import setup_logging, get_logger
from pipeline import run_pipeline
from pipeline_state import PipelineState, make_initial_state
from eval.run_eval import run_benign_resumes, run_full_eval, load_corpus, load_benign_resumes as load_benign, load_payload
from eval.analysis import format_corpus_summary, compute_metrics, generate_report

logger = get_logger("doorman.main")

_DEFAULT_CORPUS = Path("corpus/corpus.yaml").resolve()
_DEFAULT_BENIGN = Path("corpus/benign_resumes.yaml").resolve()


def load_corpus_yaml(path):
    """Load corpus from YAML file."""
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_benign_yaml(path):
    """Load benign resumes from YAML file."""
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("benign_resumes", [])


def cmd_smoke_test(config):
    """Run a single smoke test on a clean resume."""
    from test_resume import BENIGN_SMOKE_TEST_RESUME_TEXT

    job_description = (
        "We are looking for a Senior Software Engineer with 5+ years of experience "
        "in Python, 3+ years in cloud infrastructure (AWS/GCP), and experience "
        "leading distributed systems projects. Strong communication skills required."
    )

    print("\n" + "=" * 72)
    print("DOORMAN SMOKE TEST")
    print("=" * 72)
    print(f"\nCandidate: Sarah Mitchell (smoke test)")
    print(f"Input:      Benign resume (no attack patterns)")
    print(f"Pipeline:   7-node LangGraph graph with 5 defense layers")
    print(f"Guards:     HF classifier + heuristic + LLM-judge ensemble")
    print(f"LLM:        Ollama (llama3.1) for scoring")
    print(f"Tools:      Mock mode (no real email/ATS calls)")
    print(f"Tool Allowlist: score + flag_for_review (scoring stage only)")
    print()

    response = run_pipeline(
        input_text=BENIGN_SMOKE_TEST_RESUME_TEXT,
        candidate_id="smoke_test_001",
        candidate_name="Sarah Mitchell",
        job_description=job_description,
        config=config,
        confirm_next=True,
    )

    print("-" * 72)
    print("RESULT")
    print("-" * 72)
    print(f"Run ID:        {response.run_id}")
    print(f"Verdict:       {response.pipeline_verdict}")
    print(f"Blocked:       {response.blocked}")
    if response.blocked:
        print(f"Block Stage:   {response.block_stage}")
        print(f"Block Rule:    {response.block_rule_id}")
        print(f"Block Reason:  {response.block_reason}")
    print(f"Summary:       {response.pipeline_summary}")
    print(f"Hidden Text:   {'detected' if response.hidden_text_segments else 'none detected'}")
    if response.hidden_text_segments:
        print(f"  -> {response.hidden_text_detail[:200]}")
    if response.score_result:
        print(f"Score:         {response.score_result.overall_score}/10 ({response.score_result.category})")
        print(f"Flags:         {len(response.score_result.flags)} evidence flags")
    print(f"Pending Email: {'yes' if response.pending_email.get('body') else 'no'}")
    print(f"Pending ATS:   {'yes' if response.pending_ats.get('status') else 'no'}")
    print(f"Held Actions:  {response.held_count}")
    print(f"Confirmed:     {len(response.confirmed_actions)}")
    print(f"Output Scan:   clean={getattr(response.output_scan, 'overall_clean', True)}")
    if response.classification:
        print(f"Classification: {response.classification}")
    print()
    print("=" * 72)
    print("SMOKE TEST PASSED -- pipeline runs end-to-end on benign input")
    print("=" * 72 + "\n")


def cmd_eval(config, corpus_path, benign_path, output_dir):
    """Run the full evaluation harness."""
    print("\n" + "=" * 72)
    print("DOORMAN EVALUATION HARNESS")
    print("=" * 72)
    print(f"\nCorpus:       {corpus_path}")
    print(f"Benign:       {benign_path}")
    print(f"Output dir:   {output_dir}")
    print()

    corpus_data = load_corpus_yaml(corpus_path)
    benign_data = load_benign_yaml(benign_path)

    corpus = corpus_data.get("corpus", [])
    benign = benign_data.get("benign_resumes", [])

    if not corpus:
        print(f"ERROR: No attacks found in {corpus_path}")
        print("Expected format: corpus:\n  - id: A01\n    family: direct_instruction\n    ...")
        sys.exit(1)

    if not benign:
        print(f"WARNING: No benign resumes found in {benign_path}")
        print("Benign FPR will not be computed.")

    print(f"Loaded {len(corpus)} attacks and {len(benign)} benign resumes")
    print()

    results = run_evaluation(
        corpus_path=corpus_path,
        benign_path=benign_path,
        output_dir=output_dir,
        config=config,
    )

    summary = format_corpus_summary(results)
    print(summary)

    print("\n" + "-" * 72)
    print("METRICS SUMMARY")
    print("-" * 72)
    metrics = compute_metrics(results)
    for k, v in sorted(metrics.items()):
        if isinstance(v, dict):
            print(f"  {k}:")
            for k2, v2 in sorted(v.items()):
                print(f"    {k2}: {v2}")
        elif isinstance(v, float):
            print(f"  {k}: {v:.2f}")
        else:
            print(f"  {k}: {v}")

    if results.get("bypasses"):
        print("\n" + "-" * 72)
        print("BYPASS REPORT")
        print("-" * 72)
        for bp in results["bypasses"]:
            print(f"  {bp['id']} ({bp['family']}/{bp['technique']}): "
                  f"verdict={bp['verdict']}, signals={bp['signals']}")

    report = generate_report(results)
    report_path = os.path.join(output_dir, "eval_summary.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\nFull evaluation report: {report_path}\n")


def cmd_corpus_stats(config):
    """Print corpus statistics."""
    print("\n" + "=" * 72)
    print("CORPUS STATISTICS")
    print("=" * 72)

    corpus_data = load_corpus_yaml(_DEFAULT_CORPUS)
    benign_data = load_benign_yaml(_DEFAULT_BENIGN)

    corpus = corpus_data.get("corpus", [])
    benign = benign_data.get("benign_resumes", [])

    print(f"\nTotal attacks:     {len(corpus)}")
    print(f"Total benign:      {len(benign)}")

    if corpus:
        families = {}
        for a in corpus:
            fam = a.get("family", "unknown")
            families.setdefault(fam, []).append(a)

        print(f"\nFamilies ({len(families)}):")
        for fam in sorted(families.keys()):
            attacks = families[fam]
            print(f"  {fam}: {len(attacks)} attacks")
            for a in attacks:
                tech = a.get("technique", "N/A")
                print(f"    - {a.get('id')}: {tech}")

        print(f"\nPystems directories:")
        payload_dir = Path("corpus_payloads")
        if payload_dir.exists():
            for p in sorted(payload_dir.iterdir()):
                if p.is_file():
                    print(f"  {p.name} ({p.stat().st_size} bytes)")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="doorman",
        description="Doorman -- Prompt Injection Guardrails for a Recruiting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/main.py                              Run smoke test
  python src/main.py --eval                       Run full evaluation harness
  python src/main.py --corpus                     Show corpus stats
  python src/main.py resume.txt                   Run pipeline on resume file
  PYTHONPATH=src python src/main.py --eval        Run eval (if PYTHONPATH needed)
        """,
    )

    parser.add_argument(
        "--eval", action="store_true",
        help="Run the full evaluation harness (attacks + benign resumes)",
    )
    parser.add_argument(
        "--corpus", action="store_true",
        help="Print corpus statistics and exit",
    )
    parser.add_argument(
        "--corpus-path", type=Path, default=None,
        help="Path to corpus YAML (default: corpus/corpus.yaml)",
    )
    parser.add_argument(
        "--benign-path", type=Path, default=None,
        help="Path to benign resumes YAML (default: corpus/benign_resumes.yaml)",
    )
    parser.add_argument(
        "--output-dir", type=str, default=None,
        help="Output directory for logs (default: output/)",
    )
    parser.add_argument(
        "--config", type=Path, default=None,
        help="Path to settings.yaml (default: config/settings.yaml)",
    )
    parser.add_argument(
        "input_file", nargs="?", default=None,
        help="Optional resume text file to test (smoke test mode)",
    )

    args = parser.parse_args()

    # Load configuration
    config_path = args.config or Path("config/settings.yaml")
    config = load_config(str(config_path))
    print(f"Config: {config_path}")

    # Override from environment
    if os.environ.get("OLLAMA_BASE_URL"):
        config.setdefault("pipeline", {})["llm_base_url"] = os.environ["OLLAMA_BASE_URL"]
        print(f"  OLLAMA_BASE_URL={os.environ['OLLAMA_BASE_URL']}")

    if os.environ.get("OLLAMA_MODEL"):
        config.setdefault("pipeline", {})["llm_model"] = os.environ["OLLAMA_MODEL"]
        print(f"  OLLAMA_MODEL={os.environ['OLLAMA_MODEL']}")

    if os.environ.get("HF_MODEL"):
        config.setdefault("guard", {}).setdefault("classifier", {})["hf_model_name"] = os.environ["HF_MODEL"]
        print(f"  HF_MODEL={os.environ['HF_MODEL']}")

    if os.environ.get("MOCK_MODE", "").lower() in ("1", "true", "yes"):
        config.setdefault("pipeline", {})["mock_mode"] = True
        print("  MOCK_MODE=on")

    # Set up logging
    output_dir = args.output_dir or config.get("evaluation", {}).get("output_dir", "output")
    setup_logging(output_dir=output_dir)

    # Run the requested command
    if args.eval:
        corpus_path = args.corpus_path or _DEFAULT_CORPUS
        benign_path = args.benign_path or _DEFAULT_BENIGN
        cmd_eval(config, corpus_path, benign_path, output_dir)
    elif args.corpus:
        cmd_corpus_stats(config)
    elif args.input_file:
        text = Path(args.input_file).read_text(encoding="utf-8")
        job_desc = (
            "We are hiring a Software Engineer with Python and cloud experience."
        )
        run_pipeline(
            input_text=text,
            candidate_id="cli_test_001",
            candidate_name="CLI Test Candidate",
            job_description=job_desc,
            config=config,
            confirm_next=True,
        )
        print("\nPipeline complete. Check output/logs/ for decision log.")
    else:
        cmd_smoke_test(config)


if __name__ == "__main__":
    main()
