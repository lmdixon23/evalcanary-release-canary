"""Verify the exact-tag consumer's output contract and synthetic report privacy."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import uuid
from html.parser import HTMLParser
from pathlib import Path

OUTPUT_NAMES = (
    "report_directory",
    "report_json",
    "report_markdown",
    "report_html",
    "run_id",
    "changed_cases",
    "policy_passed",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def prepare() -> None:
    require(importlib.util.find_spec("evalcanary") is None, "Package was already installed")
    # A synthetic privacy marker, never a credential or repository secret.
    marker = "canary-privacy-" + uuid.uuid4().hex
    with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as handle:
        handle.write(f"CANARY_PRIVACY_SENTINEL={marker}\n")
    Path("canary-clean.json").write_text(
        json.dumps({"evalcanary_preinstalled": False, "synthetic_privacy_marker_set": True}) + "\n",
        encoding="utf-8",
    )


def verify(case: str) -> None:
    passing = case == "pass"
    expected_policy = "true" if passing else "false"
    expected_outcome = "success" if passing else "failure"
    outputs = {name: os.environ.get(name.upper(), "") for name in OUTPUT_NAMES}
    require(all(outputs.values()), "One or more of the seven Action outputs are empty")
    require(os.environ["STEP_OUTCOME"] == expected_outcome, "Unexpected Action outcome")
    require(os.environ["STEP_CONCLUSION"] == "success", "Unexpected step conclusion")
    report_dir = Path(f"tagged-{case}-report").resolve()
    require(Path(outputs["report_directory"]).is_absolute(), "Report directory is not absolute")
    require(Path(outputs["report_directory"]).resolve() == report_dir, "Wrong report directory")
    expected_paths = {"report_json": "report.json", "report_markdown": "report.md", "report_html": "report.html"}
    require({p.name for p in report_dir.iterdir()} == set(expected_paths.values()), "Unexpected report inventory")
    for name, filename in expected_paths.items():
        path = Path(outputs[name])
        require(path.is_absolute() and path.resolve() == report_dir / filename, f"Wrong {name} path")
        require(path.is_file() and not path.is_symlink(), f"Missing or linked {name}")
    payload = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
    require(payload["total_cases"] == 12 and payload["error_cases"] == 0, "Wrong case counts")
    counts = payload["transition_counts"]
    require(counts["fail_to_pass"] == 5 and counts["pass_to_fail"] == 0, "Wrong transitions")
    require(outputs["changed_cases"] == str(counts["fail_to_pass"] + counts["pass_to_fail"]) == "5", "Wrong changed_cases")
    require(outputs["policy_passed"] == expected_policy, "Wrong policy output")
    require(payload["policy"]["configured"] is True and payload["policy"]["passed"] is passing, "Wrong report policy")
    if not passing:
        require(any(not check["passed"] for check in payload["policy"]["checks"]), "Negative control has no blocking check")
    identity = {
        "data_sha256": hashlib.sha256(Path("cases.jsonl").read_bytes()).hexdigest(),
        "before_verifier_sha256": hashlib.sha256(Path("verifier_before.py").read_bytes()).hexdigest(),
        "after_verifier_sha256": hashlib.sha256(Path("verifier_after.py").read_bytes()).hexdigest(),
    }
    expected_run_id = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    require(outputs["run_id"] == payload["run_id"] == expected_run_id, "Wrong content-derived run ID")
    require(payload["tool_version"] == "0.2.0", "Wrong report version")
    require(payload["schema_version"] == "evalcanary-comparison-v1", "Changed compatibility schema")
    provenance = payload["provenance"]
    require(provenance["tool"] == "EvalCanary" and provenance["tool_version"] == "0.2.0", "Wrong machine identity")
    require(provenance["report_schema"] == "evalcanary-comparison-v1", "Wrong provenance schema")
    require(provenance["path_policy"] == "basename-only", "Wrong path policy")
    require(all(item["payload"] is None for item in payload["changed_cases"]), "Case content leaked")
    require(payload["verifier_diff"].startswith("Source diff omitted by default."), "Verifier source leaked")
    marker = os.environ.get("CANARY_PRIVACY_SENTINEL", "")
    require(marker.startswith("canary-privacy-") and len(marker) > 30, "Privacy marker missing")
    forbidden = (marker, "2 + 2", "Return YES", "Strict exact-match baseline verifier",
                 "Whitespace- and case-normalized candidate verifier", "_local/", "_local\\")
    patterns = (
        r"gh[pousr]_[A-Za-z0-9]{30,}", r"github_pat_[A-Za-z0-9_]{30,}",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"(?i)[A-Z]:[\\/]", r"/(?:home|Users|runner|tmp|opt|private)/",
    )
    inventory = []
    for path in sorted(report_dir.iterdir()):
        data = path.read_bytes()
        text = data.decode("utf-8")
        require(not any(value in text for value in forbidden), "Private/content marker in report")
        require(not any(re.search(pattern, text) for pattern in patterns), "Credential or absolute path pattern in report")
        inventory.append({"file": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    markdown = (report_dir / "report.md").read_text(encoding="utf-8")
    html = (report_dir / "report.html").read_text(encoding="utf-8")
    require(markdown.startswith("# ReplayDocket evaluator migration report\n"), "Wrong Markdown heading")
    require("<h1>ReplayDocket evaluator migration report</h1>" in html, "Wrong HTML heading")
    require(f"<title>ReplayDocket report {expected_run_id}</title>" in html, "Wrong HTML title")
    parser = HTMLParser()
    parser.feed(html)
    parser.close()
    require("<script" not in html.lower(), "Unexpected report script")
    import evalcanary

    require(importlib.metadata.version("replaydocket") == evalcanary.__version__ == "0.2.0", "Wrong installed version")
    require(not Path(evalcanary.__file__).resolve().is_relative_to(Path.cwd().resolve()), "Imported local workspace source")
    contract = {
        "case": case, "action_reference": "lmdixon23/EvalCanary@v0.2.0",
        "outputs": outputs, "step_outcome": os.environ["STEP_OUTCOME"],
        "step_conclusion": os.environ["STEP_CONCLUSION"],
        "negative_control": not passing,
        "underlying_exit_evidence": "Inspect the actual Action log for exit 2; continue-on-error changes the conclusion, not the underlying exit.",
        "installed_version": evalcanary.__version__, "imported_from_workspace": False,
        "report_safety": "PASS", "synthetic_privacy_marker_absent": True,
        "report_inventory": inventory,
    }
    Path(f"canary-{case}-contract.json").write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"case": case, "all_seven_outputs": "PASS", "report_safety": "PASS", "outcome": expected_outcome}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "pass", "fail"))
    mode = parser.parse_args().mode
    if mode == "prepare":
        prepare()
    else:
        verify(mode)
