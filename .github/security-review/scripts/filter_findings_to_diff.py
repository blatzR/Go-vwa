import json
import os

# Enforces the <HARD_RULE> ("only review this PR's changed files") in code
# instead of trusting the model to have honored it. <HARD_RULE> is prompt
# text, not a technical restriction — the full repo is checked out and
# Claude's default Read/Glob/Grep tools can see all of it regardless of what
# the prompt asks for, so this step is the actual enforcement point.
#
# CHANGED_FILES is expected to be a newline-separated list (the same value
# passed to steps.diff.outputs.files in the workflow), matching the pattern
# already used in close_resolved_jira_issues.py.

CHANGED_FILES = {
    f.strip().lstrip("./")
    for f in os.environ.get("CHANGED_FILES", "").splitlines()
    if f.strip()
}

with open("security-findings.json") as fh:
    data = json.load(fh)

findings = data.get("findings", [])

if not CHANGED_FILES:
    # No diff scope was available to filter against — most likely this run
    # was triggered by workflow_dispatch (the "Get changed files" step only
    # runs on pull_request events) or the gh pr diff call returned nothing.
    # Passing findings through unfiltered here is a deliberate choice over
    # silently dropping everything, but it must be loud: this is exactly the
    # condition that let a prior run scan the whole codebase unnoticed.
    print("::warning::CHANGED_FILES is empty — no PR diff scope was available, so findings "
          "were NOT filtered by file. If this run was triggered by workflow_dispatch, that's "
          "expected (there's no PR to diff against). If this was a pull_request event, the "
          "'Get changed files' step likely failed or returned nothing — check its logs.")
    kept, dropped = findings, []
else:
    kept, dropped = [], []
    for f in findings:
        file_field = (f.get("file") or "").strip().lstrip("./")
        (kept if file_field in CHANGED_FILES else dropped).append(f)

if dropped:
    dropped_files = sorted({f.get("file", "<missing>") for f in dropped})
    print(f"::warning::Dropped {len(dropped)} finding(s) outside the PR diff scope "
          f"(files not in this PR's changed-files list): {dropped_files}. This means the "
          "model reported on code the <HARD_RULE> told it not to — worth checking the run's "
          "prompt/log if this keeps happening.")

data["findings"] = kept
with open("security-findings.json", "w") as fh:
    json.dump(data, fh, indent=2)

print(f"Findings kept: {len(kept)}  |  dropped (out of scope): {len(dropped)}")
