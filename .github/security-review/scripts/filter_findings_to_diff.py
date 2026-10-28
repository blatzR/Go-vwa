import json
import os

# Enforces the <HARD_RULE> ("only review this PR's changed files") in code
# instead of trusting the model to have honored it. Also enforces the
# central ignore list: CHANGED_FILES is the scannable list produced by
# changed_files.sh, so ignored files are absent from it too.

# Which findings file to filter: security-findings.json (PR scan) or
# verification-findings.json (post-merge scan).
FINDINGS_FILE = os.environ.get("FINDINGS_FILE", "security-findings.json")

# "ok" only when the changed-files step ran AND succeeded. This separates
# "every changed file was ignored" (empty list -> filter strictly, keep nothing)
# from "no diff scope at all" (workflow_dispatch / step skipped -> warn, pass through).
DIFF_STATUS = os.environ.get("DIFF_STATUS", "")

CHANGED_FILES = {
    f.strip().lstrip("./")
    for f in os.environ.get("CHANGED_FILES", "").splitlines()
    if f.strip()
}

with open(FINDINGS_FILE) as fh:
    data = json.load(fh)

findings = data.get("findings", [])

if DIFF_STATUS != "ok":
    print("::warning::No diff scope was available (DIFF_STATUS is not 'ok'), so findings "
          "were NOT filtered by file. Expected for workflow_dispatch runs. For a "
          "pull_request run, check the 'Get changed files' step's logs.")
    kept, dropped = findings, []
else:
    kept, dropped = [], []
    for f in findings:
        file_field = (f.get("file") or "").strip().lstrip("./")
        (kept if file_field in CHANGED_FILES else dropped).append(f)

if dropped:
    dropped_files = sorted({f.get("file", "<missing>") for f in dropped})
    print(f"::warning::Dropped {len(dropped)} finding(s) in files outside the scannable list "
          f"(not changed in this PR, or matched by the ignore list): {dropped_files}.")

data["findings"] = kept
with open(FINDINGS_FILE, "w") as fh:
    json.dump(data, fh, indent=2)

print(f"[{FINDINGS_FILE}] kept: {len(kept)}  |  dropped: {len(dropped)}")
