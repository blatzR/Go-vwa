import json, os, sys

# Sibling import: both this script and close_resolved_jira_issues.py live in
# the same scripts/ directory and share jira_common.py so their fingerprint
# formula and create/reopen/skip logic can't drift apart from each other.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jira_common as jc

SYNC_SEVERITIES = {s.strip().upper() for s in os.environ.get("SYNC_SEVERITY", "CRITICAL,HIGH,MEDIUM").split(",")}

pr_context = {
    "PR_NUMBER": os.environ["PR_NUMBER"],
    "PR_URL": os.environ["PR_URL"],
    "PR_AUTHOR": os.environ["PR_AUTHOR"],
    "PR_BRANCH": os.environ["PR_BRANCH"],
    "COMMIT_SHA": os.environ["COMMIT_SHA"],
}


def main():
    jc.validate_permissions()
    jc.validate_story()

    with open("security-findings.json") as f:
        findings = json.load(f).get("findings", [])

    result = jc.sync_findings(findings, SYNC_SEVERITIES, pr_context)

    with open("jira-sync-summary.json", "w") as f:
        json.dump(result, f, indent=2)


main()
